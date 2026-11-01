//! The GPU's state for a snapshot: what the guest built, from the record, and
//! the contents of its resources, read back from the renderer. Restoring
//! builds it all again in a new renderer.

use std::collections::BTreeSet;
use std::ffi::{c_int, c_uint, c_void};
use std::fs::File;
use std::io::{self, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::sync::OnceLock;

use rutabaga_gfx::{ResourceCreateBlob, Transfer3D};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use super::protocol::VIRTIO_GPU_BLOB_MEM_GUEST;
use super::record::{self, Chunk, Kind, Resource, Ring, Session};
use super::virtio_gpu::{Lost, VirtioGpu};
use crate::virtio::VirtioShmRegion;

#[repr(C)]
struct VirglBox {
    x: u32,
    y: u32,
    z: u32,
    w: u32,
    h: u32,
    d: u32,
}

// rutabaga's transfer_write only writes from a resource's backing, so restored
// contents go to the renderer directly.
#[link(name = "virglrenderer")]
unsafe extern "C" {
    fn virgl_renderer_transfer_write_iov(
        handle: u32,
        ctx_id: u32,
        level: c_int,
        stride: u32,
        layer_stride: u32,
        box_: *mut VirglBox,
        offset: u64,
        iovec: *mut libc::iovec,
        iovec_cnt: c_uint,
    ) -> c_int;
}

type ContextSnapshot = unsafe extern "C" fn(ctx_id: u32, out_fd: *mut c_int) -> c_int;
type ContextRestore = unsafe extern "C" fn(ctx_id: u32, fd: c_int) -> c_int;

/// A Venus context's commands reach the renderer through shared memory, so
/// only the renderer can save and rebuild one. Upstream virglrenderer can't;
/// a build that can exports these, and is looked up rather than linked so
/// libkrun builds against either.
fn venus_snapshot() -> Option<(ContextSnapshot, ContextRestore)> {
    static FNS: OnceLock<Option<(ContextSnapshot, ContextRestore)>> = OnceLock::new();
    *FNS.get_or_init(|| {
        // SAFETY: dlsym with NUL-terminated names; the symbols, when present,
        // have these signatures.
        unsafe {
            let save = libc::dlsym(
                libc::RTLD_DEFAULT,
                c"virgl_renderer_context_snapshot".as_ptr(),
            );
            let restore = libc::dlsym(
                libc::RTLD_DEFAULT,
                c"virgl_renderer_context_restore".as_ptr(),
            );
            (!save.is_null() && !restore.is_null()).then(|| {
                (
                    mem::transmute::<*mut c_void, ContextSnapshot>(save),
                    mem::transmute::<*mut c_void, ContextRestore>(restore),
                )
            })
        }
    })
}

/// A blob a Venus context made from device memory. Its contents travel in the
/// context's own snapshot, and it can be made again only once the renderer has
/// rebuilt that memory.
fn is_venus_memory_blob(session: &Session, r: &Resource) -> bool {
    match &r.kind {
        Kind::Blob(b) => {
            b.blob_id != 0
                && session
                    .contexts
                    .get(&b.ctx_id)
                    .is_some_and(|c| record::is_venus(c.init))
        }
        _ => false,
    }
}

/// The Venus contexts in the order they replay: each after the contexts
/// whose Venus buffers it holds, which it imports as its commands replay.
/// Contexts that hold each other's come in the order of their ids.
fn venus_order(session: &Session) -> Vec<u32> {
    let holds = |ctx_id: u32, c: &record::Context| -> BTreeSet<u32> {
        c.attached
            .iter()
            .filter_map(|res| session.resources.get(res))
            .filter(|r| is_venus_memory_blob(session, r))
            .filter_map(|r| match &r.kind {
                Kind::Blob(b) if b.ctx_id != ctx_id => Some(b.ctx_id),
                _ => None,
            })
            .collect()
    };
    let mut waiting: Vec<(u32, BTreeSet<u32>)> = session
        .contexts
        .iter()
        .filter(|(_, c)| c.venus.is_some())
        .map(|(&id, c)| (id, holds(id, c)))
        .collect();
    let mut order = Vec::with_capacity(waiting.len());
    while !waiting.is_empty() {
        let next = waiting
            .iter()
            .position(|(_, deps)| deps.iter().all(|d| !waiting.iter().any(|(w, _)| w == d)))
            .unwrap_or(0);
        order.push(waiting.remove(next).0);
    }
    order
}

fn guest_vecs(entries: &[(u64, u32)]) -> Vec<(GuestAddress, usize)> {
    entries
        .iter()
        .map(|&(a, l)| (GuestAddress(a), l as usize))
        .collect()
}

fn whole_blob(size: u64) -> Chunk {
    Chunk {
        level: u32::MAX,
        x: 0,
        y: 0,
        z: 0,
        w: 0,
        h: 0,
        d: 0,
        stride: 0,
        layer_stride: 0,
        offset: 0,
        len: size,
    }
}

impl VirtioGpu {
    /// The session and its resources' contents, encoded. Runs on the worker
    /// thread with nothing in flight, so nothing changes while it reads.
    pub fn save_session(&mut self) -> Result<Vec<u8>, String> {
        let mut session = self.rec.clone();
        let mut data: Vec<u8> = Vec::new();

        // Venus first: the renderer drains each context's rings before it
        // writes, and the rings are in blobs read back below, which then show
        // them drained.
        for (&id, c) in session.contexts.iter_mut() {
            c.venus = None;
            if !record::is_venus(c.init) {
                continue;
            }
            let Some((snapshot, _)) = venus_snapshot() else {
                warn!(
                    "gpu: venus context {id} won't survive a restore: the renderer can't save it"
                );
                continue;
            };
            let mut fd: c_int = -1;
            // SAFETY: the renderer writes a descriptor it hands over to us.
            let ret = unsafe { snapshot(id, &mut fd) };
            if ret != 0 || fd < 0 {
                warn!("gpu: venus context {id}: snapshot failed ({ret})");
                continue;
            }
            // SAFETY: fd is ours, from the renderer.
            let mut file = unsafe { File::from_raw_fd(fd) };
            let mut bytes = Vec::new();
            if let Err(e) = file.read_to_end(&mut bytes) {
                warn!("gpu: venus context {id}: reading its snapshot: {e}");
                continue;
            }
            c.venus = Some((data.len() as u64, bytes.len() as u64));
            data.extend_from_slice(&bytes);
        }

        let view = session.clone();
        let ids: Vec<u32> = session.resources.keys().copied().collect();
        for id in ids {
            let r = session.resources.get_mut(&id).unwrap();
            r.contents.clear();
            if is_venus_memory_blob(&view, r) {
                continue;
            }
            let chunks = match &r.kind {
                Kind::ThreeD(c) => record::chunks_for(c),
                // Guest pages, which the snapshot carries.
                Kind::Blob(b) if b.blob_mem == VIRTIO_GPU_BLOB_MEM_GUEST => continue,
                Kind::Blob(b) => Ok(vec![whole_blob(b.size)]),
            };
            let chunks = match chunks {
                Ok(c) => c,
                Err(why) => {
                    warn!("gpu: resource {id}: contents not carried: {why}");
                    continue;
                }
            };
            let mut saved = Vec::new();
            for mut ch in chunks {
                let mut buf = vec![0u8; ch.len as usize];
                let read = if ch.level == u32::MAX {
                    self.blob_bytes(id, &mut buf, false)
                } else {
                    let t = Transfer3D {
                        x: ch.x,
                        y: ch.y,
                        z: ch.z,
                        w: ch.w,
                        h: ch.h,
                        d: ch.d,
                        level: ch.level,
                        stride: ch.stride,
                        layer_stride: ch.layer_stride,
                        offset: 0,
                    };
                    self.rutabaga
                        .transfer_read(0, id, t, Some(IoSliceMut::new(&mut buf)))
                        .map_err(|e| e.to_string())
                };
                if let Err(e) = read {
                    warn!("gpu: resource {id}: reading its contents back: {e}");
                    saved.clear();
                    break;
                }
                ch.offset = data.len() as u64;
                data.extend_from_slice(&buf);
                saved.push(ch);
            }
            session.resources.get_mut(&id).unwrap().contents = saved;
        }

        bincode::encode_to_vec((session, data), bincode::config::standard())
            .map_err(|e| e.to_string())
    }

    /// Builds a saved session again, in the order of dependence: contexts,
    /// the pipe resources blobs are made from, resources with their backing
    /// and contents, Venus contexts, the blobs made from their memory, the
    /// blobs' places in the window, attachments, and last each virgl
    /// context's objects and bindings, which name all of the above.
    ///
    /// What can't be built again is lost: the guest is told so when it names
    /// it, and a lost Venus context's rings are marked failed.
    pub fn restore_session(
        &mut self,
        state: &[u8],
        mem: &GuestMemoryMmap,
        shm_region: &VirtioShmRegion,
    ) -> Result<(), String> {
        let ((session, data), _): ((Session, Vec<u8>), _) =
            bincode::decode_from_slice(state, bincode::config::standard())
                .map_err(|e| format!("gpu state: {e}"))?;
        let mut built = BTreeSet::new();
        let mut lost = Lost::default();

        for (&id, c) in &session.contexts {
            if let Err(e) = self.create_context(id, c.init, c.name.as_deref()) {
                warn!("gpu: context {id}: {e:?}");
                lost.contexts.insert(id);
            } else if c.virgl.is_none() && c.venus.is_none() {
                lost.contexts.insert(id);
            }
        }

        for (&ctx_id, c) in &session.contexts {
            let Some(v) = &c.virgl else { continue };
            let blob_ids = session
                .resources
                .values()
                .filter_map(|r| match &r.kind {
                    Kind::Blob(b) if b.ctx_id == ctx_id && b.blob_id != 0 => Some(b.blob_id as u32),
                    _ => None,
                })
                .collect();
            if let Err(e) = self.submit_words(ctx_id, &v.pipe_resource_commands(&blob_ids)) {
                warn!("gpu: context {ctx_id}: recreating pipe resources: {e}");
            }
        }

        for (&id, r) in &session.resources {
            if is_venus_memory_blob(&session, r) {
                continue;
            }
            let made = match &r.kind {
                Kind::ThreeD(c) => self.resource_create_3d(id, (*c).into()),
                Kind::Blob(b) => self.resource_create_blob(
                    b.ctx_id,
                    id,
                    ResourceCreateBlob {
                        blob_mem: b.blob_mem,
                        blob_flags: b.blob_flags,
                        blob_id: b.blob_id,
                        size: b.size,
                    },
                    guest_vecs(&b.entries),
                    mem,
                ),
            };
            match made {
                Ok(_) => {
                    built.insert(id);
                }
                Err(e) => {
                    warn!("gpu: resource {id}: {e:?}");
                    lost.resources.insert(id);
                }
            }
        }

        for (&id, r) in &session.resources {
            if !built.contains(&id) {
                continue;
            }
            if let Some(backing) = &r.backing
                && let Err(e) = self.attach_backing(id, mem, guest_vecs(backing))
            {
                warn!("gpu: resource {id}: attaching its backing again: {e:?}");
            }
            for ch in &r.contents {
                let Some(bytes) = data.get(ch.offset as usize..(ch.offset + ch.len) as usize)
                else {
                    warn!("gpu: resource {id}: its contents are missing");
                    break;
                };
                let mut buf = bytes.to_vec();
                let written = if ch.level == u32::MAX {
                    self.blob_bytes(id, &mut buf, true)
                } else {
                    write_level(id, ch, &mut buf)
                };
                if let Err(e) = written {
                    warn!("gpu: resource {id}: writing its contents back: {e}");
                }
            }
        }

        // Everything a Venus context names in shared memory, its rings and
        // reply streams, exists again by now with its contents, which is what
        // a ring resumes from. A context's commands import the buffers it
        // holds, a compositor's its clients', so the contexts replay one at a
        // time, each after those whose buffers it holds, with what it holds
        // that exists by then attached, and each context's own buffers are
        // made as soon as it has replayed.
        for ctx_id in venus_order(&session) {
            let c = &session.contexts[&ctx_id];
            let Some((offset, len)) = c.venus else {
                continue;
            };
            if lost.contexts.contains(&ctx_id) {
                continue;
            }
            for &res in c.attached.iter().filter(|r| built.contains(r)) {
                if let Err(e) = self.context_attach_resource(ctx_id, res) {
                    warn!("gpu: context {ctx_id}: attaching resource {res}: {e:?}");
                }
            }
            let restored = data
                .get(offset as usize..(offset + len) as usize)
                .ok_or_else(|| "its snapshot is missing".to_string())
                .and_then(restore_venus_context(ctx_id));
            if let Err(e) = restored {
                warn!("gpu: venus context {ctx_id}: {e}");
                lost.contexts.insert(ctx_id);
                continue;
            }
            for (&id, r) in &session.resources {
                let Kind::Blob(b) = &r.kind else { continue };
                if b.ctx_id != ctx_id || !is_venus_memory_blob(&session, r) {
                    continue;
                }
                let create = ResourceCreateBlob {
                    blob_mem: b.blob_mem,
                    blob_flags: b.blob_flags,
                    blob_id: b.blob_id,
                    size: b.size,
                };
                match self.resource_create_blob(ctx_id, id, create, Vec::new(), mem) {
                    Ok(_) => {
                        built.insert(id);
                    }
                    Err(e) => warn!("gpu: venus blob {id}: {e:?}"),
                }
            }
        }

        // The guest driver checks a ring's status on every submission, so a
        // lost Venus context is failed there; left alone, the driver would
        // wait on a ring nothing reads.
        for (&ctx_id, c) in &session.contexts {
            if !record::is_venus(c.init) || !lost.contexts.contains(&ctx_id) {
                continue;
            }
            for ring in c.rings.iter().filter(|r| built.contains(&r.resource)) {
                if let Err(e) = self.fail_ring(ring) {
                    warn!(
                        "gpu: venus context {ctx_id}: failing ring {:#x}: {e}",
                        ring.id
                    );
                }
            }
        }

        for (&id, r) in &session.resources {
            if built.contains(&id) || !is_venus_memory_blob(&session, r) {
                continue;
            }
            // A compositor's context samples its clients' buffers, and loses
            // all its state if one it binds is gone. A blank texture of the
            // type it gave the buffer keeps the rest.
            let stand_in = session
                .contexts
                .values()
                .find_map(|c| c.virgl.as_ref()?.stand_in(id));
            match stand_in.map(|c| self.resource_create_3d(id, c.into())) {
                Some(Ok(_)) => {
                    built.insert(id);
                    lost.stand_ins.insert(id);
                }
                Some(Err(e)) => {
                    warn!("gpu: venus blob {id}: standing a texture in for it: {e:?}");
                    lost.resources.insert(id);
                }
                None => {
                    lost.resources.insert(id);
                }
            }
        }

        for (&id, r) in &session.resources {
            if let (true, Some(offset)) = (
                built.contains(&id) && !lost.stand_ins.contains(&id),
                r.mapped_at,
            ) && let Err(e) = self.resource_map_blob(id, shm_region, offset)
            {
                warn!("gpu: blob {id}: mapping it into the window again: {e:?}");
            }
        }

        for (&ctx_id, c) in &session.contexts {
            if lost.contexts.contains(&ctx_id) {
                continue;
            }
            for &res in c.attached.iter().filter(|r| built.contains(r)) {
                if let Err(e) = self.context_attach_resource(ctx_id, res) {
                    warn!("gpu: context {ctx_id}: attaching resource {res}: {e:?}");
                }
            }
        }

        // The renderer finds a resource a command names only among those
        // attached to the context, but an object made from one outlives the
        // attachment: a sampler view of a buffer the guest imported and
        // closed is still bound. So every rebuilt resource is attached for the
        // replay, and those that weren't are detached after.
        let mut borrowed = Vec::new();
        for (&ctx_id, c) in &session.contexts {
            if c.virgl.is_none() || lost.contexts.contains(&ctx_id) {
                continue;
            }
            for &res in built.iter().filter(|res| !c.attached.contains(res)) {
                match self.rutabaga.context_attach_resource(ctx_id, res) {
                    Ok(()) => borrowed.push((ctx_id, res)),
                    Err(e) => warn!("gpu: context {ctx_id}: attaching resource {res}: {e}"),
                }
            }
        }
        let virgl: Vec<(u32, &record::Virgl)> = session
            .contexts
            .iter()
            .filter(|(id, _)| !lost.contexts.contains(id))
            .filter_map(|(&id, c)| c.virgl.as_ref().map(|v| (id, v)))
            .collect();
        for &(ctx_id, v) in &virgl {
            if let Err(e) = self.submit_words(ctx_id, &v.set_types(&built)) {
                warn!("gpu: context {ctx_id}: typing its resources: {e}");
            }
        }
        for &(ctx_id, v) in &virgl {
            if let Err(e) = self.submit_words(ctx_id, &v.replay(&built)) {
                warn!("gpu: context {ctx_id}: replaying its state: {e}");
                lost.contexts.insert(ctx_id);
            }
        }
        for (ctx_id, res) in borrowed {
            let _ = self.rutabaga.context_detach_resource(ctx_id, res);
        }

        for (&scanout, &res) in &session.scanouts {
            let Some(Kind::ThreeD(c)) = session.resources.get(&res).map(|r| &r.kind) else {
                continue;
            };
            if built.contains(&res)
                && let Err(e) = self.set_scanout(scanout, res, c.width, c.height)
            {
                warn!("gpu: scanout {scanout}: {e:?}");
            }
        }

        info!(
            "gpu: restored {} of {} resources ({} as blank textures) and {} of {} contexts",
            built.len(),
            session.resources.len(),
            lost.stand_ins.len(),
            session.contexts.len() - lost.contexts.len(),
            session.contexts.len()
        );

        let mut rec = session;
        for id in &lost.resources {
            rec.resources.remove(id);
        }
        for id in &lost.contexts {
            if let Some(c) = rec.contexts.get_mut(id) {
                c.virgl = None;
            }
        }
        for c in rec.contexts.values_mut() {
            c.venus = None;
        }
        for r in rec.resources.values_mut() {
            r.contents.clear();
        }
        self.rec = rec;
        self.lost = lost;
        Ok(())
    }

    fn submit_words(&mut self, ctx_id: u32, words: &[u32]) -> Result<(), String> {
        if words.is_empty() {
            return Ok(());
        }
        let mut bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.rutabaga
            .submit_command(ctx_id, &mut bytes, &[])
            .map_err(|e| e.to_string())
    }

    /// Sets a ring's FATAL status bit, and clears ALIVE, in the blob the guest
    /// driver reads it from.
    fn fail_ring(&mut self, ring: &Ring) -> Result<(), String> {
        const FATAL: u32 = 1 << 1;
        const ALIVE: u32 = 1 << 2;
        let size = match self.rec.resources.get(&ring.resource).map(|r| &r.kind) {
            Some(Kind::Blob(b)) => b.size,
            _ => return Err("the ring's resource isn't a blob".into()),
        };
        if ring.status + 4 > size {
            return Err("the status word is outside the ring's resource".into());
        }
        let mut buf = vec![0u8; size as usize];
        self.blob_bytes(ring.resource, &mut buf, false)?;
        let at = ring.status as usize;
        let status = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
        buf[at..at + 4].copy_from_slice(&((status | FATAL) & !ALIVE).to_le_bytes());
        self.blob_bytes(ring.resource, &mut buf, true)
    }

    /// Reads or writes a blob's bytes through a mapping of its descriptor.
    fn blob_bytes(&mut self, id: u32, buf: &mut [u8], write: bool) -> Result<(), String> {
        let (fd, _) = self.blob_fd(id)?;
        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        // SAFETY: a new mapping of a descriptor we hold, the blob's size,
        // unmapped before returning.
        unsafe {
            let p = libc::mmap(
                ptr::null_mut(),
                buf.len(),
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(format!("mapping the blob: {}", io::Error::last_os_error()));
            }
            if write {
                ptr::copy_nonoverlapping(buf.as_ptr(), p as *mut u8, buf.len());
            } else {
                ptr::copy_nonoverlapping(p as *const u8, buf.as_mut_ptr(), buf.len());
            }
            libc::munmap(p, buf.len());
        }
        Ok(())
    }
}

fn write_level(id: u32, ch: &Chunk, buf: &mut [u8]) -> Result<(), String> {
    let mut b = VirglBox {
        x: ch.x,
        y: ch.y,
        z: ch.z,
        w: ch.w,
        h: ch.h,
        d: ch.d,
    };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };
    // SAFETY: the box and iovec outlive the call, which only reads the iovec.
    let ret = unsafe {
        virgl_renderer_transfer_write_iov(
            id,
            0,
            ch.level as c_int,
            ch.stride,
            ch.layer_stride,
            &mut b,
            0,
            &mut iov,
            1,
        )
    };
    if ret != 0 {
        return Err(format!("level {}: {ret}", ch.level));
    }
    Ok(())
}

fn restore_venus_context(ctx_id: u32) -> impl FnOnce(&[u8]) -> Result<(), String> {
    move |bytes| {
        let Some((_, restore)) = venus_snapshot() else {
            return Err("the renderer can't restore it".into());
        };
        // SAFETY: a new anonymous file, owned here.
        let fd = unsafe { libc::memfd_create(c"krun-venus".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        // SAFETY: fd was just created, and is owned here.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let fd = OwnedFd::from(file);
        // SAFETY: the renderer takes its own reference to the file.
        let ret = unsafe { restore(ctx_id, fd.as_raw_fd()) };
        if ret != 0 {
            return Err(format!("the renderer refused it ({ret})"));
        }
        Ok(())
    }
}
