//! VM snapshot format.
//!
//! A snapshot is a directory: `manifest.json`, which says what VM it is, the
//! `vmstate` blob with the vCPU, interrupt controller and device sections, and
//! `memory.img`, guest RAM in address order. Each backend encodes its own vCPU
//! and interrupt controller sections; devices encode theirs.

use std::env::consts;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::{fmt, slice};

use devices::SavedState;
use serde::{Deserialize, Serialize};
use vm_memory::{
    GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
};

pub const MANIFEST_NAME: &str = "manifest.json";
pub const VMSTATE_NAME: &str = "vmstate";
pub const MEMORY_NAME: &str = "memory.img";

/// Current manifest schema version. Independent of [`VMSTATE_VERSION`].
pub const MANIFEST_VERSION: u32 = 1;

/// `vmstate` blob magic. Bumps only on an incompatible framing change.
pub const VMSTATE_MAGIC: &[u8; 4] = b"KRSV";
/// Framing version (the header layout), independent of any section's version.
pub const VMSTATE_VERSION: u32 = 1;

#[derive(Debug)]
pub enum SnapErr {
    Io(io::Error),
    /// A manifest or vmstate version this build cannot read.
    Version {
        expected: u32,
        found: u32,
    },
    /// A device, vCPU or the configuration rejected the state.
    State(String),
}

impl From<io::Error> for SnapErr {
    fn from(e: io::Error) -> Self {
        SnapErr::Io(e)
    }
}

impl fmt::Display for SnapErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnapErr::Io(e) => write!(f, "{e}"),
            SnapErr::Version { expected, found } => {
                write!(f, "unsupported version {found}, expected {expected}")
            }
            SnapErr::State(s) => write!(f, "{s}"),
        }
    }
}

/// What a snapshot's VM is: what a restored VM must be configured as.
#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub libkrun_version: String,
    pub arch: String,
    pub backend: String,
    pub mem_size_mib: usize,
    pub vcpu_count: u8,
    pub vmstate_version: u32,
    /// Device ids in registration order. Restore matches saved device state to
    /// the configured devices by position, so this is the topology the restore
    /// configuration must reproduce exactly.
    pub devices: Vec<String>,
}

impl Manifest {
    pub fn new(mem_size_mib: usize, vcpu_count: u8, devices: Vec<String>) -> Self {
        Self {
            manifest_version: MANIFEST_VERSION,
            libkrun_version: env!("CARGO_PKG_VERSION").to_string(),
            arch: consts::ARCH.to_string(),
            backend: BACKEND.to_string(),
            mem_size_mib,
            vcpu_count,
            vmstate_version: VMSTATE_VERSION,
            devices,
        }
    }

    /// Rejects a freshly configured VM that doesn't match the snapshot it is
    /// restoring into.
    pub fn validate(
        &self,
        mem_size_mib: usize,
        vcpu_count: u8,
        devices: &[String],
    ) -> Result<(), SnapErr> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(SnapErr::Version {
                expected: MANIFEST_VERSION,
                found: self.manifest_version,
            });
        }
        let mismatch = |field: &str, want: &dyn fmt::Display, got: &dyn fmt::Display| {
            SnapErr::State(format!(
                "snapshot {field} mismatch: snapshot={want}, config={got}"
            ))
        };
        if self.arch != consts::ARCH {
            return Err(mismatch("arch", &self.arch, &consts::ARCH));
        }
        if self.backend != BACKEND {
            return Err(mismatch("backend", &self.backend, &BACKEND));
        }
        if self.mem_size_mib != mem_size_mib {
            return Err(mismatch("mem_size_mib", &self.mem_size_mib, &mem_size_mib));
        }
        if self.vcpu_count != vcpu_count {
            return Err(mismatch("vcpu_count", &self.vcpu_count, &vcpu_count));
        }
        if self.devices != devices {
            return Err(SnapErr::State(format!(
                "snapshot device topology mismatch: snapshot={:?}, config={:?}",
                self.devices, devices
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
const BACKEND: &str = "kvm";
#[cfg(target_os = "macos")]
const BACKEND: &str = "hvf";
#[cfg(target_os = "windows")]
const BACKEND: &str = "whp";

/// Section tags. The byte values are part of the on-disk format — append only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SectionId {
    Vcpu = 0,
    Irqchip = 1,
    Device = 2,
}

/// Builds a `vmstate` blob: magic, version, then sections, each
/// `[id:u8][version:u8][len:u32 LE][bytes]`.
pub struct VmstateWriter {
    buf: Vec<u8>,
}

impl VmstateWriter {
    pub fn new() -> Self {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(VMSTATE_MAGIC);
        buf.extend_from_slice(&VMSTATE_VERSION.to_le_bytes());
        Self { buf }
    }

    pub fn section(&mut self, id: SectionId, version: u8, bytes: &[u8]) {
        self.buf.push(id as u8);
        self.buf.push(version);
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(bytes);
    }

    /// A device section: `[id_len:u16 LE][id][state]`, with the device's own
    /// state version.
    pub fn device(&mut self, id: &str, state: &SavedState) {
        let mut payload = Vec::with_capacity(2 + id.len() + state.bytes.len());
        payload.extend_from_slice(&(id.len() as u16).to_le_bytes());
        payload.extend_from_slice(id.as_bytes());
        payload.extend_from_slice(&state.bytes);
        self.section(SectionId::Device, state.version, &payload);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// One decoded section, borrowed from the blob.
pub struct Section<'a> {
    pub id: u8,
    pub version: u8,
    pub bytes: &'a [u8],
}

/// Checks the header and iterates the sections. A truncated section is an
/// error, not a partial value.
pub struct VmstateReader<'a> {
    rest: &'a [u8],
}

impl<'a> VmstateReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, SnapErr> {
        if data.len() < 8 || &data[0..4] != VMSTATE_MAGIC {
            return Err(SnapErr::State("vmstate: bad magic".into()));
        }
        let found = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if found != VMSTATE_VERSION {
            return Err(SnapErr::Version {
                expected: VMSTATE_VERSION,
                found,
            });
        }
        Ok(Self { rest: &data[8..] })
    }
}

impl<'a> Iterator for VmstateReader<'a> {
    type Item = Result<Section<'a>, SnapErr>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 6 {
            return Some(Err(SnapErr::State(
                "vmstate: truncated section header".into(),
            )));
        }
        let id = self.rest[0];
        let version = self.rest[1];
        let len = u32::from_le_bytes(self.rest[2..6].try_into().unwrap()) as usize;
        let end = 6 + len;
        if self.rest.len() < end {
            return Some(Err(SnapErr::State(
                "vmstate: truncated section body".into(),
            )));
        }
        let bytes = &self.rest[6..end];
        self.rest = &self.rest[end..];
        Some(Ok(Section { id, version, bytes }))
    }
}

/// A snapshot read back from its directory.
pub struct Snapshot {
    pub manifest: Manifest,
    /// One per vCPU, in vCPU order, each `(version, state)`.
    pub vcpus: Vec<(u8, Vec<u8>)>,
    pub irqchip: Option<(u8, Vec<u8>)>,
    /// `(device id, state)`, in registration order.
    pub devices: Vec<(String, SavedState)>,
    pub memory: PathBuf,
}

impl Snapshot {
    pub fn read(dir: &Path) -> Result<Self, SnapErr> {
        let manifest: Manifest = serde_json::from_slice(&fs::read(dir.join(MANIFEST_NAME))?)
            .map_err(|e| SnapErr::State(format!("manifest: {e}")))?;
        let blob = fs::read(dir.join(VMSTATE_NAME))?;
        let mut vcpus = Vec::new();
        let mut irqchip = None;
        let mut devices = Vec::new();
        for section in VmstateReader::new(&blob)? {
            let s = section?;
            match s.id {
                x if x == SectionId::Vcpu as u8 => vcpus.push((s.version, s.bytes.to_vec())),
                x if x == SectionId::Irqchip as u8 => irqchip = Some((s.version, s.bytes.to_vec())),
                x if x == SectionId::Device as u8 => {
                    let (id, bytes) = split_device_section(s.bytes)?;
                    devices.push((
                        id,
                        SavedState {
                            version: s.version,
                            bytes,
                        },
                    ));
                }
                other => {
                    return Err(SnapErr::State(format!(
                        "vmstate: unknown section id {other}"
                    )));
                }
            }
        }
        Ok(Self {
            manifest,
            vcpus,
            irqchip,
            devices,
            memory: dir.join(MEMORY_NAME),
        })
    }
}

fn split_device_section(bytes: &[u8]) -> Result<(String, Vec<u8>), SnapErr> {
    let id_len = bytes
        .get(0..2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| SnapErr::State("device section: truncated id length".into()))?;
    let end = 2 + id_len;
    let id = bytes
        .get(2..end)
        .ok_or_else(|| SnapErr::State("device section: truncated id".into()))?;
    let id = String::from_utf8(id.to_vec())
        .map_err(|e| SnapErr::State(format!("device id utf8: {e}")))?;
    Ok((id, bytes[end..].to_vec()))
}

/// Writes a snapshot directory. Creates `dir` if needed.
pub fn write(
    dir: &Path,
    manifest: &Manifest,
    vmstate: &[u8],
    mem: &GuestMemoryMmap,
    shared: &[GuestAddress],
) -> Result<(), SnapErr> {
    fs::create_dir_all(dir)?;
    let json = serde_json::to_vec_pretty(manifest).map_err(|e| SnapErr::State(e.to_string()))?;
    fs::write(dir.join(MANIFEST_NAME), json)?;
    fs::write(dir.join(VMSTATE_NAME), vmstate)?;
    write_memory(mem, shared, &File::create(dir.join(MEMORY_NAME))?)
}

const PAGE: usize = 4096;

/// The regions of guest memory a snapshot carries: all but the shared memory
/// windows devices map their own memory into, which those devices restore.
fn ram<'a>(
    mem: &'a GuestMemoryMmap,
    shared: &'a [GuestAddress],
) -> impl Iterator<Item = &'a GuestRegionMmap> {
    mem.iter().filter(|r| !shared.contains(&r.start_addr()))
}

/// Writes guest RAM to `file`, regions in address order, leaving holes where
/// pages are zero: a guest's untouched and freed memory costs no disk, and a
/// restore doesn't touch it.
pub fn write_memory(
    mem: &GuestMemoryMmap,
    shared: &[GuestAddress],
    file: &File,
) -> Result<(), SnapErr> {
    let mut offset = 0u64;
    for region in ram(mem, shared) {
        let len = region.len() as usize;
        let host = mem
            .get_host_address(region.start_addr())
            .map_err(|e| SnapErr::State(format!("guest memory host address: {e:?}")))?;
        // SAFETY: the vCPUs and device workers are stopped, so the region is
        // quiescent, and the mapping outlives this read.
        let bytes = unsafe { slice::from_raw_parts(host, len) };
        let mut start = 0;
        while start < len {
            if is_zero(&bytes[start..(start + PAGE).min(len)]) {
                start += PAGE;
                continue;
            }
            let mut end = start + PAGE;
            while end < len && !is_zero(&bytes[end..(end + PAGE).min(len)]) {
                end += PAGE;
            }
            let end = end.min(len);
            file.write_all_at(&bytes[start..end], offset + start as u64)?;
            start = end;
        }
        offset += len as u64;
    }
    file.set_len(offset)?;
    Ok(())
}

fn is_zero(page: &[u8]) -> bool {
    let (prefix, words, suffix) = unsafe { page.align_to::<u64>() };
    prefix.iter().all(|&b| b == 0)
        && words.iter().all(|&w| w == 0)
        && suffix.iter().all(|&b| b == 0)
}

/// Loads `memory.img` into freshly created guest RAM, copying only the image's
/// data: its holes are zero, which the new RAM already is.
pub fn read_memory(
    mem: &GuestMemoryMmap,
    shared: &[GuestAddress],
    path: &Path,
) -> Result<(), SnapErr> {
    let file = File::open(path)?;
    let total: u64 = ram(mem, shared).map(|r| r.len()).sum();
    if file.metadata()?.len() != total {
        return Err(SnapErr::State(format!(
            "memory image is {} bytes, guest memory {total}",
            file.metadata()?.len()
        )));
    }
    let mut offset = 0u64;
    for region in ram(mem, shared) {
        let len = region.len();
        let host = mem
            .get_host_address(region.start_addr())
            .map_err(|e| SnapErr::State(format!("guest memory host address: {e:?}")))?;
        // SAFETY: the vCPUs haven't started, so the region is ours alone, and
        // the mapping outlives this write.
        let bytes = unsafe { slice::from_raw_parts_mut(host, len as usize) };
        let end = offset + len;
        let mut pos = offset;
        while pos < end {
            let data = seek(&file, pos, libc::SEEK_DATA)?.unwrap_or(end).min(end);
            clear(&mut bytes[(pos - offset) as usize..(data - offset) as usize])?;
            if data == end {
                break;
            }
            let hole = seek(&file, data, libc::SEEK_HOLE)?.unwrap_or(end).min(end);
            let range = (data - offset) as usize..(hole - offset) as usize;
            file.read_exact_at(&mut bytes[range], data)?;
            pos = hole;
        }
        offset += len;
    }
    Ok(())
}

/// Zeroes what the VM's build wrote where the snapshot has a hole: the
/// kernel, initrd and device tree a restored VM was built with. Only the pages
/// in memory can hold anything, so the rest isn't touched.
fn clear(range: &mut [u8]) -> Result<(), SnapErr> {
    if range.is_empty() {
        return Ok(());
    }
    let mut resident = vec![0u8; range.len().div_ceil(PAGE)];
    // SAFETY: `range` is a page-aligned part of guest memory's mapping, and
    // `resident` has a byte for each of its pages.
    let r = unsafe {
        libc::mincore(
            range.as_mut_ptr() as *mut libc::c_void,
            range.len(),
            resident.as_mut_ptr() as *mut _,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let len = range.len();
    for (page, _) in resident.iter().enumerate().filter(|(_, r)| **r & 1 != 0) {
        let bytes = &mut range[page * PAGE..((page + 1) * PAGE).min(len)];
        if !is_zero(bytes) {
            bytes.fill(0);
        }
    }
    Ok(())
}

/// `lseek` to the next data or hole at or after `pos`; `None` when there is
/// no more data.
fn seek(file: &File, pos: u64, whence: i32) -> Result<Option<u64>, SnapErr> {
    // SAFETY: lseek on an open fd, with no memory passed.
    let r = unsafe { libc::lseek(file.as_raw_fd(), pos as libc::off_t, whence) };
    if r < 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENXIO) => Ok(None),
            _ => Err(err.into()),
        };
    }
    Ok(Some(r as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, process};
    use vm_memory::Bytes;

    #[test]
    fn vmstate_round_trips() {
        let mut w = VmstateWriter::new();
        w.section(SectionId::Vcpu, 1, &[1, 2, 3]);
        w.device(
            "blk0",
            &SavedState {
                version: 7,
                bytes: b"state".to_vec(),
            },
        );
        let blob = w.finish();

        let secs: Vec<_> = VmstateReader::new(&blob)
            .unwrap()
            .map(|s| s.unwrap())
            .collect();
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].id, SectionId::Vcpu as u8);
        assert_eq!(secs[0].bytes, &[1, 2, 3]);
        assert_eq!(secs[1].id, SectionId::Device as u8);
        assert_eq!(secs[1].version, 7);
        let (id, bytes) = split_device_section(secs[1].bytes).unwrap();
        assert_eq!(id, "blk0");
        assert_eq!(bytes, b"state");
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        assert!(matches!(
            VmstateReader::new(b"XXXX\x01\x00\x00\x00"),
            Err(SnapErr::State(_))
        ));
        let mut blob = VMSTATE_MAGIC.to_vec();
        blob.extend_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            VmstateReader::new(&blob),
            Err(SnapErr::Version { found: 99, .. })
        ));
    }

    #[test]
    fn detects_truncated_body() {
        let mut blob = VMSTATE_MAGIC.to_vec();
        blob.extend_from_slice(&VMSTATE_VERSION.to_le_bytes());
        blob.extend_from_slice(&[SectionId::Vcpu as u8, 1, 10, 0, 0, 0]);
        blob.extend_from_slice(&[0, 0]);
        let mut r = VmstateReader::new(&blob).unwrap();
        assert!(matches!(r.next(), Some(Err(SnapErr::State(_)))));
    }

    #[test]
    fn manifest_validate_rejects_mismatch() {
        let m = Manifest::new(512, 2, vec!["fs".into(), "console".into()]);
        let devs = ["fs".to_string(), "console".to_string()];
        assert!(m.validate(512, 2, &devs).is_ok());
        assert!(m.validate(256, 2, &devs).is_err());
        assert!(m.validate(512, 1, &devs).is_err());
        assert!(m.validate(512, 2, &devs[..1]).is_err());
        assert!(
            m.validate(512, 2, &["console".to_string(), "fs".to_string()])
                .is_err()
        );
    }

    #[test]
    fn memory_round_trips_with_holes() {
        let dir = env::temp_dir().join(format!("krun-snap-mem-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(MEMORY_NAME);

        let layout = [
            (GuestAddress(0), 0x10_0000),
            (GuestAddress(0x20_0000), 0x10_0000),
        ];
        let mem = GuestMemoryMmap::from_ranges(&layout).unwrap();
        mem.write_slice(&[0xAA; 0x1800], GuestAddress(0x3000))
            .unwrap();
        mem.write_slice(&[0xBB; 8], GuestAddress(0x20_0ff8))
            .unwrap();
        write_memory(&mem, &[], &File::create(&path).unwrap()).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 0x20_0000);

        let back = GuestMemoryMmap::from_ranges(&layout).unwrap();
        // What a VM's build loads where the snapshot has holes is cleared.
        back.write_slice(&[0xCC; 0x2000], GuestAddress(0x8000))
            .unwrap();
        back.write_slice(&[0xCC; 0x10], GuestAddress(0x20_0000))
            .unwrap();
        read_memory(&back, &[], &path).unwrap();
        for (addr, len) in layout {
            let mut a = vec![0; len];
            let mut b = vec![0; len];
            mem.read_slice(&mut a, addr).unwrap();
            back.read_slice(&mut b, addr).unwrap();
            assert!(a == b);
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
