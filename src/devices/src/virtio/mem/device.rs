// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::Range;
use std::sync::Arc;

use utils::eventfd::{EFD_NONBLOCK, EventFd};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::defs::{self, uapi::*};
use super::{MemError, Result};
use crate::virtio::descriptor_utils::{Reader, Writer};
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, PauseError,
    QueueConfig, VirtioDevice,
};

pub(crate) const REQ_INDEX: usize = 0;

pub(crate) const AVAIL_FEATURES: u64 = 1 << VIRTIO_F_VERSION_1 as u64;

/// The size of the blocks the guest plugs and unplugs: a huge page, so a
/// plugged block can be backed by one.
pub const BLOCK_SIZE: u64 = 2 << 20;

/// What the region's start and size are aligned to: Linux adds hotplugged
/// memory 128 MiB at a time, and a region that doesn't line up with that
/// wastes the part of a block it doesn't cover.
pub const REGION_ALIGN: u64 = 128 << 20;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VirtioMemConfig {
    pub block_size: u64,
    pub node_id: u16,
    pub padding: [u8; 6],
    pub addr: u64,
    pub region_size: u64,
    pub usable_region_size: u64,
    pub plugged_size: u64,
    pub requested_size: u64,
}

// SAFETY: plain data with no implicit padding.
unsafe impl ByteValued for VirtioMemConfig {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VirtioMemReq {
    pub req_type: u16,
    pub padding: [u16; 3],
    pub addr: u64,
    pub nb_blocks: u16,
    pub padding_1: [u16; 3],
}

// SAFETY: plain data with no implicit padding.
unsafe impl ByteValued for VirtioMemReq {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VirtioMemResp {
    pub resp_type: u16,
    pub padding: [u16; 3],
    pub state: u16,
}

// SAFETY: plain data with no implicit padding.
unsafe impl ByteValued for VirtioMemResp {}

pub struct Mem {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    pub(crate) config: VirtioMemConfig,
    // macOS gives unplugged memory back by its guest address.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    host_addr: usize,
    plugged: Vec<bool>,
    #[cfg(target_os = "macos")]
    map_sender: Option<crossbeam_channel::Sender<WorkerMessage>>,
}

impl Mem {
    pub(crate) fn queue_event(&self, idx: usize) -> &Arc<EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    /// A device for a region of `region_size` bytes, a multiple of
    /// [`REGION_ALIGN`], with nothing plugged and nothing requested.
    pub fn new(region_size: u64) -> Result<Mem> {
        if region_size == 0 || !region_size.is_multiple_of(REGION_ALIGN) {
            return Err(MemError::RegionSize(region_size));
        }
        Ok(Mem {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(EFD_NONBLOCK).map_err(MemError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioMemConfig {
                block_size: BLOCK_SIZE,
                region_size,
                usable_region_size: region_size,
                ..Default::default()
            },
            host_addr: 0,
            plugged: vec![false; (region_size / BLOCK_SIZE) as usize],
            #[cfg(target_os = "macos")]
            map_sender: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::MEM_DEV_ID
    }

    pub fn region_size(&self) -> u64 {
        self.config.region_size
    }

    /// Places the region at `guest_addr` in guest physical memory, mapped at
    /// `host_addr` in this process.
    pub fn set_region(&mut self, guest_addr: u64, host_addr: usize) {
        self.config.addr = guest_addr;
        self.host_addr = host_addr;
    }

    /// Sets the channel to the VMM worker, which gives unplugged memory back
    /// to the host: Hypervisor.framework keeps the pages it maps into the
    /// guest, which madvise() can't free.
    #[cfg(target_os = "macos")]
    pub fn set_map_sender(&mut self, map_sender: crossbeam_channel::Sender<WorkerMessage>) {
        self.map_sender = Some(map_sender);
    }

    pub fn requested_size(&self) -> u64 {
        self.config.requested_size
    }

    pub fn plugged_size(&self) -> u64 {
        self.config.plugged_size
    }

    /// Asks the guest to plug or unplug blocks until it has `size` bytes of
    /// the region.
    pub fn set_requested_size(&mut self, size: u64) -> Result<()> {
        if size > self.config.region_size || !size.is_multiple_of(BLOCK_SIZE) {
            return Err(MemError::RequestedSize(size));
        }
        if size == self.config.requested_size {
            return Ok(());
        }
        self.config.requested_size = size;
        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            interrupt.signal_config_change();
        }
        Ok(())
    }

    /// The indices of the `nb_blocks` blocks starting at `addr`, or None if
    /// they aren't all inside the region.
    fn blocks(&self, addr: u64, nb_blocks: u16) -> Option<Range<usize>> {
        let offset = addr.checked_sub(self.config.addr)?;
        let size = u64::from(nb_blocks) * BLOCK_SIZE;
        if nb_blocks == 0
            || !offset.is_multiple_of(BLOCK_SIZE)
            || offset.checked_add(size)? > self.config.usable_region_size
        {
            return None;
        }
        let first = (offset / BLOCK_SIZE) as usize;
        Some(first..first + nb_blocks as usize)
    }

    #[cfg(target_os = "linux")]
    fn discard(&self, blocks: Range<usize>) -> io::Result<()> {
        let offset = blocks.start as u64 * BLOCK_SIZE;
        let len = blocks.len() as u64 * BLOCK_SIZE;
        let addr = (self.host_addr + offset as usize) as *mut libc::c_void;
        // Shared guest memory (a memfd, for vhost-user) is only freed by
        // MADV_REMOVE. Private memory makes MADV_REMOVE fail with EINVAL, and
        // MADV_DONTNEED frees that instead.
        // SAFETY: the range lies in the region, which this process maps at
        // host_addr, and the guest has given it up.
        if unsafe { libc::madvise(addr, len as usize, libc::MADV_REMOVE) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
        // SAFETY: as above.
        if unsafe { libc::madvise(addr, len as usize, libc::MADV_DONTNEED) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Has the VMM replace the blocks' pages with fresh memory, which gives
    /// them back to the host, and waits for it: the guest may plug them again
    /// as soon as the unplug is answered.
    #[cfg(target_os = "macos")]
    fn discard(&self, blocks: Range<usize>) -> io::Result<()> {
        let Some(map_sender) = &self.map_sender else {
            return Err(io::Error::other("no channel to the VMM"));
        };
        let addr = self.config.addr + blocks.start as u64 * BLOCK_SIZE;
        let len = blocks.len() as u64 * BLOCK_SIZE;
        let (reply_sender, reply) = crossbeam_channel::bounded(1);
        map_sender
            .send(WorkerMessage::ReclaimMemory(reply_sender, addr, len))
            .map_err(|_| io::Error::other("the VMM has stopped"))?;
        match reply.recv() {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other("the VMM didn't replace the pages")),
            Err(_) => Err(io::Error::other("the VMM has stopped")),
        }
    }

    fn plug(&mut self, addr: u64, nb_blocks: u16) -> u16 {
        let size = u64::from(nb_blocks) * BLOCK_SIZE;
        if self.config.plugged_size + size > self.config.requested_size {
            return VIRTIO_MEM_RESP_NACK;
        }
        let Some(blocks) = self.blocks(addr, nb_blocks) else {
            return VIRTIO_MEM_RESP_ERROR;
        };
        if self.plugged[blocks.clone()].iter().any(|&p| p) {
            return VIRTIO_MEM_RESP_ERROR;
        }
        self.plugged[blocks].fill(true);
        self.config.plugged_size += size;
        VIRTIO_MEM_RESP_ACK
    }

    fn unplug(&mut self, addr: u64, nb_blocks: u16) -> u16 {
        let Some(blocks) = self.blocks(addr, nb_blocks) else {
            return VIRTIO_MEM_RESP_ERROR;
        };
        if !self.plugged[blocks.clone()].iter().all(|&p| p) {
            return VIRTIO_MEM_RESP_ERROR;
        }
        if let Err(e) = self.discard(blocks.clone()) {
            error!("mem: cannot discard unplugged memory: {e}");
            return VIRTIO_MEM_RESP_ERROR;
        }
        self.plugged[blocks.clone()].fill(false);
        self.config.plugged_size -= blocks.len() as u64 * BLOCK_SIZE;
        VIRTIO_MEM_RESP_ACK
    }

    fn unplug_all(&mut self) -> u16 {
        if let Err(e) = self.discard(0..self.plugged.len()) {
            error!("mem: cannot discard unplugged memory: {e}");
            return VIRTIO_MEM_RESP_ERROR;
        }
        self.plugged.fill(false);
        self.config.plugged_size = 0;
        VIRTIO_MEM_RESP_ACK
    }

    fn state(&self, addr: u64, nb_blocks: u16) -> (u16, u16) {
        let Some(blocks) = self.blocks(addr, nb_blocks) else {
            return (VIRTIO_MEM_RESP_ERROR, 0);
        };
        let blocks = &self.plugged[blocks];
        let state = if blocks.iter().all(|&p| p) {
            VIRTIO_MEM_STATE_PLUGGED
        } else if blocks.iter().all(|&p| !p) {
            VIRTIO_MEM_STATE_UNPLUGGED
        } else {
            VIRTIO_MEM_STATE_MIXED
        };
        (VIRTIO_MEM_RESP_ACK, state)
    }

    fn handle_request(&mut self, req: VirtioMemReq) -> VirtioMemResp {
        let (resp_type, state) = match req.req_type {
            VIRTIO_MEM_REQ_PLUG => (self.plug(req.addr, req.nb_blocks), 0),
            VIRTIO_MEM_REQ_UNPLUG => (self.unplug(req.addr, req.nb_blocks), 0),
            VIRTIO_MEM_REQ_UNPLUG_ALL => (self.unplug_all(), 0),
            VIRTIO_MEM_REQ_STATE => self.state(req.addr, req.nb_blocks),
            t => {
                warn!("mem: unknown request type {t}");
                (VIRTIO_MEM_RESP_ERROR, 0)
            }
        };
        VirtioMemResp {
            resp_type,
            state,
            ..Default::default()
        }
    }

    pub fn process_req(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem.clone(),
            DeviceState::Inactive => unreachable!(),
        };
        let mut have_used = false;
        loop {
            let queue = &mut self.queues.as_mut().expect("queues should exist")[REQ_INDEX].queue;
            let Some(head) = queue.pop(&mem) else {
                break;
            };
            let index = head.index;
            let len = match (Reader::new(&mem, head.clone()), Writer::new(&mem, head)) {
                (Ok(mut reader), Ok(mut writer)) => match reader.read_obj::<VirtioMemReq>() {
                    Ok(req) => {
                        let resp = self.handle_request(req);
                        match writer.write_obj(resp) {
                            Ok(()) => writer.bytes_written() as u32,
                            Err(e) => {
                                error!("mem: cannot write the response: {e}");
                                0
                            }
                        }
                    }
                    Err(e) => {
                        error!("mem: cannot read the request: {e}");
                        0
                    }
                },
                (Err(e), _) | (_, Err(e)) => {
                    error!("mem: invalid descriptor chain: {e:?}");
                    0
                }
            };
            let queue = &mut self.queues.as_mut().expect("queues should exist")[REQ_INDEX].queue;
            if let Err(e) = queue.add_used(&mem, index, len) {
                error!("mem: failed to add used elements to the queue: {e:?}");
            }
            have_used = true;
        }
        have_used
    }
}

impl VirtioDevice for Mem {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        VIRTIO_ID_MEM
    }

    fn device_name(&self) -> &str {
        "mem"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn config_len(&self) -> Option<u32> {
        Some(size_of::<VirtioMemConfig>() as u32)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = self.config.as_slice();
        let Some(src) = usize::try_from(offset)
            .ok()
            .and_then(|start| config.get(start..start.checked_add(data.len())?))
        else {
            error!("mem: config read out of bounds (offset={offset:x})");
            return;
        };
        data.copy_from_slice(src);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "mem: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    /// Event-loop driven, and `Vmm::snapshot` runs on that loop, so nothing of
    /// ours is running — just hand the queue over.
    fn pause(&mut self) -> std::result::Result<Vec<DeviceQueue>, PauseError> {
        Ok(self.queues.take().unwrap_or_default())
    }

    /// The requested size, then a byte for each block, 1 if it's plugged. The
    /// plugged blocks' contents are in the snapshot's memory with the rest
    /// of the guest's.
    fn save_state(&self) -> Vec<u8> {
        let mut state = self.config.requested_size.to_le_bytes().to_vec();
        state.extend(self.plugged.iter().map(|&p| p as u8));
        state
    }

    fn restore_state(&mut self, state: &[u8]) -> std::result::Result<(), crate::Error> {
        let (requested, plugged) = state.split_at_checked(8).ok_or_else(|| {
            crate::Error::Snapshot("virtio_mem: the snapshot's state is truncated".into())
        })?;
        if plugged.len() != self.plugged.len() {
            return Err(crate::Error::Snapshot(format!(
                "virtio_mem: snapshot has {} blocks, config has {}",
                plugged.len(),
                self.plugged.len()
            )));
        }
        self.config.requested_size = u64::from_le_bytes(requested.try_into().unwrap());
        self.plugged = plugged.iter().map(|&b| b != 0).collect();
        self.config.plugged_size = self.plugged.iter().filter(|&&p| p).count() as u64 * BLOCK_SIZE;
        Ok(())
    }

    fn reset(&mut self) -> bool {
        // Plugged memory stays plugged. Linux resets every virtio device as it
        // shuts down, while its processes are still using that memory, and a
        // driver that finds memory plugged when it starts unplugs it itself.
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        true
    }
}
