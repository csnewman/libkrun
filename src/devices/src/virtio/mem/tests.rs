// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests that drive the device through its queue in guest memory, the way a
//! guest driver does.

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use utils::eventfd::{EFD_NONBLOCK, EventFd};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use super::defs::uapi::*;
use super::device::{BLOCK_SIZE, Mem, VirtioMemConfig, VirtioMemReq, VirtioMemResp};
use crate::virtio::device::{InterruptHandler, InterruptType};
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{DeviceQueue, InterruptTransport, VirtioDevice};

const QUEUE_SIZE: u16 = 16;
const REQUEST_BUFFERS: u64 = 0x10000;
const RESP_OFFSET: u64 = 0x100;
const REGION: u64 = 0x1_0000_0000;
const REGION_SIZE: u64 = 256 << 20;

#[derive(Default)]
struct Interrupts {
    used: AtomicUsize,
    config: AtomicUsize,
}

impl InterruptHandler for Interrupts {
    fn try_signal(&self, interrupt: InterruptType) -> std::result::Result<(), crate::Error> {
        match interrupt {
            InterruptType::UsedQueue => self.used.fetch_add(1, Ordering::SeqCst),
            InterruptType::ConfigChange => self.config.fetch_add(1, Ordering::SeqCst),
        };
        Ok(())
    }
}

struct Harness {
    mem: GuestMemoryMmap,
    dev: Arc<Mutex<Mem>>,
    interrupts: Arc<Interrupts>,
    requests: Cell<u64>,
}

impl Harness {
    fn new() -> Self {
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 0x20000),
            (GuestAddress(REGION), REGION_SIZE as usize),
        ])
        .unwrap();
        let mut dev = Mem::new(REGION_SIZE).unwrap();
        let host_addr = mem.get_host_address(GuestAddress(REGION)).unwrap();
        dev.set_region(REGION, host_addr as usize);
        Self {
            mem,
            dev: Arc::new(Mutex::new(dev)),
            interrupts: Arc::new(Interrupts::default()),
            requests: Cell::new(0),
        }
    }

    fn activate(&self, queue: &VirtQueue) {
        let queue = DeviceQueue::new(
            queue.create_queue(),
            Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
        );
        self.dev
            .lock()
            .unwrap()
            .activate(
                self.mem.clone(),
                InterruptTransport::from_handler(self.interrupts.clone()),
                vec![queue],
            )
            .unwrap();
    }

    fn config(&self) -> VirtioMemConfig {
        let mut config = VirtioMemConfig::default();
        self.dev
            .lock()
            .unwrap()
            .read_config(0, config.as_mut_slice());
        config
    }

    fn request(&self, queue: &VirtQueue, req_type: u16, addr: u64, nb_blocks: u16) -> (u16, u16) {
        let req = VirtioMemReq {
            req_type,
            addr,
            nb_blocks,
            ..Default::default()
        };
        let slot = self.requests.get() % 8;
        let desc = (2 * slot) as u16;
        let req_addr = REQUEST_BUFFERS + slot * 0x200;
        let resp_addr = req_addr + RESP_OFFSET;
        self.mem.write_obj(req, GuestAddress(req_addr)).unwrap();
        self.mem
            .write_obj(
                VirtioMemResp {
                    resp_type: 0xffff,
                    ..Default::default()
                },
                GuestAddress(resp_addr),
            )
            .unwrap();
        let resp_len = size_of::<VirtioMemResp>() as u32;
        queue.dtable[desc as usize].set(
            req_addr,
            size_of::<VirtioMemReq>() as u32,
            VIRTQ_DESC_F_NEXT,
            desc + 1,
        );
        queue.dtable[desc as usize + 1].set(resp_addr, resp_len, VIRTQ_DESC_F_WRITE, 0);
        let idx = queue.avail.idx.get();
        queue.avail.ring[usize::from(idx % QUEUE_SIZE)].set(desc);
        queue.avail.idx.set(idx.wrapping_add(1));
        self.requests.set(self.requests.get() + 1);

        assert!(self.dev.lock().unwrap().process_req());
        let used = queue.used.idx.get();
        assert_eq!(
            queue.used.ring[usize::from((used - 1) % QUEUE_SIZE)]
                .get()
                .len,
            resp_len
        );
        let resp: VirtioMemResp = self.mem.read_obj(GuestAddress(resp_addr)).unwrap();
        (resp.resp_type, resp.state)
    }

    fn set_requested(&self, size: u64) {
        self.dev.lock().unwrap().set_requested_size(size).unwrap();
    }
}

fn block(n: u64) -> u64 {
    REGION + n * BLOCK_SIZE
}

#[test]
fn describes_its_region() {
    let h = Harness::new();
    let config = h.config();
    assert_eq!(config.block_size, BLOCK_SIZE);
    assert_eq!(config.addr, REGION);
    assert_eq!(config.region_size, REGION_SIZE);
    assert_eq!(config.usable_region_size, REGION_SIZE);
    assert_eq!(config.plugged_size, 0);
    assert_eq!(config.requested_size, 0);
}

#[test]
fn plugs_up_to_the_requested_size() {
    let h = Harness::new();
    let queue = VirtQueue::new(GuestAddress(0), &h.mem, QUEUE_SIZE);
    h.activate(&queue);

    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(0), 1).0,
        VIRTIO_MEM_RESP_NACK
    );

    h.set_requested(3 * BLOCK_SIZE);
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(0), 2).0,
        VIRTIO_MEM_RESP_ACK
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(4), 2).0,
        VIRTIO_MEM_RESP_NACK
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(4), 1).0,
        VIRTIO_MEM_RESP_ACK
    );
    assert_eq!(h.config().plugged_size, 3 * BLOCK_SIZE);
}

#[test]
fn refuses_ranges_outside_the_region_or_in_the_wrong_state() {
    let h = Harness::new();
    let queue = VirtQueue::new(GuestAddress(0), &h.mem, QUEUE_SIZE);
    h.activate(&queue);
    h.set_requested(REGION_SIZE);
    let blocks = REGION_SIZE / BLOCK_SIZE;

    for (addr, nb_blocks) in [
        (block(0) + 4096, 1),
        (REGION - BLOCK_SIZE, 1),
        (block(blocks - 1), 2),
        (block(0), 0),
        (u64::MAX - BLOCK_SIZE + 1, 1),
    ] {
        assert_eq!(
            h.request(&queue, VIRTIO_MEM_REQ_PLUG, addr, nb_blocks).0,
            VIRTIO_MEM_RESP_ERROR,
            "plug {addr:#x} x {nb_blocks}"
        );
    }

    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_UNPLUG, block(0), 1).0,
        VIRTIO_MEM_RESP_ERROR
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(0), 1).0,
        VIRTIO_MEM_RESP_ACK
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(0), 2).0,
        VIRTIO_MEM_RESP_ERROR
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_UNPLUG, block(0), 2).0,
        VIRTIO_MEM_RESP_ERROR
    );
    assert_eq!(h.request(&queue, 42, block(0), 1).0, VIRTIO_MEM_RESP_ERROR);
    assert_eq!(h.config().plugged_size, BLOCK_SIZE);
}

#[test]
fn unplugging_discards_the_memory() {
    let h = Harness::new();
    let queue = VirtQueue::new(GuestAddress(0), &h.mem, QUEUE_SIZE);
    h.activate(&queue);
    h.set_requested(2 * BLOCK_SIZE);
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(0), 2).0,
        VIRTIO_MEM_RESP_ACK
    );
    h.mem.write_obj(0x5a5a_u64, GuestAddress(block(0))).unwrap();
    h.mem.write_obj(0xa5a5_u64, GuestAddress(block(1))).unwrap();

    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_UNPLUG, block(0), 1).0,
        VIRTIO_MEM_RESP_ACK
    );
    assert_eq!(h.mem.read_obj::<u64>(GuestAddress(block(0))).unwrap(), 0);
    assert_eq!(
        h.mem.read_obj::<u64>(GuestAddress(block(1))).unwrap(),
        0xa5a5
    );
    assert_eq!(h.config().plugged_size, BLOCK_SIZE);

    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_UNPLUG_ALL, 0, 0).0,
        VIRTIO_MEM_RESP_ACK
    );
    assert_eq!(h.mem.read_obj::<u64>(GuestAddress(block(1))).unwrap(), 0);
    assert_eq!(h.config().plugged_size, 0);
}

#[test]
fn reports_the_state_of_a_range() {
    let h = Harness::new();
    let queue = VirtQueue::new(GuestAddress(0), &h.mem, QUEUE_SIZE);
    h.activate(&queue);
    h.set_requested(BLOCK_SIZE);
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(1), 1).0,
        VIRTIO_MEM_RESP_ACK
    );

    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_STATE, block(1), 1),
        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_PLUGGED)
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_STATE, block(2), 3),
        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_UNPLUGGED)
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_STATE, block(0), 3),
        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_MIXED)
    );
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_STATE, REGION + REGION_SIZE, 1)
            .0,
        VIRTIO_MEM_RESP_ERROR
    );
}

#[test]
fn a_new_requested_size_tells_the_driver() {
    let h = Harness::new();
    let queue = VirtQueue::new(GuestAddress(0), &h.mem, QUEUE_SIZE);

    h.set_requested(BLOCK_SIZE);
    h.activate(&queue);
    h.set_requested(4 * BLOCK_SIZE);
    h.set_requested(4 * BLOCK_SIZE);
    assert_eq!(h.interrupts.config.load(Ordering::SeqCst), 1);
    assert_eq!(h.config().requested_size, 4 * BLOCK_SIZE);

    let mut dev = h.dev.lock().unwrap();
    assert!(dev.set_requested_size(BLOCK_SIZE + 4096).is_err());
    assert!(dev.set_requested_size(REGION_SIZE + BLOCK_SIZE).is_err());
    assert_eq!(dev.requested_size(), 4 * BLOCK_SIZE);
}

#[test]
fn a_reset_leaves_memory_plugged() {
    let h = Harness::new();
    let queue = VirtQueue::new(GuestAddress(0), &h.mem, QUEUE_SIZE);
    h.activate(&queue);
    h.set_requested(BLOCK_SIZE);
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(0), 1).0,
        VIRTIO_MEM_RESP_ACK
    );
    h.mem.write_obj(1_u64, GuestAddress(block(0))).unwrap();

    assert!(h.dev.lock().unwrap().reset());
    assert_eq!(h.config().plugged_size, BLOCK_SIZE);
    assert_eq!(h.mem.read_obj::<u64>(GuestAddress(block(0))).unwrap(), 1);
}

#[test]
fn the_region_is_whole_memory_blocks() {
    assert!(Mem::new(0).is_err());
    assert!(Mem::new(64 << 20).is_err());
    assert!(Mem::new(128 << 20).is_ok());
}

#[test]
fn a_snapshot_keeps_what_is_plugged_and_requested() {
    let h = Harness::new();
    let queue = VirtQueue::new(GuestAddress(0), &h.mem, QUEUE_SIZE);
    h.activate(&queue);
    h.set_requested(4 * BLOCK_SIZE);
    assert_eq!(
        h.request(&queue, VIRTIO_MEM_REQ_PLUG, block(1), 2).0,
        VIRTIO_MEM_RESP_ACK
    );
    let state = {
        let mut dev = h.dev.lock().unwrap();
        assert_eq!(dev.pause().unwrap().len(), 1);
        dev.save_state()
    };

    let restored = Harness::new();
    restored.dev.lock().unwrap().restore_state(&state).unwrap();
    let queue = VirtQueue::new(GuestAddress(0), &restored.mem, QUEUE_SIZE);
    restored.activate(&queue);
    let config = restored.config();
    assert_eq!(config.requested_size, 4 * BLOCK_SIZE);
    assert_eq!(config.plugged_size, 2 * BLOCK_SIZE);
    assert_eq!(
        restored.request(&queue, VIRTIO_MEM_REQ_STATE, block(1), 2),
        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_PLUGGED)
    );
    assert_eq!(
        restored
            .request(&queue, VIRTIO_MEM_REQ_UNPLUG, block(2), 1)
            .0,
        VIRTIO_MEM_RESP_ACK
    );

    let mut other = Mem::new(2 * REGION_SIZE).unwrap();
    assert!(other.restore_state(&state).is_err());
    assert!(other.restore_state(&state[..4]).is_err());
}
