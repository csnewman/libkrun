// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! virtio-mem: guest memory that grows and shrinks while the guest runs.
//!
//! The device owns a region of guest physical memory past the end of RAM,
//! which the guest doesn't see as RAM. The host sets how much of it the
//! guest should have (the requested size), and the guest's driver plugs
//! blocks of it in or unplugs them to match. Unplugged blocks are discarded,
//! so their memory goes back to the host.

mod device;
mod event_handler;

#[cfg(test)]
mod tests;

pub use self::defs::uapi::VIRTIO_ID_MEM as TYPE_MEM;
pub use self::device::{BLOCK_SIZE, Mem, REGION_ALIGN};

mod defs {
    use crate::virtio::QueueConfig;

    pub const MEM_DEV_ID: &str = "virtio_mem";
    pub const NUM_QUEUES: usize = 1;
    const QUEUE_SIZE: u16 = 128;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_MEM: u32 = 24;

        pub const VIRTIO_MEM_REQ_PLUG: u16 = 0;
        pub const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
        pub const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
        pub const VIRTIO_MEM_REQ_STATE: u16 = 3;

        pub const VIRTIO_MEM_RESP_ACK: u16 = 0;
        pub const VIRTIO_MEM_RESP_NACK: u16 = 1;
        pub const VIRTIO_MEM_RESP_ERROR: u16 = 3;

        pub const VIRTIO_MEM_STATE_PLUGGED: u16 = 0;
        pub const VIRTIO_MEM_STATE_UNPLUGGED: u16 = 1;
        pub const VIRTIO_MEM_STATE_MIXED: u16 = 2;
    }
}

#[derive(Debug)]
pub enum MemError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// The region is empty, or isn't a multiple of 128 MiB.
    RegionSize(u64),
    /// The requested size isn't a whole number of blocks, or is larger than
    /// the region.
    RequestedSize(u64),
}

type Result<T> = std::result::Result<T, MemError>;
