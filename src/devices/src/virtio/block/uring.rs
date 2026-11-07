//! Reads and writes on a raw image through io_uring, straight between the
//! image file and guest memory: no thread hands a request on, no buffer is
//! copied, and the completions of a batch are taken together.
//!
//! One ring serves one queue, owned by that queue's worker. Every other
//! request -- flushes, discards, write-zeroes -- waits for the ring to be
//! idle and is served as before.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use io_uring::{IoUring, opcode, types};
use log::error;
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_blk::{VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK};
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

/// A request's header, which a write's readable buffers begin with.
const HEADER_LEN: usize = 16;

pub(crate) struct Uring {
    ring: IoUring,
    /// Signalled by the kernel as requests complete.
    pub(crate) event: EventFd,
    file: Arc<File>,
    /// The disk's size in bytes, which no request may reach past.
    capacity: u64,
    /// The alignment of offsets and lengths, and of buffers in memory, that
    /// the file needs: more than 1 with direct I/O.
    req_align: usize,
    mem_align: usize,
    slots: Vec<Option<Request>>,
    free: Vec<usize>,
}

struct Request {
    head_index: u16,
    // Points into guest memory, which outlives the worker.
    iovecs: Vec<libc::iovec>,
    data_len: usize,
    status: GuestAddress,
    read: bool,
}

// SAFETY: a request's iovecs point into guest memory, which lasts as long as
// the VM, and only the worker that owns the ring uses them.
unsafe impl Send for Request {}

/// Why the ring turns a request down.
pub(crate) enum Refused {
    /// The device refuses it: its caller completes it with an error.
    Invalid,
    /// It misses the alignment the file needs for direct I/O: its caller
    /// serves it without the ring.
    Unaligned,
}

impl Uring {
    pub(crate) fn new(
        file: Arc<File>,
        capacity: u64,
        depth: u32,
        req_align: usize,
        mem_align: usize,
    ) -> io::Result<Self> {
        let ring = IoUring::new(depth)?;
        let event = EventFd::new(EFD_NONBLOCK)?;
        ring.submitter().register_eventfd(event.as_raw_fd())?;
        let depth = depth as usize;
        Ok(Self {
            ring,
            event,
            file,
            capacity,
            req_align,
            mem_align,
            slots: (0..depth).map(|_| None).collect(),
            free: (0..depth).rev().collect(),
        })
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.free.is_empty()
    }

    /// Queues a read (`writable`: the data then the status byte) or a write
    /// (`readable`: the header then the data; `writable`: the status byte).
    /// Nothing reaches the kernel until [`Uring::submit`].
    pub(crate) fn push(
        &mut self,
        mem: &GuestMemoryMmap,
        head_index: u16,
        read: bool,
        sector: u64,
        readable: &[(GuestAddress, u32)],
        writable: &[(GuestAddress, u32)],
    ) -> Result<(), Refused> {
        let total = |list: &[(GuestAddress, u32)]| -> usize {
            list.iter().map(|&(_, len)| len as usize).sum()
        };
        let (data, data_len, status) = if read {
            let len = total(writable).checked_sub(1).ok_or(Refused::Invalid)?;
            (segments(writable, 0, len), len, address_at(writable, len))
        } else {
            let len = total(readable)
                .checked_sub(HEADER_LEN)
                .ok_or(Refused::Invalid)?;
            (
                segments(readable, HEADER_LEN, len),
                len,
                address_at(writable, 0),
            )
        };
        let status = status.ok_or(Refused::Invalid)?;
        if !data_len.is_multiple_of(512) || data_len == 0 {
            return Err(Refused::Invalid);
        }
        let offset = sector.checked_mul(512).ok_or(Refused::Invalid)?;
        if offset
            .checked_add(data_len as u64)
            .is_none_or(|end| end > self.capacity)
        {
            return Err(Refused::Invalid);
        }
        let mut iovecs = Vec::with_capacity(data.len());
        for (addr, len) in data {
            let slice = mem.get_slice(addr, len).map_err(|_| Refused::Invalid)?;
            iovecs.push(libc::iovec {
                iov_base: slice.ptr_guard_mut().as_ptr().cast(),
                iov_len: len,
            });
        }
        if !offset.is_multiple_of(self.req_align as u64)
            || iovecs.iter().any(|iov| {
                !(iov.iov_base as usize).is_multiple_of(self.mem_align)
                    || !iov.iov_len.is_multiple_of(self.req_align)
            })
        {
            return Err(Refused::Unaligned);
        }
        let slot = self.free.pop().ok_or(Refused::Invalid)?;
        let fd = types::Fd(self.file.as_raw_fd());
        let entry = if read {
            opcode::Readv::new(fd, iovecs.as_ptr(), iovecs.len() as u32)
                .offset(offset)
                .build()
        } else {
            opcode::Writev::new(fd, iovecs.as_ptr(), iovecs.len() as u32)
                .offset(offset)
                .build()
        }
        .user_data(slot as u64);
        // The iovecs live in the slot, whose vector does not move them.
        self.slots[slot] = Some(Request {
            head_index,
            iovecs,
            data_len,
            status,
            read,
        });
        // SAFETY: the entry's buffers are guest memory and the slot's iovecs,
        // both kept until its completion is taken.
        while unsafe { self.ring.submission().push(&entry) }.is_err() {
            if let Err(e) = self.ring.submit() {
                error!("io_uring submit: {e}");
            }
        }
        Ok(())
    }

    /// Hands the kernel what has been queued.
    pub(crate) fn submit(&mut self) {
        if let Err(e) = self.ring.submit() {
            error!("io_uring submit: {e}");
        }
    }

    /// Takes the completions there are, writing each request's status, and
    /// returns each as its descriptor head and the length used.
    pub(crate) fn complete(&mut self, mem: &GuestMemoryMmap) -> Vec<(u16, u32)> {
        let _ = self.event.read();
        let cqes: Vec<_> = self.ring.completion().collect();
        let mut done = Vec::with_capacity(cqes.len());
        for cqe in cqes {
            let slot = cqe.user_data() as usize;
            let Some(req) = self.slots.get_mut(slot).and_then(Option::take) else {
                continue;
            };
            self.free.push(slot);
            let res = cqe.result();
            let ok = if res < 0 {
                error!(
                    "io_uring {}: {}",
                    if req.read { "read" } else { "write" },
                    io::Error::from_raw_os_error(-res)
                );
                false
            } else if req.read {
                // Past the end of a sparse image's file reads as zeroes.
                zero_from(&req.iovecs, res as usize);
                true
            } else {
                res as usize == req.data_len
            };
            let status: u8 = if ok {
                VIRTIO_BLK_S_OK as u8
            } else {
                VIRTIO_BLK_S_IOERR as u8
            };
            let status_len = match mem.write_obj(status, req.status) {
                Ok(()) => 1,
                Err(e) => {
                    error!("Failed to write virtio block status: {e:?}");
                    0
                }
            };
            let len = if req.read && ok { req.data_len } else { 0 } + status_len;
            done.push((req.head_index, len as u32));
        }
        done
    }

    /// Waits for every request in flight, as [`Uring::complete`] returns them.
    pub(crate) fn wait_idle(&mut self, mem: &GuestMemoryMmap) -> Vec<(u16, u32)> {
        let mut done = Vec::new();
        while self.in_flight() > 0 {
            if let Err(e) = self.ring.submit_and_wait(1) {
                error!("io_uring wait: {e}");
                break;
            }
            done.extend(self.complete(mem));
        }
        done
    }

    /// Waits for at least one request in flight to complete.
    pub(crate) fn wait_one(&mut self, mem: &GuestMemoryMmap) -> Vec<(u16, u32)> {
        if let Err(e) = self.ring.submit_and_wait(1) {
            error!("io_uring wait: {e}");
        }
        self.complete(mem)
    }
}

/// The part of a buffer list from `skip` bytes in, `len` bytes long.
fn segments(list: &[(GuestAddress, u32)], skip: usize, len: usize) -> Vec<(GuestAddress, usize)> {
    let mut out = Vec::new();
    let (mut skip, mut len) = (skip, len);
    for &(addr, size) in list {
        let size = size as usize;
        if skip >= size {
            skip -= size;
            continue;
        }
        if len == 0 {
            break;
        }
        let take = (size - skip).min(len);
        out.push((GuestAddress(addr.0 + skip as u64), take));
        len -= take;
        skip = 0;
    }
    out
}

/// The guest address `offset` bytes into a buffer list.
fn address_at(list: &[(GuestAddress, u32)], offset: usize) -> Option<GuestAddress> {
    let mut offset = offset;
    for &(addr, size) in list {
        if offset < size as usize {
            return Some(GuestAddress(addr.0 + offset as u64));
        }
        offset -= size as usize;
    }
    None
}

/// Zeroes the buffers from `from` bytes in to their end.
fn zero_from(iovecs: &[libc::iovec], from: usize) {
    let mut skip = from;
    for iov in iovecs {
        if skip >= iov.iov_len {
            skip -= iov.iov_len;
            continue;
        }
        // SAFETY: each iovec is a validated range of guest memory.
        unsafe {
            std::ptr::write_bytes((iov.iov_base as *mut u8).add(skip), 0, iov.iov_len - skip)
        };
        skip = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> Vec<(GuestAddress, u32)> {
        vec![
            (GuestAddress(0x1000), 16),
            (GuestAddress(0x2000), 1024),
            (GuestAddress(0x3000), 1),
        ]
    }

    #[test]
    fn segments_skip_the_header_and_stop_at_the_data() {
        assert_eq!(
            segments(&list(), 16, 1024),
            vec![(GuestAddress(0x2000), 1024)]
        );
        assert_eq!(
            segments(&list(), 8, 520),
            vec![(GuestAddress(0x1008), 8), (GuestAddress(0x2000), 512)]
        );
    }

    #[test]
    fn writes_and_reads_go_between_the_file_and_guest_memory() {
        use std::io::Write as _;
        use utils::tempfile::TempFile;

        let backing = TempFile::new().unwrap();
        backing.as_file().write_all(&[0x11; 1024]).unwrap();
        let file = Arc::new(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(backing.as_path())
                .unwrap(),
        );
        // Two sectors of file, four of disk: the last two read as zeroes.
        let mut uring = Uring::new(file, 2048, 8, 1, 1).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        // A write of 512 bytes of 0x5a to sector 1.
        mem.write_slice(&[0x5a; 512], GuestAddress(0x2000)).unwrap();
        uring
            .push(
                &mem,
                7,
                false,
                1,
                &[(GuestAddress(0x1000), 16), (GuestAddress(0x2000), 512)],
                &[(GuestAddress(0x3000), 1)],
            )
            .ok()
            .unwrap();
        assert_eq!(uring.wait_idle(&mem), vec![(7, 1)]);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0);

        // A read of sectors 1 to 3 -- the write, then past the file's end --
        // into two buffers, its status byte in the second.
        mem.write_slice(&[0xff; 1537], GuestAddress(0x4000))
            .unwrap();
        uring
            .push(
                &mem,
                9,
                true,
                1,
                &[(GuestAddress(0x1000), 16)],
                &[(GuestAddress(0x4000), 1024), (GuestAddress(0x5000), 513)],
            )
            .ok()
            .unwrap();
        assert_eq!(uring.wait_idle(&mem), vec![(9, 1537)]);
        let mut data = [0; 1024];
        mem.read_slice(&mut data, GuestAddress(0x4000)).unwrap();
        assert_eq!(&data[..512], &[0x5a; 512]);
        assert_eq!(&data[512..], &[0; 512]);
        let mut tail = [0; 513];
        mem.read_slice(&mut tail, GuestAddress(0x5000)).unwrap();
        assert_eq!(&tail[..512], &[0; 512]);
        assert_eq!(tail[512], 0);

        // Past the disk's end, refused.
        assert!(
            uring
                .push(
                    &mem,
                    1,
                    true,
                    4,
                    &[(GuestAddress(0x1000), 16)],
                    &[(GuestAddress(0x4000), 513)],
                )
                .is_err()
        );
    }

    #[test]
    fn requests_off_the_files_alignment_are_left_to_the_caller() {
        use utils::tempfile::TempFile;

        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(16384).unwrap();
        let file = Arc::new(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(backing.as_path())
                .unwrap(),
        );
        let mut uring = Uring::new(file, 16384, 8, 4096, 4096).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let header = [(GuestAddress(0x1000), 16)];

        // 512 bytes at sector 1: neither offset nor length is aligned.
        assert!(matches!(
            uring.push(
                &mem,
                1,
                true,
                1,
                &header,
                &[(GuestAddress(0x2000), 512), (GuestAddress(0x3000), 1)],
            ),
            Err(Refused::Unaligned)
        ));
        // An aligned offset and length, into a buffer that is not.
        assert!(matches!(
            uring.push(
                &mem,
                2,
                true,
                8,
                &header,
                &[(GuestAddress(0x2200), 4096), (GuestAddress(0x4000), 1)],
            ),
            Err(Refused::Unaligned)
        ));
        assert!(
            uring
                .push(
                    &mem,
                    3,
                    true,
                    8,
                    &header,
                    &[(GuestAddress(0x8000), 4096), (GuestAddress(0x9000), 1)],
                )
                .is_ok()
        );
        let done = uring.wait_idle(&mem);
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].0, 3);
    }

    #[test]
    fn address_at_crosses_buffers() {
        assert_eq!(address_at(&list(), 1040), Some(GuestAddress(0x3000)));
        assert_eq!(address_at(&list(), 1041), None);
    }
}
