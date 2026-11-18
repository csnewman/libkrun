use std::num::Wrapping;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, Shutdown, SockFlag, SockType, UnixAddr, accept, bind,
    connect, listen, recv, send, shutdown, socket,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::defs;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiConnectReq, VsockPacket};
use super::super::proxy::{
    NewProxyType, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
};
use utils::epoll::EventSet;

pub type PlatformHandle = OwnedFd;

pub(crate) fn create_socket(id: u64) -> Result<PlatformHandle, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;

    // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
    match fcntl(&fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("error switching to non-blocking: id={id}, err={e}");
                }
            }
            None => error!("invalid fd flags id={id}"),
        },
        Err(e) => error!("couldn't obtain fd flags id={id}, err={e}"),
    };

    #[cfg(target_os = "macos")]
    {
        // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
        let option_value: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &option_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&option_value) as libc::socklen_t,
            )
        };
    }

    Ok(fd)
}

/// Marks the connection connected. Its socket is left non-blocking: the
/// guest's data is written from the device's event loop, which must not
/// wait for the host to read.
pub(crate) fn switch_to_connected(proxy: &mut super::UnixProxy) {
    proxy.status = ProxyStatus::Connected;
    match fcntl(&proxy.fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&proxy.fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!(
                        "error switching to non-blocking: id={}, err={}",
                        proxy.id, e
                    );
                }
            }
            None => error!("invalid fd flags id={}", proxy.id),
        },
        Err(e) => error!("couldn't obtain fd flags id={}, err={}", proxy.id, e),
    };
}

fn push_connect_rsp(proxy: &super::UnixProxy, result: i32) {
    debug!(
        "push_connect_rsp: id: {}, control_port: {}, result: {}",
        proxy.id, proxy.control_port, result
    );

    // This response goes to the control port (DGRAM).
    let rx = MuxerRx::ConnResponse {
        local_port: 1025,
        peer_port: proxy.control_port,
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn recv_to_pkt(proxy: &super::UnixProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        debug!(
            "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
            proxy.peer_avail_credit(),
            buf.len(),
            max_len
        );

        if max_len == 0 {
            return RecvPkt::WaitForCredit;
        }

        match recv(
            proxy.fd.as_raw_fd(),
            &mut buf[..max_len],
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(cnt) => {
                debug!("recv cnt={cnt}");
                if cnt > 0 {
                    debug!("recv rx_cnt={}", proxy.rx_cnt);
                    RecvPkt::Read(cnt)
                } else {
                    RecvPkt::Close
                }
            }
            Err(e) => {
                debug!("recv_pkt: recv error: {e:?}");
                match e {
                    Errno::EAGAIN | Errno::EINTR => RecvPkt::Error,
                    _ => RecvPkt::Close,
                }
            }
        }
    } else {
        debug!("recv_pkt: pkt without buf");
        RecvPkt::Error
    }
}

pub(crate) fn do_connect(
    proxy: &mut super::UnixProxy,
    _pkt: &VsockPacket,
    _req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let addr = UnixAddr::new(&proxy.path).unwrap();

    let result = match connect(proxy.fd.as_raw_fd(), &addr) {
        Ok(()) => {
            debug!("connect: Connected");
            switch_to_connected(proxy);
            0
        }
        Err(nix::errno::Errno::EINPROGRESS) => {
            debug!("connect: Connecting");
            proxy.status = ProxyStatus::Connecting;
            0
        }
        Err(e) => {
            debug!("Error connecting: {e}");
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(Errno::last_raw());
            #[cfg(target_os = "linux")]
            let errno = -Errno::last_raw();
            errno
        }
    };

    if proxy.status == ProxyStatus::Connecting {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN | EventSet::OUT));
    } else {
        if proxy.status == ProxyStatus::Connected {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        }
        push_connect_rsp(proxy, result);
    }
    update
}

pub(crate) fn confirm_connect(
    proxy: &mut super::UnixProxy,
    pkt: &VsockPacket,
) -> Option<ProxyUpdate> {
    debug!(
        "confirm_connect: local_port={} peer_port={}, src_port={}, dst_port={}",
        pkt.dst_port(),
        pkt.src_port(),
        proxy.local_port,
        proxy.peer_port,
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    proxy.local_port = pkt.dst_port();
    proxy.peer_port = pkt.src_port();

    // This response goes to the connection.
    let rx = MuxerRx::OpResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    None
}

const SHUTDOWN_BOTH: u32 =
    super::uapi::VSOCK_FLAGS_SHUTDOWN_RCV | super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND;

#[cfg(target_os = "macos")]
const SEND_FLAGS: MsgFlags = MsgFlags::empty();
#[cfg(target_os = "linux")]
const SEND_FLAGS: MsgFlags = MsgFlags::MSG_NOSIGNAL;

/// The socket events the connection waits for: the host's data while the
/// guest takes it, and room while the guest's waits to be written.
fn interest(proxy: &super::UnixProxy) -> EventSet {
    let mut events = EventSet::empty();
    if proxy.status == ProxyStatus::Connected && proxy.peer_shutdown != SHUTDOWN_BOTH {
        events |= EventSet::IN;
    }
    if !proxy.unsent.is_empty() {
        events |= EventSet::OUT;
    }
    events
}

/// Writes what the host socket takes of the unsent data.
fn flush(proxy: &mut super::UnixProxy) -> nix::Result<()> {
    while !proxy.unsent.is_empty() {
        let (front, _) = proxy.unsent.as_slices();
        match send(proxy.fd.as_raw_fd(), front, SEND_FLAGS) {
            Ok(sent) => {
                proxy.unsent.drain(..sent);
                proxy.tx_cnt += Wrapping(sent as u32);
            }
            Err(Errno::EAGAIN) => return Ok(()),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Tells the guest how much the host has taken, once enough has been to
/// be worth telling. The guest's credit counts only what was written to
/// the host socket, so the unsent data stays within the buffer the guest
/// was given.
fn update_credit(proxy: &mut super::UnixProxy) -> bool {
    let taken = (proxy.tx_cnt - proxy.last_tx_cnt_sent).0;
    if taken == 0 || taken < proxy.peer_buf_alloc / 2 {
        return false;
    }
    debug!(
        "sending credit update: id={}, tx_cnt={}, last_tx_cnt={}",
        proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
    );
    proxy.last_tx_cnt_sent = proxy.tx_cnt;
    let rx = MuxerRx::CreditUpdate {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
        fwd_cnt: proxy.tx_cnt.0,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    true
}

pub(crate) fn sendmsg(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();
    let Some(buf) = pkt.buf() else {
        return update;
    };

    if proxy.unsent.len() + buf.len() > defs::CONN_TX_BUF_SIZE {
        warn!("guest sent beyond its credit, resetting: id={}", proxy.id);
        proxy.unsent.clear();
        proxy.push_reset();
        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        return update;
    }

    if proxy.unsent.is_empty() {
        match send(proxy.fd.as_raw_fd(), buf, SEND_FLAGS) {
            Ok(sent) => {
                proxy.tx_cnt += Wrapping(sent as u32);
                proxy.unsent.extend(&buf[sent..]);
            }
            Err(Errno::EAGAIN | Errno::EINTR) => proxy.unsent.extend(buf),
            // The host has gone: its hang-up closes the connection.
            Err(e) => debug!("sendmsg: id={}, err={}", proxy.id, e),
        }
        if !proxy.unsent.is_empty() {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy)));
        }
    } else {
        proxy.unsent.extend(buf);
    }

    update.signal_queue = update_credit(proxy);
    update
}

/// Writes the unsent data as the host socket takes it. Once it is all
/// written, a shutdown the guest asked for meanwhile goes through.
fn send_unsent(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    if let Err(e) = flush(proxy) {
        debug!("send_unsent: id={}, err={}", proxy.id, e);
        proxy.unsent.clear();
    }
    let credited = update_credit(proxy);
    if !proxy.unsent.is_empty() {
        return ProxyUpdate {
            signal_queue: credited,
            ..Default::default()
        };
    }

    if proxy.peer_shutdown & super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0
        && let Err(e) = shutdown(proxy.fd.as_raw_fd(), Shutdown::Write)
    {
        warn!("error sending shutdown to socket: {e}");
    }
    if proxy.peer_shutdown == SHUTDOWN_BOTH {
        return proxy.close();
    }
    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy))),
        signal_queue: credited,
        ..Default::default()
    }
}

pub(crate) fn update_peer_credit(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    debug!(
        "update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
        pkt.buf_alloc(),
        proxy.rx_cnt,
        pkt.fwd_cnt()
    );
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    if proxy.status != ProxyStatus::WaitingCreditUpdate || proxy.peer_avail_credit() == 0 {
        return ProxyUpdate::default();
    }

    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy))),
        ..Default::default()
    }
}

pub(crate) fn push_op_request(proxy: &super::UnixProxy) {
    debug!(
        "push_op_request: id={}, local_port={} peer_port={}",
        proxy.id, proxy.local_port, proxy.peer_port
    );

    // This packet goes to the connection.
    let rx = MuxerRx::OpRequest {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn process_op_response(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    debug!(
        "process_op_response: id={} src_port={} dst_port={}",
        proxy.id,
        pkt.src_port(),
        pkt.dst_port()
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    switch_to_connected(proxy);

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy))),
        ..Default::default()
    }
}

pub(crate) fn do_shutdown(proxy: &mut super::UnixProxy, pkt: &VsockPacket) {
    let recv_off = pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
    // Data the host has not taken yet goes before the end of the stream,
    // which send_unsent writes once it has.
    let send_off =
        pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0 && proxy.unsent.is_empty();

    let how = match (recv_off, send_off) {
        (true, true) => Shutdown::Both,
        (true, false) => Shutdown::Read,
        (false, true) => Shutdown::Write,
        (false, false) => return,
    };

    if let Err(e) = shutdown(proxy.fd.as_raw_fd(), how) {
        warn!("error sending shutdown to socket: {e}");
    }
}

pub(crate) fn release(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    debug!(
        "release: id={}, tx_cnt={}, last_tx_cnt={}",
        proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
    );

    // A connection that never reached Connected carries no data and is not
    // registered for polling yet, so there is nothing to reserve its id for.
    // Keeping it would leave the accepted host socket open, and its peer
    // blocked, until the reaper reclaims the proxy.
    let remove_proxy = match proxy.status {
        ProxyStatus::ReverseInit | ProxyStatus::Connecting => ProxyRemoval::Immediate,
        _ => ProxyRemoval::Deferred,
    };

    ProxyUpdate {
        remove_proxy,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::UnixProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    // A hung-up stream can still contain data, including more than the guest
    // currently has buffers or credit for. Only recv() can establish EOF.
    if evset.contains(EventSet::HANG_UP)
        && !matches!(
            proxy.status,
            ProxyStatus::Connected | ProxyStatus::WaitingCreditUpdate
        )
    {
        debug!("process_event: HANG_UP");

        if proxy.status == ProxyStatus::Connecting {
            push_connect_rsp(proxy, -libc::ECONNREFUSED);
        } else {
            proxy.push_reset();
        }

        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;

        return update;
    }

    if !proxy.unsent.is_empty() && evset.intersects(EventSet::OUT | EventSet::HANG_UP) {
        debug!("process_event: OUT with unsent data");
        return send_unsent(proxy);
    }

    if evset.intersects(EventSet::IN | EventSet::HANG_UP) {
        debug!("process_event: IN");
        if proxy.status == ProxyStatus::Connected {
            let (signal_queue, wait_credit) = proxy.recv_pkt();
            update.signal_queue = signal_queue;

            if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
                proxy.status = ProxyStatus::WaitingCreditUpdate;
                let rx = MuxerRx::CreditRequest {
                    local_port: proxy.local_port,
                    peer_port: proxy.peer_port,
                    fwd_cnt: proxy.tx_cnt.0,
                };
                update.push_credit_req = Some(rx);
            }

            if proxy.status == ProxyStatus::Closed {
                debug!(
                    "process_event: endpoint closed, sending reset: id={}",
                    proxy.id
                );

                proxy.push_reset();
                update.signal_queue = true;
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
                update.remove_proxy = ProxyRemoval::Deferred;
                return update;
            } else if proxy.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: WaitingCreditUpdate");
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy)));
            }
        } else {
            debug!("EventSet::IN while not connected: {:?}", proxy.status);
        }
    }

    if evset.contains(EventSet::OUT) {
        debug!("process_event: OUT");
        if proxy.status == ProxyStatus::Connecting {
            switch_to_connected(proxy);
            push_connect_rsp(proxy, 0);
            update.signal_queue = true;
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy)));
        } else if proxy.unsent.is_empty() {
            debug!("process_event: OUT with nothing unsent");
        }
    }

    update
}

pub(crate) fn as_raw_fd(proxy: &super::UnixProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}

pub(crate) fn new_acceptor_proxy(
    id: u64,
    path: &Path,
    peer_port: u32,
) -> Result<super::UnixAcceptorProxy, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    bind(
        fd.as_raw_fd(),
        &UnixAddr::new(path)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    // The muxer accepts one connection per event, so a burst of clients
    // waits in the backlog; any that overflow it are refused outright.
    listen(&fd, Backlog::MAXCONN)
        .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(super::UnixAcceptorProxy { id, fd, peer_port })
}

pub(crate) fn process_acceptor_event(
    proxy: &mut super::UnixAcceptorProxy,
    evset: EventSet,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        debug!("process_event: HANG_UP");
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        return update;
    }
    if evset.contains(EventSet::IN) {
        match accept(proxy.fd.as_raw_fd()) {
            Ok(accept_fd) => {
                // Safe because we've just obtained the FD from the `accept` call above.
                let new_fd = unsafe { OwnedFd::from_raw_fd(accept_fd) };
                update.new_proxy = Some((
                    proxy.peer_port,
                    new_fd,
                    AddressFamily::Unix,
                    NewProxyType::Unix,
                ));
            }
            Err(e) => warn!("error accepting connection: id={}, err={}", proxy.id, e),
        };
        update.signal_queue = true;
    }
    update
}

pub(crate) fn as_raw_acceptor_fd(proxy: &super::UnixAcceptorProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::super::super::defs::uapi;
    use super::super::super::muxer_rxq::MuxerRxQ;
    use super::super::UnixProxy;
    use super::*;
    use crate::virtio::Queue;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::proxy::Proxy;

    const PACKET_ADDR: u64 = 0x10000;
    const HDR_SIZE: usize = 44;
    const CHUNK: usize = 32 << 10;
    const GUEST_BUF_ALLOC: u32 = 256 << 10;

    /// The guest's end of a connection the host opened, connected, and the
    /// host's end of the socket it is carried on.
    struct Conn<'a> {
        mem: &'a GuestMemoryMmap,
        guest_tx: VirtQueue<'a>,
        tx: Queue,
        posted: u16,
        proxy: UnixProxy,
        host: UnixStream,
    }

    impl<'a> Conn<'a> {
        fn new(mem: &'a GuestMemoryMmap) -> Self {
            let guest_tx = VirtQueue::new(GuestAddress(0), mem, 16);
            let guest_rx = VirtQueue::new(GuestAddress(0x2000), mem, 16);
            let tx = guest_tx.create_queue();
            let (host, ours) = UnixStream::pair().unwrap();
            let proxy = UnixProxy::new_reverse(
                1,
                3,
                1024,
                2000,
                OwnedFd::from(ours),
                mem.clone(),
                Arc::new(Mutex::new(guest_rx.create_queue())),
                Arc::new(Mutex::new(MuxerRxQ::new())),
            );
            let mut c = Conn {
                mem,
                guest_tx,
                tx,
                posted: 0,
                proxy,
                host,
            };
            let rsp = c.packet(uapi::VSOCK_OP_RESPONSE, 0, &[]);
            c.proxy.process_op_response(&rsp);
            assert_eq!(c.proxy.status, ProxyStatus::Connected);
            c
        }

        /// A packet the guest sends, as the device takes it off its TX
        /// queue.
        fn packet(&mut self, op: u16, flags: u32, data: &[u8]) -> VsockPacket {
            let mut hdr = [0u8; HDR_SIZE];
            hdr[0..8].copy_from_slice(&3u64.to_le_bytes());
            hdr[8..16].copy_from_slice(&2u64.to_le_bytes());
            hdr[16..20].copy_from_slice(&2000u32.to_le_bytes());
            hdr[20..24].copy_from_slice(&1024u32.to_le_bytes());
            hdr[24..28].copy_from_slice(&(data.len() as u32).to_le_bytes());
            hdr[28..30].copy_from_slice(&uapi::VSOCK_TYPE_STREAM.to_le_bytes());
            hdr[30..32].copy_from_slice(&op.to_le_bytes());
            hdr[32..36].copy_from_slice(&flags.to_le_bytes());
            hdr[36..40].copy_from_slice(&GUEST_BUF_ALLOC.to_le_bytes());
            self.mem
                .write_slice(&hdr, GuestAddress(PACKET_ADDR))
                .unwrap();
            self.mem
                .write_slice(data, GuestAddress(PACKET_ADDR + HDR_SIZE as u64))
                .unwrap();
            self.guest_tx.dtable[0].set(PACKET_ADDR, (HDR_SIZE + data.len()) as u32, 0, 0);
            let size = self.guest_tx.size();
            self.guest_tx.avail.ring[(self.posted % size) as usize].set(0);
            self.posted = self.posted.wrapping_add(1);
            self.guest_tx.avail.idx.set(self.posted);
            let head = self.tx.pop(self.mem).unwrap();
            VsockPacket::from_tx_virtq_head(&head).unwrap()
        }

        /// Sends data from the guest, saying whether the proxy asked to be
        /// told when the host socket has room.
        fn send(&mut self, data: &[u8]) -> bool {
            let mut waits = false;
            for chunk in data.chunks(CHUNK) {
                let pkt = self.packet(uapi::VSOCK_OP_RW, 0, chunk);
                let update = self.proxy.sendmsg(&pkt);
                if let Some((_, _, events)) = update.polling {
                    waits |= events.contains(EventSet::OUT);
                }
            }
            waits
        }

        /// The credit updates and resets the proxy has queued for the guest.
        fn to_guest(&self) -> (Vec<u32>, usize) {
            let (mut credits, mut resets) = (Vec::new(), 0);
            while let Some(rx) = self.proxy.rxq.lock().unwrap().pop() {
                match rx {
                    MuxerRx::CreditUpdate { fwd_cnt, .. } => credits.push(fwd_cnt),
                    MuxerRx::Reset { .. } => resets += 1,
                    _ => {}
                }
            }
            (credits, resets)
        }

        /// Reads the host's end on a thread of its own until it ends.
        fn read_host(&self) -> thread::JoinHandle<Vec<u8>> {
            let mut host = self.host.try_clone().unwrap();
            thread::spawn(move || {
                let mut got = Vec::new();
                host.read_to_end(&mut got).unwrap();
                got
            })
        }

        /// Hands the proxy the socket's write readiness until done says so.
        fn drain(&mut self, done: impl Fn(&UnixProxy) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !done(&self.proxy) {
                assert!(Instant::now() < deadline, "the unsent data was not written");
                let mut fds = [PollFd::new(self.proxy.fd.as_fd(), PollFlags::POLLOUT)];
                poll(&mut fds, PollTimeout::from(100u16)).unwrap();
                self.proxy.process_event(EventSet::OUT);
            }
        }
    }

    fn same(got: Vec<u8>, want: &[u8]) {
        assert!(
            got == want,
            "the host got {} bytes of {}",
            got.len(),
            want.len()
        );
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Runs f on a thread of its own, failing if it does not finish.
    fn within(f: impl FnOnce() + Send + 'static) {
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            f();
            done.send(()).unwrap();
        });
        finished
            .recv_timeout(Duration::from_secs(30))
            .expect("the test did not finish: a send blocked on the host socket");
    }

    #[test]
    fn a_host_that_reads_slowly_does_not_block_the_guests_sends() {
        within(|| {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
            let mut c = Conn::new(&mem);
            let data = pattern(4 << 20);

            assert!(c.send(&data), "the proxy never waited for room");
            let written = c.proxy.tx_cnt.0;
            assert!((written as usize) < data.len());
            let (credits, _) = c.to_guest();
            assert!(
                credits.iter().all(|&fwd| fwd <= written),
                "{credits:?} > {written}"
            );

            let reader = c.read_host();
            c.drain(|p| p.unsent.is_empty());
            shutdown(c.proxy.fd.as_raw_fd(), Shutdown::Write).unwrap();
            same(reader.join().unwrap(), &data);
            assert_eq!(c.proxy.tx_cnt.0 as usize, data.len());
            let (credits, _) = c.to_guest();
            let last = *credits.last().expect("a credit update");
            assert!(data.len() as u32 - last < GUEST_BUF_ALLOC / 2);
        });
    }

    #[test]
    fn a_guest_that_closes_has_its_unsent_data_written_first() {
        within(|| {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
            let mut c = Conn::new(&mem);
            let data = pattern(1 << 20);

            assert!(c.send(&data));
            let close = c.packet(uapi::VSOCK_OP_SHUTDOWN, SHUTDOWN_BOTH, &[]);
            c.proxy.shutdown(&close);
            assert_eq!(c.proxy.status, ProxyStatus::Connected);
            assert_eq!(c.to_guest().1, 0, "reset before the data was written");

            let reader = c.read_host();
            c.drain(|p| p.status == ProxyStatus::Closed);
            same(reader.join().unwrap(), &data);
            assert_eq!(c.to_guest().1, 1);
        });
    }

    #[test]
    fn a_guest_that_stops_sending_ends_the_stream_after_its_unsent_data() {
        within(|| {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
            let mut c = Conn::new(&mem);
            let data = pattern(1 << 20);

            assert!(c.send(&data));
            let half = c.packet(
                uapi::VSOCK_OP_SHUTDOWN,
                uapi::VSOCK_FLAGS_SHUTDOWN_SEND,
                &[],
            );
            c.proxy.shutdown(&half);

            let reader = c.read_host();
            c.drain(|p| p.unsent.is_empty());
            same(reader.join().unwrap(), &data);
            assert_eq!(c.proxy.status, ProxyStatus::Connected);
        });
    }

    fn socket_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("libkrun-vsock-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("sock")
    }

    #[test]
    fn acceptor_holds_a_burst_of_connections() {
        let path = socket_path("burst");
        let _acceptor = new_acceptor_proxy(1, &path, 1024).unwrap();
        let addr = UnixAddr::new(&path).unwrap();

        let refused: Vec<Errno> = (0..64)
            .map(|i| create_socket(i).unwrap())
            .filter_map(|fd| connect(fd.as_raw_fd(), &addr).err())
            .collect();

        assert!(refused.is_empty(), "refused: {refused:?}");
    }
}
