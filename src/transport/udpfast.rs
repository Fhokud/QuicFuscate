use std::net::UdpSocket;

use crate::optimize::{prefetch, PrefetchHint};
// Maximum sophisticated UDP fast path
// Batching, vectored I/O, GSO/GRO, prefetch, branch hints, zero-copy

use std::io;
#[cfg(target_os = "linux")]
use std::mem;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

// Linux-specific imports
#[cfg(target_os = "linux")]
use libc::{
    c_void, cmsghdr, iovec, mmsghdr, msghdr, recvmmsg, sendmmsg, sockaddr_storage, timespec,
    CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE, MSG_DONTWAIT, MSG_ERRQUEUE,
    MSG_ZEROCOPY, SOL_UDP, UDP_GRO, UDP_SEGMENT,
};

#[cfg(target_os = "macos")]
extern "C" {
    fn sendmsg_x(
        s: libc::c_int,
        msgp: *const libc::msghdr,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::c_int;
}

// Telemetry
pub static BATCHED_SENDS: AtomicU64 = AtomicU64::new(0);
pub static BATCHED_RECVS: AtomicU64 = AtomicU64::new(0);
pub static GSO_SEGMENTS: AtomicU64 = AtomicU64::new(0);
pub static GRO_COALESCED: AtomicU64 = AtomicU64::new(0);
pub static VECTORED_OPS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
pub static ZC_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
pub static ZC_COMPLETED_BYTES: AtomicU64 = AtomicU64::new(0);

// Maximum batch sizes
pub const MAX_BATCH_SIZE: usize = 64;
pub const MAX_GSO_SEGMENTS: usize = 64;
pub const MAX_VECTORED_IO: usize = 1024;

// Cache line size for alignment
const CACHE_LINE_SIZE: usize = 64;

// Prefetch hints
#[cfg_attr(feature = "aggressive_inline", inline(always))]
fn prefetch_read(ptr: *const u8) {
    unsafe { prefetch(ptr, PrefetchHint::T0) };
}

#[cfg_attr(feature = "aggressive_inline", inline(always))]
fn prefetch_write(ptr: *mut u8) {
    unsafe { prefetch(ptr as *const u8, PrefetchHint::T0) };
}

// Branch prediction hints
#[inline(always)]
#[cold]
fn cold_path() {}

#[inline(always)]
pub(crate) fn likely(b: bool) -> bool {
    if !b {
        cold_path();
    }
    b
}

#[inline(always)]
pub(crate) fn unlikely(b: bool) -> bool {
    if b {
        cold_path();
    }
    b
}

// Aligned buffer for zero-copy
#[repr(align(64))]
pub struct AlignedBuffer {
    data: Vec<u8>,
}

impl AlignedBuffer {
    pub fn new(size: usize) -> Self {
        let aligned_size = (size + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);
        Self { data: vec![0u8; aligned_size] }
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

pub struct UdpFastPath {
    socket: UdpSocket,
    #[cfg(target_os = "linux")]
    fd: RawFd,
    gso_enabled: bool,
    gro_enabled: bool,
    zerocopy_enabled: bool,
    #[cfg(target_os = "linux")]
    sendmmsg_available: bool,
    #[cfg(target_os = "linux")]
    recvmmsg_available: bool,

    // Buffers for batching
    send_batch: Vec<AlignedBuffer>,
    recv_batch: Vec<AlignedBuffer>,

    // Statistics
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}

impl UdpFastPath {
    pub fn new(bind: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        let fd = socket.as_raw_fd();

        let mut fast_path = Self {
            socket,
            #[cfg(target_os = "linux")]
            fd,
            gso_enabled: false,
            gro_enabled: false,
            zerocopy_enabled: false,
            #[cfg(target_os = "linux")]
            sendmmsg_available: cfg!(target_os = "linux"),
            #[cfg(target_os = "linux")]
            recvmmsg_available: cfg!(target_os = "linux"),
            send_batch: Vec::with_capacity(MAX_BATCH_SIZE),
            recv_batch: Vec::with_capacity(MAX_BATCH_SIZE),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        };

        // Pre-allocate aligned buffers
        for _ in 0..MAX_BATCH_SIZE {
            fast_path.send_batch.push(AlignedBuffer::new(65536));
            fast_path.recv_batch.push(AlignedBuffer::new(65536));
        }

        // Enable features as supported on this platform
        fast_path.enable_gso();
        fast_path.enable_gro();
        fast_path.enable_zerocopy();

        Ok(fast_path)
    }

    #[cfg(target_os = "linux")]
    fn enable_gso(&mut self) {
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                self.fd,
                SOL_UDP,
                UDP_SEGMENT,
                &val as *const _ as *const c_void,
                mem::size_of_val(&val) as libc::socklen_t,
            );
            self.gso_enabled = ret == 0;
            if self.gso_enabled {
                log::info!("UDP GSO enabled");
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn enable_gro(&mut self) {
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                self.fd,
                SOL_UDP,
                UDP_GRO,
                &val as *const _ as *const c_void,
                mem::size_of_val(&val) as libc::socklen_t,
            );
            self.gro_enabled = ret == 0;
            if self.gro_enabled {
                log::info!("UDP GRO enabled");
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn enable_zerocopy(&mut self) {
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_ZEROCOPY,
                &val as *const _ as *const c_void,
                mem::size_of_val(&val) as libc::socklen_t,
            );
            self.zerocopy_enabled = ret == 0;
            if self.zerocopy_enabled {
                log::info!("MSG_ZEROCOPY enabled");
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn enable_gso(&mut self) {
        // Not available on non-Linux, but track intent
        self.gso_enabled = false;
    }

    fn enable_gro(&mut self) {
        #[cfg(target_os = "linux")]
        {
            // Try to enable GRO via socket option
            unsafe {
                let val: libc::c_int = 1;
                libc::setsockopt(
                    self.fd,
                    libc::SOL_UDP,
                    104, // UDP_GRO
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
            }
            self.gro_enabled = true;
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.gro_enabled = false;
        }
    }

    fn enable_zerocopy(&mut self) {
        #[cfg(target_os = "linux")]
        {
            // Try MSG_ZEROCOPY
            unsafe {
                let val: libc::c_int = 1;
                let ret = libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_ZEROCOPY,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
                self.zerocopy_enabled = ret == 0;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.zerocopy_enabled = false;
        }
    }

    // Sophisticated batched send - cross-platform optimized
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        if unlikely(packets.is_empty()) {
            return Ok(0);
        }

        crate::optimize::telemetry::ZEROCOPY_SEND_CALLS.fetch_add(1, Ordering::Relaxed);

        // Fast path for single packet
        if packets.len() == 1 {
            return self.send_single(packets[0].0, packets[0].1);
        }

        unsafe {
            let mut msgs: Vec<mmsghdr> = Vec::with_capacity(packets.len());
            let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
            let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(packets.len());

            let sock_addr = socket2::SockAddr::from(packets[0].1);

            for (i, packet) in packets.iter().enumerate() {
                // Prefetch next packet
                if i + 1 < packets.len() {
                    prefetch_read(packet.0.as_ptr());
                }

                // Setup iovec
                iovecs.push(iovec {
                    iov_base: packet.0.as_ptr() as *mut c_void,
                    iov_len: packet.0.len(),
                });

                // Setup address
                let mut addr_storage: sockaddr_storage = mem::zeroed();
                ptr::copy_nonoverlapping(
                    sock_addr.as_ptr() as *const u8,
                    &mut addr_storage as *mut _ as *mut u8,
                    sock_addr.len() as usize,
                );
                addrs.push(addr_storage);

                // Setup message header
                let mut msg: mmsghdr = mem::zeroed();
                msg.msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut c_void;
                msg.msg_hdr.msg_namelen = sock_addr.len();
                msg.msg_hdr.msg_iov = &mut iovecs[i];
                msg.msg_hdr.msg_iovlen = 1;

                msgs.push(msg);
            }

            // Send all messages
            let flags =
                if self.zerocopy_enabled { MSG_DONTWAIT | MSG_ZEROCOPY } else { MSG_DONTWAIT };

            let sent = sendmmsg(self.fd, msgs.as_mut_ptr(), packets.len() as u32, flags as i32);

            if sent < 0 {
                crate::optimize::telemetry::ZEROCOPY_SEND_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::last_os_error());
            }

            let sent_count = sent as usize;
            let mut total_bytes = 0;
            for i in 0..sent_count {
                total_bytes += msgs[i].msg_len as usize;
            }

            BATCHED_SENDS.fetch_add(1, Ordering::Relaxed);
            self.packets_sent.fetch_add(sent_count as u64, Ordering::Relaxed);
            self.bytes_sent.fetch_add(total_bytes as u64, Ordering::Relaxed);

            // Drain zerocopy completion inbox (best-effort, non-blocking)
            #[cfg(target_os = "linux")]
            {
                for ev in crate::transport::uring::try_drain_zerocopy_events(64) {
                    ZC_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                    ZC_COMPLETED_BYTES.fetch_add(ev.bytes as u64, Ordering::Relaxed);
                    crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                        .fetch_add(1, Ordering::Relaxed);
                    crate::optimize::telemetry::ZC_COMPLETED_BYTES_TOTAL
                        .fetch_add(ev.bytes as u64, Ordering::Relaxed);
                }
                // Additionally, drain kernel MSG_ERRQUEUE for zerocopy notifications
                let drained = unsafe { try_drain_zerocopy_errqueue(self.fd, 8) };
                if drained > 0 {
                    ZC_COMPLETIONS.fetch_add(drained as u64, Ordering::Relaxed);
                    crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                        .fetch_add(drained as u64, Ordering::Relaxed);
                }
            }

            Ok(sent_count)
        }
    }

    // Fallback for non-Linux
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        // macOS/iOS: Use sendmsg_x when available, fall back to sendmsg.
        use libc::{iovec, msghdr, sendmsg, sockaddr_storage, MSG_DONTWAIT};
        use std::os::unix::io::AsRawFd;
        let fd = self.socket.as_raw_fd();

        if unlikely(packets.is_empty()) {
            return Ok(0);
        }
        if packets.len() == 1 {
            return self.send_single(packets[0].0, packets[0].1);
        }

        let mut msgs: Vec<msghdr> = Vec::with_capacity(packets.len());
        let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
        let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(packets.len());
        let mut addr_lens: Vec<libc::socklen_t> = Vec::with_capacity(packets.len());

        for (data, addr) in packets.iter() {
            let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
            let len = match addr {
                SocketAddr::V4(v4) => {
                    #[cfg(target_os = "macos")]
                    let raw = libc::sockaddr_in {
                        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: v4.port().to_be(),
                        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                        sin_zero: [0; 8],
                    };
                    #[cfg(not(target_os = "macos"))]
                    let raw = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: v4.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(v4.ip().octets()).to_be(),
                        },
                        sin_zero: [0; 8],
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &raw as *const _ as *const u8,
                            &mut storage as *mut _ as *mut u8,
                            std::mem::size_of_val(&raw),
                        );
                    }
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                }
                SocketAddr::V6(v6) => {
                    #[cfg(target_os = "macos")]
                    let raw = libc::sockaddr_in6 {
                        sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: v6.port().to_be(),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                        sin6_scope_id: v6.scope_id(),
                    };
                    #[cfg(not(target_os = "macos"))]
                    let raw = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: v6.port().to_be(),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                        sin6_scope_id: v6.scope_id(),
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &raw as *const _ as *const u8,
                            &mut storage as *mut _ as *mut u8,
                            std::mem::size_of_val(&raw),
                        );
                    }
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                }
            };

            addrs.push(storage);
            addr_lens.push(len);
            iovecs.push(iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() });
        }

        for i in 0..packets.len() {
            msgs.push(msghdr {
                msg_name: &mut addrs[i] as *mut _ as *mut _,
                msg_namelen: addr_lens[i],
                msg_iov: &mut iovecs[i],
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            });
        }

        let flags = MSG_DONTWAIT;
        let mut sent = 0usize;

        #[cfg(target_os = "macos")]
        {
            crate::optimize::telemetry::ZEROCOPY_SEND_CALLS.fetch_add(1, Ordering::Relaxed);
            let ret = unsafe { sendmsg_x(fd, msgs.as_ptr(), msgs.len() as u32, flags) };
            if ret >= 0 {
                sent = ret as usize;
            } else {
                let err = io::Error::last_os_error();
                if matches!(
                    err.raw_os_error(),
                    Some(libc::ENOSYS)
                        | Some(libc::EOPNOTSUPP)
                        | Some(libc::ENOTSUP)
                        | Some(libc::EINVAL)
                        | Some(libc::EADDRNOTAVAIL)
                ) {
                    crate::optimize::telemetry::ZEROCOPY_SEND_FALLBACKS
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    return Err(err);
                }
            }
        }

        let mut total_bytes = 0usize;
        if sent > 0 {
            total_bytes += packets.iter().take(sent).map(|(data, _)| data.len()).sum::<usize>();
        }

        for (_packet, msg) in packets.iter().zip(msgs.iter()).skip(sent) {
            let n = unsafe { sendmsg(fd, msg, flags) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            sent += 1;
            total_bytes += n as usize;
        }

        BATCHED_SENDS.fetch_add(1, Ordering::Relaxed);
        self.packets_sent.fetch_add(sent as u64, Ordering::Relaxed);
        self.bytes_sent.fetch_add(total_bytes as u64, Ordering::Relaxed);

        Ok(sent)
    }

    #[cfg(target_os = "windows")]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        // Windows: Use WSASend with WSABUF arrays for vectorized I/O
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            WSASend, SOCKET, WSABUF, WSAOVERLAPPED, WSA_IO_PENDING,
        };

        let socket = self.socket.as_raw_socket() as SOCKET;
        let mut total_sent = 0;

        for (data, _addr) in packets {
            let mut wsabuf = WSABUF { len: data.len() as u32, buf: data.as_ptr() as *mut u8 };

            let mut bytes_sent = 0u32;
            let result = unsafe {
                WSASend(
                    socket,
                    &mut wsabuf,
                    1,
                    &mut bytes_sent,
                    0,
                    std::ptr::null_mut::<WSAOVERLAPPED>(),
                    None,
                )
            };

            if result == 0
                || unsafe { windows_sys::Win32::Foundation::GetLastError() } == WSA_IO_PENDING
            {
                total_sent += 1;
            }
        }
        Ok(total_sent)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )))]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        let mut sent = 0;
        for packet in packets {
            self.send_single(packet.0, packet.1)?;
            sent += 1;
        }
        Ok(sent)
    }

    // Single packet send with GSO support
    pub fn send_single(&mut self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // Prefetch data
        prefetch_read(data.as_ptr());

        #[cfg(target_os = "linux")]
        {
            if self.gso_enabled && data.len() > 1400 {
                return self.send_gso(data, addr, 1400);
            }
        }

        let sent = self.socket.send_to(data, addr)?;
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);
        // Drain zerocopy completion inbox opportunistically on Linux
        #[cfg(target_os = "linux")]
        {
            for ev in crate::transport::uring::try_drain_zerocopy_events(16) {
                ZC_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                ZC_COMPLETED_BYTES.fetch_add(ev.bytes as u64, Ordering::Relaxed);
                crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
                crate::optimize::telemetry::ZC_COMPLETED_BYTES_TOTAL
                    .fetch_add(ev.bytes as u64, Ordering::Relaxed);
            }
            let drained = unsafe { try_drain_zerocopy_errqueue(self.fd, 4) };
            if drained > 0 {
                ZC_COMPLETIONS.fetch_add(drained as u64, Ordering::Relaxed);
                crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                    .fetch_add(drained as u64, Ordering::Relaxed);
            }
        }
        Ok(sent)
    }

    #[cfg(target_os = "linux")]
    fn send_gso(
        &mut self,
        data: &[u8],
        addr: SocketAddr,
        segment_size: usize,
    ) -> io::Result<usize> {
        unsafe {
            let sock_addr = socket2::SockAddr::from(addr);

            let iov = iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() };

            // Setup control message for GSO
            let mut cmsg_buf = [0u8; CMSG_SPACE(mem::size_of::<u16>() as u32) as usize];

            let mut msg: msghdr = mem::zeroed();
            msg.msg_name = sock_addr.as_ptr() as *mut c_void;
            msg.msg_namelen = sock_addr.len();
            msg.msg_iov = &iov as *const _ as *mut iovec;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_buf.len();

            let cmsg = CMSG_FIRSTHDR(&msg);
            if !cmsg.is_null() {
                (*cmsg).cmsg_level = SOL_UDP;
                (*cmsg).cmsg_type = UDP_SEGMENT;
                (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<u16>() as u32) as usize;

                let segment_size_ptr = CMSG_DATA(cmsg) as *mut u16;
                *segment_size_ptr = segment_size as u16;
            }

            let flags =
                if self.zerocopy_enabled { MSG_DONTWAIT | MSG_ZEROCOPY } else { MSG_DONTWAIT };

            let sent = libc::sendmsg(self.fd, &msg, flags);

            if sent < 0 {
                return Err(io::Error::last_os_error());
            }

            let segments = (data.len() + segment_size - 1) / segment_size;
            GSO_SEGMENTS.fetch_add(segments as u64, Ordering::Relaxed);
            self.packets_sent.fetch_add(segments as u64, Ordering::Relaxed);
            self.bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);

            // Drain zerocopy completion inbox after GSO send
            for ev in crate::transport::uring::try_drain_zerocopy_events(64) {
                ZC_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                ZC_COMPLETED_BYTES.fetch_add(ev.bytes as u64, Ordering::Relaxed);
                crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
                crate::optimize::telemetry::ZC_COMPLETED_BYTES_TOTAL
                    .fetch_add(ev.bytes as u64, Ordering::Relaxed);
            }
            let drained = try_drain_zerocopy_errqueue(self.fd, 8);
            if drained > 0 {
                ZC_COMPLETIONS.fetch_add(drained as u64, Ordering::Relaxed);
                crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                    .fetch_add(drained as u64, Ordering::Relaxed);
            }

            Ok(sent as usize)
        }
    }

    // Sophisticated batched receive with recvmmsg on Linux
    #[cfg(target_os = "linux")]
    pub fn recv_batch(&mut self, max_packets: usize) -> io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        unsafe {
            let batch_size = max_packets.min(MAX_BATCH_SIZE);
            let mut msgs: Vec<mmsghdr> = Vec::with_capacity(batch_size);
            let mut iovecs: Vec<iovec> = Vec::with_capacity(batch_size);
            let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(batch_size);

            for i in 0..batch_size {
                let buf = &mut self.recv_batch[i];

                // Prefetch buffer
                prefetch_write(buf.as_mut_slice().as_mut_ptr());

                iovecs.push(iovec {
                    iov_base: buf.as_mut_slice().as_mut_ptr() as *mut c_void,
                    iov_len: buf.as_slice().len(),
                });

                addrs.push(mem::zeroed());

                let mut msg: mmsghdr = mem::zeroed();
                msg.msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut c_void;
                msg.msg_hdr.msg_namelen = mem::size_of::<sockaddr_storage>() as u32;
                msg.msg_hdr.msg_iov = &mut iovecs[i];
                msg.msg_hdr.msg_iovlen = 1;

                msgs.push(msg);
            }

            let timeout = timespec {
                tv_sec: 0,
                tv_nsec: 1000000, // 1ms timeout
            };

            let received = recvmmsg(
                self.fd,
                msgs.as_mut_ptr(),
                batch_size as u32,
                MSG_DONTWAIT,
                &timeout as *const _,
            );

            if received < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(Vec::new());
                }
                return Err(err);
            }

            let mut results = Vec::with_capacity(received as usize);
            for i in 0..received as usize {
                let len = msgs[i].msg_len as usize;
                let mut data = vec![0u8; len];
                data.copy_from_slice(&self.recv_batch[i].as_slice()[..len]);

                let addr = socket2::SockAddr::from_raw_parts(
                    &addrs[i] as *const _ as *const libc::sockaddr,
                    msgs[i].msg_hdr.msg_namelen,
                );

                results.push((data, addr.as_socket().unwrap()));
            }

            BATCHED_RECVS.fetch_add(1, Ordering::Relaxed);
            self.packets_received.fetch_add(received as u64, Ordering::Relaxed);

            // Also drain any pending zerocopy completions while we're on a recv path
            #[cfg(target_os = "linux")]
            {
                for ev in crate::transport::uring::try_drain_zerocopy_events(16) {
                    ZC_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                    ZC_COMPLETED_BYTES.fetch_add(ev.bytes as u64, Ordering::Relaxed);
                    crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                        .fetch_add(1, Ordering::Relaxed);
                    crate::optimize::telemetry::ZC_COMPLETED_BYTES_TOTAL
                        .fetch_add(ev.bytes as u64, Ordering::Relaxed);
                }
                let drained = try_drain_zerocopy_errqueue(self.fd, 4);
                if drained > 0 {
                    ZC_COMPLETIONS.fetch_add(drained as u64, Ordering::Relaxed);
                    crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                        .fetch_add(drained as u64, Ordering::Relaxed);
                }
            }

            Ok(results)
        }
    }

    // Fallback for non-Linux
    #[cfg(not(target_os = "linux"))]
    pub fn recv_batch(&mut self, max_packets: usize) -> io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        let mut results = Vec::with_capacity(max_packets);
        for _ in 0..max_packets {
            match self.recv_single() {
                Ok(Some((data, addr))) => results.push((data, addr)),
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(results)
    }

    // Single packet receive
    pub fn recv_single(&mut self) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        let buf = &mut self.recv_batch[0];
        prefetch_write(buf.as_mut_slice().as_mut_ptr());

        match self.socket.recv_from(buf.as_mut_slice()) {
            Ok((len, addr)) => {
                let data = buf.as_slice()[..len].to_vec();
                self.packets_received.fetch_add(1, Ordering::Relaxed);
                self.bytes_received.fetch_add(len as u64, Ordering::Relaxed);
                #[cfg(target_os = "linux")]
                {
                    for ev in crate::transport::uring::try_drain_zerocopy_events(8) {
                        ZC_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                        ZC_COMPLETED_BYTES.fetch_add(ev.bytes as u64, Ordering::Relaxed);
                        crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                            .fetch_add(1, Ordering::Relaxed);
                        crate::optimize::telemetry::ZC_COMPLETED_BYTES_TOTAL
                            .fetch_add(ev.bytes as u64, Ordering::Relaxed);
                    }
                    let drained = try_drain_zerocopy_errqueue(self.fd, 2);
                    if drained > 0 {
                        ZC_COMPLETIONS.fetch_add(drained as u64, Ordering::Relaxed);
                        crate::optimize::telemetry::ZC_COMPLETIONS_TOTAL
                            .fetch_add(drained as u64, Ordering::Relaxed);
                    }
                }
                Ok(Some((data, addr)))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(addr)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[cfg(target_os = "linux")]
#[inline(always)]
unsafe fn try_drain_zerocopy_errqueue(fd: RawFd, max: usize) -> usize {
    use libc::{iovec, msghdr, recvmsg, MSG_DONTWAIT, MSG_ERRQUEUE};
    let mut drained = 0usize;
    let mut dummy = [0u8; 1];
    let mut iov = iovec { iov_base: dummy.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut control = [0u8; 256];
    let mut msg: msghdr = core::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();
    for _ in 0..max {
        let ret = recvmsg(fd, &mut msg, MSG_ERRQUEUE | MSG_DONTWAIT);
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                break;
            } else {
                break;
            }
        } else {
            drained += 1;
        }
    }
    drained
}
