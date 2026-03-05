// Legacy compat, redirects to udpfast/uring (inline)
// Fast-path transport implementations
// UDP batching, io_uring, GSO/GRO optimizations

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
use super::uring::*;
#[cfg(target_os = "linux")]
use std::mem;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::ptr;
use std::sync::Arc;

use crate::optimize::{prefetch, PrefetchHint};

// UDP fast path re-export
#[cfg(feature = "uring_sys")]
pub use crate::transport::udpfast::*;

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
pub use super::uring::*;

// Legacy compatibility module (empty)
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use libc::c_void;

    const XDP_RING_SIZE: u32 = 2048;

    // Legacy XDP structures removed - using pure UDP/io_uring
    #[repr(C)]
    pub struct SockaddrXdp {
        pub sxdp_family: u16,
        pub sxdp_flags: u16,
        pub sxdp_ifindex: u32,
        pub sxdp_queue_id: u32,
        pub sxdp_shared_umem_fd: u32,
    }

    // UMEM descriptor for zero-copy
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct XdpDesc {
        pub addr: u64,
        pub len: u32,
        pub options: u32,
    }

    // XDP ring structures
    pub struct XdpRing {
        pub producer: u32,
        pub consumer: u32,
        pub desc: Box<[XdpDesc; XDP_RING_SIZE as usize]>,
        pub flags: u32,
    }

    impl XdpRing {
        fn new() -> Self {
            Self {
                producer: 0,
                consumer: 0,
                desc: Box::new([XdpDesc::default(); XDP_RING_SIZE as usize]),
                flags: 0,
            }
        }
    }

    // XDP removed - use UdpFastPath or IoUringTransport instead

    pub struct UmemArea {
        pub(crate) addr: *mut u8,
        pub(crate) size: usize,
        pub(crate) frame_size: usize,
        pub(crate) frame_count: usize,
    }

    pub struct XdpSocket {
        pub(crate) fd: i32,
        pub(crate) umem: Arc<UmemArea>,
        pub(crate) rx_ring: XdpRing,
        pub(crate) tx_ring: XdpRing,
        pub(crate) fill_ring: XdpRing,
        pub(crate) comp_ring: XdpRing,
    }

    impl XdpSocket {
        pub fn new(
            ifindex: u32,
            queue_id: u32,
            frame_size: usize,
            frame_count: usize,
        ) -> Result<Self, std::io::Error> {
            if frame_size == 0 || frame_count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "frame_size and frame_count must be greater than zero",
                ));
            }
            let umem_size = frame_size.checked_mul(frame_count).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "UMEM size overflow")
            })?;

            unsafe {
                // Create AF_XDP socket
                let fd = libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let sockaddr = SockaddrXdp {
                    sxdp_family: libc::AF_XDP as u16,
                    sxdp_flags: 0,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id,
                    sxdp_shared_umem_fd: 0,
                };
                let bind_rc = libc::bind(
                    fd,
                    &sockaddr as *const SockaddrXdp as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
                );
                if bind_rc < 0 {
                    let err = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(err);
                }

                // Allocate UMEM area (try huge pages first, then standard pages).
                let mut addr = libc::mmap(
                    ptr::null_mut(),
                    umem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
                    -1,
                    0,
                ) as *mut u8;

                if addr == libc::MAP_FAILED as *mut u8 {
                    addr = libc::mmap(
                        ptr::null_mut(),
                        umem_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    ) as *mut u8;
                    if addr == libc::MAP_FAILED as *mut u8 {
                        libc::close(fd);
                        return Err(std::io::Error::last_os_error());
                    }
                }

                let umem = Arc::new(UmemArea { addr, size: umem_size, frame_size, frame_count });

                // Allocate independent software-side rings.
                let rx_ring = XdpRing::new();
                let tx_ring = XdpRing::new();
                let fill_ring = XdpRing::new();
                let comp_ring = XdpRing::new();

                Ok(XdpSocket { fd, umem, rx_ring, tx_ring, fill_ring, comp_ring })
            }
        }

        pub fn send_packet(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
            unsafe {
                let producer = self.tx_ring.producer;
                let consumer = self.tx_ring.consumer;

                if producer.wrapping_sub(consumer) >= XDP_RING_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "TX ring full",
                    ));
                }

                let idx = (producer & (XDP_RING_SIZE - 1)) as usize;
                let desc = &mut self.tx_ring.desc[idx];
                let copy_len = data.len().min(self.umem.frame_size);

                // Copy data to UMEM
                let frame_addr = self.umem.addr.add((idx as usize) * self.umem.frame_size);
                ptr::copy_nonoverlapping(data.as_ptr(), frame_addr, copy_len);

                desc.addr = (idx as u64) * (self.umem.frame_size as u64);
                desc.len = copy_len as u32;
                desc.options = 0;

                // Update producer
                self.tx_ring.producer = producer.wrapping_add(1);

                // Kick TX
                libc::sendto(self.fd, ptr::null(), 0, libc::MSG_DONTWAIT, ptr::null(), 0);

                Ok(())
            }
        }

        pub fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
            unsafe {
                let producer = self.rx_ring.producer;
                let consumer = self.rx_ring.consumer;

                if producer == consumer {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "RX ring empty",
                    ));
                }

                let idx = (consumer & (XDP_RING_SIZE - 1)) as usize;
                let desc = self.rx_ring.desc[idx];
                let frame_offset = desc.addr as usize;
                if frame_offset >= self.umem.size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "RX descriptor points outside UMEM",
                    ));
                }

                // Copy from UMEM
                let frame_addr = self.umem.addr.add(frame_offset);
                let available = self.umem.size.saturating_sub(frame_offset);
                let len = (desc.len as usize).min(buf.len()).min(available);
                ptr::copy_nonoverlapping(frame_addr, buf.as_mut_ptr(), len);

                // Update consumer
                self.rx_ring.consumer = consumer.wrapping_add(1);

                // Refill
                let fill_producer = self.fill_ring.producer;
                let fill_desc =
                    &mut self.fill_ring.desc[(fill_producer & (XDP_RING_SIZE - 1)) as usize];
                fill_desc.addr = desc.addr;
                self.fill_ring.producer = fill_producer.wrapping_add(1);

                Ok(len)
            }
        }
    }

    impl Drop for XdpSocket {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
                libc::munmap(self.umem.addr as *mut c_void, self.umem.size);
            }
        }
    }
}

// =========================== io_uring UDP Fast Path ===========================
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
pub mod uring_udp {
    use super::*;
    use io_uring::{opcode, types, IoUring};
    use libc::{c_void, sockaddr, sockaddr_in, sockaddr_in6, socklen_t};
    use std::io;
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

    const BUFFER_GROUP_ID: u16 = 0;
    const BUFFER_SIZE: usize = 4096;
    const BUFFER_COUNT: usize = 64;

    fn to_raw_sockaddr(
        addr: &SocketAddr,
        storage: &mut libc::sockaddr_storage,
    ) -> (usize, *const sockaddr) {
        unsafe {
            std::ptr::write_bytes(
                storage as *mut _ as *mut u8,
                0,
                std::mem::size_of::<libc::sockaddr_storage>(),
            )
        };
        match addr {
            SocketAddr::V4(v4) => {
                let mut s: sockaddr_in = unsafe { std::mem::zeroed() };
                s.sin_family = libc::AF_INET as u16;
                s.sin_port = v4.port().to_be();
                s.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &s as *const _ as *const u8,
                        storage as *const _ as *mut u8,
                        std::mem::size_of::<sockaddr_in>(),
                    )
                };
                (std::mem::size_of::<sockaddr_in>(), storage as *const _ as *const sockaddr)
            }
            SocketAddr::V6(v6) => {
                let mut s: sockaddr_in6 = unsafe { std::mem::zeroed() };
                s.sin6_family = libc::AF_INET6 as u16;
                s.sin6_port = v6.port().to_be();
                s.sin6_addr = libc::in6_addr { s6_addr: v6.ip().octets() };
                s.sin6_scope_id = v6.scope_id();
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &s as *const _ as *const u8,
                        storage as *const _ as *mut u8,
                        std::mem::size_of::<sockaddr_in6>(),
                    )
                };
                (std::mem::size_of::<sockaddr_in6>(), storage as *const _ as *const sockaddr)
            }
        }
    }

    #[inline(always)]
    fn buffer_select(flags: u32) -> Option<u16> {
        const IORING_CQE_F_BUFFER: u32 = 1 << 5;
        if flags & IORING_CQE_F_BUFFER != 0 {
            let bid = (flags >> 16) as u16;
            Some(bid)
        } else {
            None
        }
    }

    pub struct UringUdp {
        ring: IoUring,
        fd: RawFd,
        _registered: bool,
        buffers_provided: bool,
        buffer_pool: Option<Vec<Vec<u8>>>,
        multishot_enabled: bool,
    }

    impl UringUdp {
        #[inline(always)]
        fn zerocopy_enabled() -> bool {
            std::env::var("QUICFUSCATE_URING_ZEROCOPY")
                .map(|v| v != "0" && v.to_lowercase() != "false")
                .unwrap_or(false)
        }

        #[inline(always)]
        fn drain_errqueue(fd: RawFd) {
            // Best-effort: drain error queue created by MSG_ZEROCOPY completions to avoid buildup.
            // Non-blocking socket: loop until EAGAIN/EWOULDBLOCK.
            unsafe {
                let mut cbuf = [0u8; 256];
                let mut iov = libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 };
                let mut hdr: libc::msghdr = std::mem::zeroed();
                hdr.msg_iov = &mut iov;
                hdr.msg_iovlen = 0;
                hdr.msg_control = cbuf.as_mut_ptr() as *mut _;
                hdr.msg_controllen = cbuf.len() as _;
                loop {
                    let rc = libc::recvmsg(fd, &mut hdr, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT);
                    if rc < 0 {
                        let e = *libc::__errno_location();
                        if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                            break;
                        }
                        crate::optimize::telemetry::URING_ERRORS.inc();
                        break;
                    }
                    // else: drained one notif; continue
                }
            }
        }

        pub fn new(
            bind: SocketAddr,
            peer: SocketAddr,
            queue_depth: u32,
            register_buffers: bool,
        ) -> io::Result<Self> {
            unsafe {
                let domain = match bind {
                    SocketAddr::V4(_) => libc::AF_INET,
                    SocketAddr::V6(_) => libc::AF_INET6,
                };
                let fd = libc::socket(
                    domain,
                    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                );
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // bind
                let mut bind_storage: libc::sockaddr_storage = std::mem::zeroed();
                let (blen, bptr) = to_raw_sockaddr(&bind, &mut bind_storage);
                if libc::bind(fd, bptr, blen as socklen_t) < 0 {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }
                // connect (so we can use Send/Recv without msg headers)
                let mut peer_storage: libc::sockaddr_storage = std::mem::zeroed();
                let (plen, pptr) = to_raw_sockaddr(&peer, &mut peer_storage);
                if libc::connect(fd, pptr, plen as socklen_t) < 0 {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }

                // Optional: enable SO_ZEROCOPY if requested (best-effort)
                if std::env::var("QUICFUSCATE_URING_ZEROCOPY")
                    .map(|v| v != "0" && v.to_lowercase() != "false")
                    .unwrap_or(false)
                {
                    let one: libc::c_int = 1;
                    let rc = libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ZEROCOPY,
                        &one as *const _ as *const c_void,
                        std::mem::size_of_val(&one) as socklen_t,
                    );
                    if rc < 0 {
                        crate::optimize::telemetry::URING_FALLBACKS.inc();
                    }
                }
                let mut ring = IoUring::new(queue_depth as _)?;

                // Setup buffer provisioning if requested
                let buffers_provided = register_buffers;
                let mut buffer_pool = None;
                let multishot = std::env::var("QUICFUSCATE_URING_MULTISHOT")
                    .map(|v| v != "0" && v.to_lowercase() != "false")
                    .unwrap_or(false);

                if buffers_provided {
                    // Allocate buffer pool
                    let mut pool = Vec::with_capacity(BUFFER_COUNT);
                    for _ in 0..BUFFER_COUNT {
                        pool.push(vec![0u8; BUFFER_SIZE]);
                    }

                    // Provide buffers to io_uring
                    for (i, buf) in pool.iter().enumerate() {
                        let provide_e = opcode::ProvideBuffers::new(
                            buf.as_ptr(),
                            BUFFER_SIZE as _,
                            1,
                            BUFFER_GROUP_ID,
                            i as u16,
                        )
                        .build();
                        unsafe {
                            ring.submission().push(&provide_e).map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "provide buffers failed")
                            })?;
                        }
                    }
                    ring.submit()?;
                    buffer_pool = Some(pool);
                }

                let me = Self {
                    ring,
                    fd,
                    _registered: false,
                    buffers_provided,
                    buffer_pool,
                    multishot_enabled: multishot,
                };
                // Telemetry
                crate::optimize::telemetry::URING_ACTIVE
                    .store(1, std::sync::atomic::Ordering::Relaxed);
                crate::optimize::telemetry::URING_QUEUE_DEPTH.set(queue_depth as i64);
                Ok(me)
            }
        }

        #[inline(always)]
        pub fn send(&mut self, data: &[u8]) -> io::Result<usize> {
            let ptr = data.as_ptr();
            let len = data.len();
            let mut send = opcode::Send::new(types::Fd(self.fd), ptr, len as _);
            if Self::zerocopy_enabled() {
                send = send.flags(libc::MSG_ZEROCOPY as _);
            }
            let send_e = send.build().user_data(0x51);
            unsafe {
                self.ring
                    .submission()
                    .push(&send_e)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "sq full"))?;
            }
            crate::optimize::telemetry::URING_SUBMISSIONS.inc();
            self.ring.submit_and_wait(1)?;
            if let Some(cqe) = self.ring.completion().next() {
                crate::optimize::telemetry::URING_COMPLETIONS.inc();
                if cqe.result() < 0 {
                    crate::optimize::telemetry::URING_ERRORS.inc();
                    return Err(io::Error::from_raw_os_error(-cqe.result()));
                }
                let n = cqe.result() as usize;
                crate::optimize::telemetry::URING_BYTES_SENT.inc_by(n as u64);
                if Self::zerocopy_enabled() {
                    Self::drain_errqueue(self.fd);
                }
                Ok(n)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "no cqe"))
            }
        }

        #[inline(always)]
        pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.buffers_provided && self.multishot_enabled {
                // Multishot recv with buffer selection
                let recv_e = opcode::RecvMsg::new(
                    types::Fd(self.fd),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
                .flags(libc::MSG_DONTWAIT as _)
                .buf_group(BUFFER_GROUP_ID)
                .build()
                .flags(io_uring::squeue::Flags::BUFFER_SELECT)
                .user_data(0x52);
                unsafe {
                    self.ring
                        .submission()
                        .push(&recv_e)
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "sq full"))?;
                }
                crate::optimize::telemetry::URING_SUBMISSIONS.inc();
                self.ring.submit_and_wait(1)?;

                if let Some(cqe) = self.ring.completion().next() {
                    crate::optimize::telemetry::URING_COMPLETIONS.inc();
                    if cqe.result() < 0 {
                        crate::optimize::telemetry::URING_ERRORS.inc();
                        return Err(io::Error::from_raw_os_error(-cqe.result()));
                    }

                    let n = cqe.result() as usize;
                    if n > 0 {
                        // Extract buffer ID from flags
                        let bid = buffer_select(cqe.flags()).unwrap_or(0) as usize;
                        if let Some(ref pool) = self.buffer_pool {
                            if bid < pool.len() && n <= buf.len() {
                                buf[..n].copy_from_slice(&pool[bid][..n]);
                            }
                        }
                        // Re-provide the buffer
                        if let Some(ref pool) = self.buffer_pool {
                            if bid < pool.len() {
                                let provide_e = opcode::ProvideBuffers::new(
                                    pool[bid].as_ptr(),
                                    BUFFER_SIZE as _,
                                    1,
                                    BUFFER_GROUP_ID,
                                    bid as u16,
                                )
                                .build();
                                unsafe {
                                    let _ = self.ring.submission().push(&provide_e);
                                }
                            }
                        }

                        #[cfg(test)]
                        mod tests {
                            use super::*;
                            use std::net::SocketAddr;

                            #[test]
                            fn sockaddr_roundtrip_v4() {
                                let addr: SocketAddr = "192.0.2.15:4433".parse().unwrap();
                                let mut storage: libc::sockaddr_storage =
                                    unsafe { std::mem::zeroed() };
                                let (len, raw) = super::to_raw_sockaddr(&addr, &mut storage);
                                assert_eq!(len, std::mem::size_of::<libc::sockaddr_in>());
                                unsafe {
                                    let v4 = *(raw as *const libc::sockaddr_in);
                                    assert_eq!(u16::from_be(v4.sin_port), 4433);
                                    assert_eq!(v4.sin_family, libc::AF_INET as u16);
                                    assert_eq!(v4.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 15]);
                                }
                            }

                            #[test]
                            fn sockaddr_roundtrip_v6() {
                                let addr: SocketAddr = "[2001:db8::1]:8443".parse().unwrap();
                                let mut storage: libc::sockaddr_storage =
                                    unsafe { std::mem::zeroed() };
                                let (len, raw) = super::to_raw_sockaddr(&addr, &mut storage);
                                assert_eq!(len, std::mem::size_of::<libc::sockaddr_in6>());
                                unsafe {
                                    let v6 = *(raw as *const libc::sockaddr_in6);
                                    assert_eq!(u16::from_be(v6.sin6_port), 8443);
                                    assert_eq!(v6.sin6_family, libc::AF_INET6 as u16);
                                    let expected = match addr {
                                        SocketAddr::V6(v) => v.ip().octets(),
                                        _ => unreachable!(),
                                    };
                                    assert_eq!(v6.sin6_addr.s6_addr, expected);
                                }
                            }
                        }
                    }

                    crate::optimize::telemetry::URING_BYTES_RECEIVED.inc_by(n as u64);
                    Ok(n)
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "no cqe"))
                }
            } else {
                // Standard recv path
                let ptr = buf.as_mut_ptr();
                let len = buf.len();
                let recv_e =
                    opcode::Recv::new(types::Fd(self.fd), ptr, len as _).build().user_data(0x52);
                unsafe {
                    self.ring
                        .submission()
                        .push(&recv_e)
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "sq full"))?;
                }
                crate::optimize::telemetry::URING_SUBMISSIONS.inc();
                self.ring.submit_and_wait(1)?;
                if let Some(cqe) = self.ring.completion().next() {
                    crate::optimize::telemetry::URING_COMPLETIONS.inc();
                    if cqe.result() < 0 {
                        crate::optimize::telemetry::URING_ERRORS.inc();
                        return Err(io::Error::from_raw_os_error(-cqe.result()));
                    }
                    let n = cqe.result() as usize;
                    crate::optimize::telemetry::URING_BYTES_RECEIVED.inc_by(n as u64);
                    Ok(n)
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "no cqe"))
                }
            }
        }
    }

    impl Drop for UringUdp {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
            crate::optimize::telemetry::URING_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

// GSO/GRO Offload Support
pub struct SegmentationOffload {
    gso_enabled: bool,
    gro_enabled: bool,
    max_gso_size: usize,
    max_gro_size: usize,
    current_batch_size: usize,
    adaptive_batching: bool,
}

impl Default for SegmentationOffload {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentationOffload {
    pub fn new() -> Self {
        Self {
            gso_enabled: Self::detect_gso_support(),
            gro_enabled: Self::detect_gro_support(),
            max_gso_size: 65536,
            max_gro_size: 65536,
            current_batch_size: 32,
            adaptive_batching: true,
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_gso_support() -> bool {
        // Check if GSO is available via UDP_SEGMENT socket option
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                return false;
            }
            let mut val: i32 = 0;
            let mut len = mem::size_of::<i32>() as socklen_t;
            let ret = libc::getsockopt(
                sock,
                libc::SOL_UDP,
                103, // UDP_SEGMENT
                &mut val as *mut _ as *mut c_void,
                &mut len,
            );
            libc::close(sock);
            ret == 0
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_gso_support() -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    fn detect_gro_support() -> bool {
        // Check if GRO is available via UDP_GRO socket option
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                return false;
            }
            let mut val: i32 = 0;
            let mut len = mem::size_of::<i32>() as socklen_t;
            let ret = libc::getsockopt(
                sock,
                libc::SOL_UDP,
                104, // UDP_GRO
                &mut val as *mut _ as *mut c_void,
                &mut len,
            );
            libc::close(sock);
            ret == 0
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_gro_support() -> bool {
        false
    }

    // Optimized userland GSO emulation for non-Linux platforms
    pub fn segment_packet(&self, data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        // Use configured max_gso_size if available
        let effective_mtu = if self.gso_enabled { mtu.min(self.max_gso_size) } else { mtu };

        // Adaptive batching: adjust batch size based on performance
        let _batch_hint = if self.adaptive_batching {
            self.current_batch_size
        } else {
            32 // Default batch size
        };

        // Pre-calculate number of segments for capacity
        let num_segments = data.len().div_ceil(effective_mtu);
        let mut segments = Vec::with_capacity(num_segments);
        let mut offset = 0;

        while offset < data.len() {
            let segment_size = (data.len() - offset).min(effective_mtu);

            // Prefetch next segment data
            if offset + effective_mtu < data.len() {
                unsafe {
                    prefetch(data.as_ptr().add(offset + effective_mtu), PrefetchHint::T0);
                }
            }

            let mut segment = Vec::with_capacity(segment_size);
            segment.extend_from_slice(&data[offset..offset + segment_size]);
            segments.push(segment);
            offset += segment_size;
        }

        segments
    }

    // Optimized userland GRO emulation
    pub fn coalesce_packets(&self, packets: Vec<Vec<u8>>) -> Vec<u8> {
        let mut total_size: usize = packets.iter().map(|p| p.len()).sum();
        if self.gro_enabled {
            total_size = total_size.min(self.max_gro_size);
        }
        let mut coalesced = Vec::with_capacity(total_size);

        for packet in packets {
            // Prefetch packet data
            unsafe {
                prefetch(packet.as_ptr(), PrefetchHint::T0);
            }
            let remaining = if self.gro_enabled {
                self.max_gro_size.saturating_sub(coalesced.len())
            } else {
                usize::MAX
            };
            if remaining == 0 {
                break;
            }
            let take = remaining.min(packet.len());
            coalesced.extend_from_slice(&packet[..take]);
            if self.gro_enabled && coalesced.len() >= self.max_gro_size {
                break;
            }
        }

        coalesced
    }
}

use std::collections::VecDeque;
use std::time::Instant;

// Integration with Transport
pub struct FastPathTransport {
    pub(crate) udp_fast: Option<crate::transport::udpfast::UdpFastPath>,
    #[cfg(all(target_os = "linux", feature = "uring_sys"))]
    pub(crate) uring: Option<uring_udp::UringUdp>,
    pub(crate) segmentation: SegmentationOffload,
    pub(crate) mem_pool: Arc<crate::optimize::MemoryPool>,
    pub(crate) batch_queue: VecDeque<BatchedPacket>,
    pub(crate) vectored_io_enabled: bool,
    pub(crate) numa_aware: bool,
    pub(crate) default_peer: Option<std::net::SocketAddr>,
}

#[derive(Debug)]
pub struct BatchedPacket {
    pub data: Vec<u8>,
    pub addr: std::net::SocketAddr,
    pub ecn: u8,
    pub timestamp: Instant,
}

impl FastPathTransport {
    pub fn new(mem_pool: Arc<crate::optimize::MemoryPool>) -> Self {
        Self {
            udp_fast: None,
            #[cfg(all(target_os = "linux", feature = "uring_sys"))]
            uring: None,
            segmentation: SegmentationOffload::new(),
            mem_pool,
            batch_queue: VecDeque::new(),
            vectored_io_enabled: true,
            numa_aware: false,
            default_peer: None,
        }
    }

    // XDP removed - use UDP fast path or io_uring instead

    fn flush_batch(&mut self) -> Result<(), std::io::Error> {
        if self.batch_queue.is_empty() {
            return Ok(());
        }

        // Allocate from memory pool if NUMA-aware
        let packets: Vec<_> = if self.numa_aware {
            self.batch_queue
                .drain(..)
                .map(|p| {
                    let mut block = self.mem_pool.alloc();
                    let len = p.data.len().min(block.len());
                    block[..len].copy_from_slice(&p.data[..len]);
                    (block.to_vec(), p.addr)
                })
                .collect()
        } else {
            self.batch_queue.drain(..).map(|p| (p.data, p.addr)).collect()
        };

        // Send via UDP fast path if available
        if let Some(ref mut udp) = self.udp_fast {
            let packet_refs: Vec<_> =
                packets.iter().map(|(data, addr)| (data.as_ref(), *addr)).collect();
            udp.send_batch(&packet_refs)?;
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "UDP fast path not configured",
            ))
        }
    }

    pub fn send_with_gso(&mut self, data: &[u8], mtu: usize) -> Result<(), std::io::Error> {
        // Use vectored I/O if enabled for better batching
        if self.vectored_io_enabled {
            let peer = self.default_peer.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "Fast path peer not set")
            })?;
            let packet = BatchedPacket {
                data: data.to_vec(),
                addr: peer,
                ecn: 0,
                timestamp: Instant::now(),
            };
            self.batch_queue.push_back(packet);

            // Flush if queue is full
            if self.batch_queue.len() >= 32 {
                return self.flush_batch();
            }
            return Ok(());
        }

        let segments = self.segmentation.segment_packet(data, mtu);

        // XDP removed
        #[cfg(all(target_os = "linux", feature = "uring_sys"))]
        if let Some(ref mut ur) = self.uring {
            for segment in segments {
                let _ = ur.send(&segment)?;
            }
            return Ok(());
        }

        if let Some(ref mut udp) = self.udp_fast {
            let peer = self.default_peer.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "Fast path peer not set")
            })?;
            let packet_refs: Vec<_> = segments.iter().map(|seg| (seg.as_ref(), peer)).collect();
            udp.send_batch(&packet_refs)?;
            return Ok(());
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "No fast path transport configured",
        ))
    }

    pub fn recv_with_gro(&mut self, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
        // XDP removed
        #[cfg(all(target_os = "linux", feature = "uring_sys"))]
        if let Some(ref mut ur) = self.uring {
            return ur.recv(_buf);
        }
        // Fallback
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No fast path enabled"))
    }

    #[cfg(all(target_os = "linux", feature = "uring_sys"))]
    pub fn enable_uring(
        &mut self,
        bind: std::net::SocketAddr,
        peer: std::net::SocketAddr,
    ) -> Result<(), std::io::Error> {
        let qd = std::env::var("QUICFUSCATE_URING_QUEUE_DEPTH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256u32);
        let reg = std::env::var("QUICFUSCATE_URING_REGISTER_BUFFERS")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(false);
        let ur = uring_udp::UringUdp::new(bind, peer, qd, reg)?;
        self.uring = Some(ur);
        self.default_peer = Some(peer);
        log::info!(
            "io_uring fastpath enabled (bind={}, peer={}, qd={}, reg={})",
            bind,
            peer,
            qd,
            reg
        );
        Ok(())
    }

    /// Enable the best available fast-path based on environment configuration.
    ///
    /// QUICFUSCATE_FASTPATH = "off" | "uring" | "xdp" | "auto" (default: auto)
    /// Current implementation auto-enables io_uring when available and requested.
    #[inline]
    pub fn enable_fastpath_from_env(
        &mut self,
        bind: std::net::SocketAddr,
        peer: std::net::SocketAddr,
    ) {
        self.default_peer = Some(peer);
        let mode = std::env::var("QUICFUSCATE_FASTPATH")
            .unwrap_or_else(|_| "auto".to_string())
            .to_lowercase();
        match mode.as_str() {
            "off" => { /* no-op */ }
            "xdp" => {
                log::info!(
                    "XDP requested via env; use enable_xdp(ifindex, queue) explicitly to activate"
                );
            }
            "uring" | "auto" => {
                #[cfg(all(target_os = "linux", feature = "uring_sys"))]
                {
                    if let Err(e) = self.enable_uring(bind, peer) {
                        log::warn!("io_uring enable failed: {}", e);
                    }
                }
                #[cfg(not(all(target_os = "linux", feature = "uring_sys")))]
                {
                    let _ = (bind, peer);
                }
            }
            _ => {}
        }
    }
}

#[cfg(all(test, target_os = "linux", feature = "uring_sys"))]
mod fastpath_tests {
    use super::FastPathTransport;

    #[test]
    fn enable_uring_is_no_longer_unwired_stub() {
        let mut fp = FastPathTransport::new(crate::optimize::global_pool());
        let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

        if let Err(e) = fp.enable_uring(bind, peer) {
            assert!(
                !e.to_string().contains("not wired"),
                "enable_uring regressed to unwired stub error: {}",
                e
            );
        }
    }
}
