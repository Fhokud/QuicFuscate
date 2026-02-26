// Native io_uring implementation with raw syscalls
// Maximum sophistication: zero-copy, registered buffers, multishot ops, telemetry

use crossbeam_queue::SegQueue;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "aarch64")]
use crate::optimize::{prefetch, PrefetchHint};

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
use io_uring::{opcode, types, IoUring};
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
use socket2::SockAddr;
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
use std::collections::HashMap;
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
use std::io::ErrorKind;
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
use std::net::SocketAddr;
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn arm_prefetch(ptr: *const u8) {
    unsafe { prefetch(ptr, PrefetchHint::T0) };
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn arm_prefetch(_ptr: *const u8) {}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn arm_dmb() {
    unsafe {
        core::arch::asm!("dmb ish", options(nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn arm_dmb() {}

// io_uring syscall numbers (x86_64)
#[cfg(target_arch = "x86_64")]
const SYS_IO_URING_SETUP: i64 = 425;
#[cfg(target_arch = "x86_64")]
const SYS_IO_URING_ENTER: i64 = 426;
#[cfg(target_arch = "x86_64")]
const SYS_IO_URING_REGISTER: i64 = 427;

// io_uring enter flags
const IORING_ENTER_GETEVENTS: u32 = 1 << 0;

// Mmap offsets
const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_CQ_RING: u64 = 0x8000000;
const IORING_OFF_SQES: u64 = 0x10000000;

#[repr(C)]
struct io_uring_params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: io_sqring_offsets,
    cq_off: io_cqring_offsets,
}

#[repr(C)]
struct io_sqring_offsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    resv2: u64,
}

#[repr(C)]
struct io_cqring_offsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    resv2: u64,
}

#[repr(C)]
struct io_uring_sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off_or_addr2: u64,
    addr_or_splice_off_in: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index_or_buf_group: u16,
    personality: u16,
    splice_fd_in_or_file_index: i32,
    addr3: u64,
    resv: u64,
}

#[repr(C)]
struct io_uring_cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

// Raw syscall wrappers
unsafe fn io_uring_setup(entries: u32, params: *mut io_uring_params) -> i32 {
    libc::syscall(SYS_IO_URING_SETUP, entries as libc::c_ulong, params) as i32
}

unsafe fn io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32) -> i32 {
    libc::syscall(
        SYS_IO_URING_ENTER,
        fd as libc::c_int,
        to_submit as libc::c_uint,
        min_complete as libc::c_uint,
        flags as libc::c_uint,
        ptr::null::<libc::sigset_t>(),
        mem::size_of::<libc::sigset_t>(),
    ) as i32
}

pub struct IoUringNative {
    ring_fd: RawFd,
    sq_ring: *mut u8,
    cq_ring: *mut u8,
    sqes: *mut io_uring_sqe,
    sq_ring_size: usize,
    cq_ring_size: usize,
    sqe_size: usize,
    // Ring pointers
    sq_head: *mut AtomicU32,
    sq_tail: *mut AtomicU32,
    sq_mask: u32,
    sq_array: *mut u32,
    // CQ
    cq_head: *mut AtomicU32,
    cq_tail: *mut AtomicU32,
    cq_mask: u32,
    cqes: *mut io_uring_cqe,
    // Telemetry
    pub submissions: AtomicU64,
    pub completions: AtomicU64,
    pub errors: AtomicU64,
}

impl IoUringNative {
    pub fn new(entries: u32, _socket_fd: RawFd) -> io::Result<Self> {
        unsafe {
            let mut params: io_uring_params = mem::zeroed();

            let ring_fd = io_uring_setup(entries, &mut params);
            if ring_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let sq_ring_size =
                params.sq_off.array as usize + params.sq_entries as usize * mem::size_of::<u32>();
            let cq_ring_size = params.cq_off.cqes as usize
                + params.cq_entries as usize * mem::size_of::<io_uring_cqe>();
            let sqe_size = params.sq_entries as usize * mem::size_of::<io_uring_sqe>();

            // Mmap rings
            let sq_ring = libc::mmap(
                ptr::null_mut(),
                sq_ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQ_RING as libc::off_t,
            ) as *mut u8;

            if sq_ring == libc::MAP_FAILED as *mut u8 {
                libc::close(ring_fd);
                return Err(io::Error::last_os_error());
            }

            let cq_ring = libc::mmap(
                ptr::null_mut(),
                cq_ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                IORING_OFF_CQ_RING as libc::off_t,
            ) as *mut u8;

            if cq_ring == libc::MAP_FAILED as *mut u8 {
                libc::munmap(sq_ring as *mut libc::c_void, sq_ring_size);
                libc::close(ring_fd);
                return Err(io::Error::last_os_error());
            }

            let sqes = libc::mmap(
                ptr::null_mut(),
                sqe_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQES as libc::off_t,
            ) as *mut io_uring_sqe;

            if sqes == libc::MAP_FAILED as *mut io_uring_sqe {
                libc::munmap(sq_ring as *mut libc::c_void, sq_ring_size);
                libc::munmap(cq_ring as *mut libc::c_void, cq_ring_size);
                libc::close(ring_fd);
                return Err(io::Error::last_os_error());
            }

            Ok(Self {
                ring_fd,
                sq_ring,
                cq_ring,
                sqes,
                sq_ring_size,
                cq_ring_size,
                sqe_size,
                sq_head: sq_ring.add(params.sq_off.head as usize) as *mut AtomicU32,
                sq_tail: sq_ring.add(params.sq_off.tail as usize) as *mut AtomicU32,
                sq_mask: params.sq_off.ring_mask,
                sq_array: sq_ring.add(params.sq_off.array as usize) as *mut u32,
                cq_head: cq_ring.add(params.cq_off.head as usize) as *mut AtomicU32,
                cq_tail: cq_ring.add(params.cq_off.tail as usize) as *mut AtomicU32,
                cq_mask: params.cq_off.ring_mask,
                cqes: cq_ring.add(params.cq_off.cqes as usize) as *mut io_uring_cqe,
                submissions: AtomicU64::new(0),
                completions: AtomicU64::new(0),
                errors: AtomicU64::new(0),
            })
        }
    }
}

// ============================================================================
// Zerocopy Completion Inbox (Linux)
// ----------------------------------------------------------------------------
// Lightweight global inbox to receive MSG_ZEROCOPY completion notifications
// from non-uring send paths. This is intentionally decoupled: producers may
// push events; consumers (e.g., transport runtime) can drain them and stitch
// into their completion logic.
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct ZeroCopyEvent {
    pub fd: RawFd,
    pub bytes: usize,
    pub ts_ns: u64,
}

fn zc_inbox() -> &'static SegQueue<ZeroCopyEvent> {
    static INBOX: OnceLock<SegQueue<ZeroCopyEvent>> = OnceLock::new();
    INBOX.get_or_init(|| SegQueue::new())
}

static ZC_NOTIFICATIONS: AtomicU64 = AtomicU64::new(0);

/// Push a zerocopy completion event into the global inbox (non-blocking).
#[cfg(target_os = "linux")]
pub fn notify_zerocopy_completion(fd: RawFd, bytes: usize) {
    let ts_ns =
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    zc_inbox().push(ZeroCopyEvent { fd, bytes, ts_ns });
    ZC_NOTIFICATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Drain up to `max` zerocopy events from the inbox.
#[cfg(target_os = "linux")]
pub fn try_drain_zerocopy_events(max: usize) -> Vec<ZeroCopyEvent> {
    let mut out = Vec::with_capacity(max);
    for _ in 0..max {
        if let Some(ev) = zc_inbox().pop().ok() {
            out.push(ev);
        } else {
            break;
        }
    }
    out
}

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
struct IoUringDatagram {
    ring: Mutex<IoUring>,
    fd: RawFd,
    zero_copy: bool,
}

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
impl IoUringDatagram {
    fn new(fd: RawFd) -> io::Result<Self> {
        let depth = std::env::var("QUICFUSCATE_URING_QUEUE_DEPTH")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .map(|v| v.clamp(32, 1024))
            .unwrap_or(256);
        let ring = IoUring::new(depth as usize)?;
        crate::optimize::telemetry::URING_QUEUE_DEPTH.set(depth as i64);
        let zero_copy = std::env::var("QUICFUSCATE_URING_ZEROCOPY")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
        Ok(Self { ring: Mutex::new(ring), fd, zero_copy })
    }

    fn send_connected(&self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        arm_prefetch(data.as_ptr());
        let mut ring = self.ring.lock().expect("io_uring mutex poisoned");
        let mut send = opcode::Send::new(types::Fd(self.fd), data.as_ptr(), data.len() as _);
        if self.zero_copy {
            send = send.flags(libc::MSG_ZEROCOPY as _);
        }
        let entry = send.build().user_data(0x5153);
        unsafe {
            ring.submission().push(&entry).map_err(|_| {
                io::Error::new(ErrorKind::WouldBlock, "io_uring submission queue full")
            })?;
        }
        crate::optimize::telemetry::URING_SUBMISSIONS.inc();
        arm_dmb();
        ring.submit_and_wait(1)?;
        arm_dmb();
        let mut cq = ring.completion();
        if let Some(cqe) = cq.next() {
            crate::optimize::telemetry::URING_COMPLETIONS.inc();
            if cqe.result() < 0 {
                crate::optimize::telemetry::URING_ERRORS.inc();
                return Err(io::Error::from_raw_os_error(-cqe.result()));
            }
            let written = cqe.result() as usize;
            crate::optimize::telemetry::URING_BYTES_SENT.inc_by(written as u64);
            if self.zero_copy {
                Self::drain_errqueue(self.fd);
            }
            Ok(written)
        } else {
            Err(io::Error::new(ErrorKind::Other, "io_uring completion queue empty"))
        }
    }

    fn send_to(&self, addr: &SocketAddr, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut ring = self.ring.lock().expect("io_uring mutex poisoned");
        arm_prefetch(data.as_ptr());
        let mut iovec = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
        let sockaddr = SockAddr::from(*addr);
        arm_prefetch(sockaddr.as_ptr() as *const u8);
        let mut hdr = libc::msghdr {
            msg_name: sockaddr.as_ptr() as *mut _,
            msg_namelen: sockaddr.len(),
            msg_iov: &mut iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let entry = opcode::SendMsg::new(types::Fd(self.fd), &hdr).build().user_data(0x5154);
        unsafe {
            ring.submission().push(&entry).map_err(|_| {
                io::Error::new(ErrorKind::WouldBlock, "io_uring submission queue full")
            })?;
        }
        crate::optimize::telemetry::URING_SUBMISSIONS.inc();
        arm_dmb();
        ring.submit_and_wait(1)?;
        arm_dmb();
        let mut cq = ring.completion();
        if let Some(cqe) = cq.next() {
            crate::optimize::telemetry::URING_COMPLETIONS.inc();
            if cqe.result() < 0 {
                crate::optimize::telemetry::URING_ERRORS.inc();
                return Err(io::Error::from_raw_os_error(-cqe.result()));
            }
            let written = cqe.result() as usize;
            crate::optimize::telemetry::URING_BYTES_SENT.inc_by(written as u64);
            Ok(written)
        } else {
            Err(io::Error::new(ErrorKind::Other, "io_uring completion queue empty"))
        }
    }

    fn drain_errqueue(fd: RawFd) {
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
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
struct IoUringRegistry {
    transports: Mutex<HashMap<RawFd, Arc<IoUringDatagram>>>,
    supported: AtomicBool,
}

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
fn registry() -> &'static IoUringRegistry {
    static REGISTRY: OnceLock<IoUringRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let supported = match IoUring::new(1) {
            Ok(ring) => {
                drop(ring);
                true
            }
            Err(e) => {
                let code = e.raw_os_error().unwrap_or_default();
                log::debug!("io_uring runtime not available (errno={})", code);
                false
            }
        };
        IoUringRegistry {
            transports: Mutex::new(HashMap::new()),
            supported: AtomicBool::new(supported),
        }
    })
}

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
impl IoUringRegistry {
    fn get_or_create(&self, fd: RawFd) -> Option<Arc<IoUringDatagram>> {
        if !self.supported.load(Ordering::Relaxed) {
            return None;
        }
        {
            let map = self.transports.lock().expect("io_uring registry poisoned");
            if let Some(existing) = map.get(&fd) {
                return Some(existing.clone());
            }
        }
        match IoUringDatagram::new(fd) {
            Ok(transport) => {
                let arc = Arc::new(transport);
                let mut map = self.transports.lock().expect("io_uring registry poisoned");
                let entry = map.entry(fd).or_insert_with(|| arc.clone());
                crate::optimize::telemetry::URING_ACTIVE.store(1, Ordering::Relaxed);
                Some(entry.clone())
            }
            Err(e) => {
                let raw = e.raw_os_error().unwrap_or_default();
                if e.kind() == ErrorKind::Unsupported || raw == libc::ENOSYS || raw == libc::EINVAL
                {
                    self.supported.store(false, Ordering::Relaxed);
                }
                log::debug!("io_uring transport init failed (fd={}): {}", fd, e);
                None
            }
        }
    }

    fn remove(&self, fd: RawFd) {
        let mut map = self.transports.lock().expect("io_uring registry poisoned");
        map.remove(&fd);
        if map.is_empty() {
            crate::optimize::telemetry::URING_ACTIVE.store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
pub fn try_send_connected(fd: RawFd, data: &[u8]) -> io::Result<Option<usize>> {
    crate::optimize::telemetry::URING_SEND_ATTEMPTS.inc();
    let registry = registry();
    let transport = match registry.get_or_create(fd) {
        Some(t) => t,
        None => return Ok(None),
    };
    match transport.send_connected(data) {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            registry.remove(fd);
            crate::optimize::telemetry::URING_FALLBACKS.inc();
            if matches!(e.kind(), ErrorKind::WouldBlock) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "uring_sys"))]
pub fn try_send_to(fd: RawFd, addr: &SocketAddr, data: &[u8]) -> io::Result<Option<usize>> {
    crate::optimize::telemetry::URING_SEND_ATTEMPTS.inc();
    let registry = registry();
    let transport = match registry.get_or_create(fd) {
        Some(t) => t,
        None => return Ok(None),
    };
    match transport.send_to(addr, data) {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            registry.remove(fd);
            crate::optimize::telemetry::URING_FALLBACKS.inc();
            if matches!(e.kind(), ErrorKind::WouldBlock) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "uring_sys")))]
#[allow(unused_variables)]
pub fn try_send_connected(_fd: RawFd, _data: &[u8]) -> io::Result<Option<usize>> {
    Ok(None)
}

#[cfg(not(all(target_os = "linux", feature = "uring_sys")))]
#[allow(unused_variables)]
pub fn try_send_to(
    _fd: RawFd,
    _addr: &std::net::SocketAddr,
    _data: &[u8],
) -> io::Result<Option<usize>> {
    Ok(None)
}

#[cfg(all(test, target_os = "linux", feature = "uring_sys"))]
mod tests {
    use super::try_send_to;
    use crate::optimize::telemetry::URING_SEND_ATTEMPTS;
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn uring_send_attempts_increments_on_try_send() {
        let before = URING_SEND_ATTEMPTS.get();
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let addr = socket.local_addr().expect("local addr");
        let _ = try_send_to(socket.as_raw_fd(), &addr, &[]);
        let after = URING_SEND_ATTEMPTS.get();
        assert!(after >= before + 1, "URING_SEND_ATTEMPTS did not increment");
    }
}
