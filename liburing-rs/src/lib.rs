#![allow(unsafe_op_in_unsafe_fn, non_snake_case)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_safety_doc,
         clippy::cast_sign_loss,
         clippy::similar_names,
         clippy::cast_possible_truncation,
         clippy::cast_possible_wrap,
         clippy::cast_ptr_alignment,
         clippy::used_underscore_items)]

mod uring;

use std::{
    mem::{self, zeroed},
    os::raw::{c_char, c_int, c_longlong, c_uint, c_ushort, c_void},
    ptr,
    sync::atomic::{
        AtomicU16, AtomicU32,
        Ordering::{self, Acquire, Relaxed, Release},
    },
    time::Duration,
};

pub use uring::*;

const LIBURING_UDATA_TIMEOUT: u64 = u64::MAX;

trait Atomic: Copy
{
    unsafe fn store(p: *mut Self, val: Self, order: Ordering);
    unsafe fn load(p: *mut Self, order: Ordering) -> Self;
}

impl Atomic for u32
{
    #[inline]
    unsafe fn store(p: *mut u32, val: u32, order: Ordering)
    {
        AtomicU32::from_ptr(p).store(val, order);
    }

    #[inline]
    unsafe fn load(p: *mut u32, order: Ordering) -> u32
    {
        AtomicU32::from_ptr(p).load(order)
    }
}

impl Atomic for u16
{
    #[inline]
    unsafe fn store(p: *mut u16, val: u16, order: Ordering)
    {
        AtomicU16::from_ptr(p).store(val, order);
    }

    #[inline]
    unsafe fn load(p: *mut u16, order: Ordering) -> u16
    {
        AtomicU16::from_ptr(p).load(order)
    }
}

unsafe fn io_uring_smp_store_release<T: Atomic>(p: *mut T, v: T)
{
    Atomic::store(p, v, Release);
}

unsafe fn io_uring_smp_load_acquire<T: Atomic>(p: *const T) -> T
{
    Atomic::load(p.cast_mut(), Acquire)
}

unsafe fn IO_URING_READ_ONCE<T: Atomic>(var: *const T) -> T
{
    Atomic::load(var.cast_mut(), Relaxed)
}

unsafe fn IO_URING_WRITE_ONCE<T: Atomic>(var: *mut T, val: T)
{
    Atomic::store(var, val, Relaxed);
}

/*
 * Library interface
 */

#[must_use]
#[inline]
pub unsafe fn uring_ptr_to_u64(ptr: *const c_void) -> u64
{
    ptr as u64
}

#[inline]
pub unsafe fn io_uring_opcode_supported(p: *mut io_uring_probe, op: c_int) -> c_int
{
    if op > (*p).last_op.into() {
        return 0;
    }

    i32::from((*(*p).ops.as_ptr().add(op as _)).flags & IO_URING_OP_SUPPORTED as u16 != 0)
}

/*
 * Returns the bit shift needed to index the CQ.
 * This shift is 1 for rings with big CQEs, and 0 for rings with normal CQEs.
 * CQE `index` can be computed as &cq.cqes[(index & cq.ring_mask) << cqe_shift].
 */
#[must_use]
#[inline]
pub fn io_uring_cqe_shift_from_flags(flags: c_uint) -> c_uint
{
    u32::from(flags & IORING_SETUP_CQE32 != 0)
}

#[inline]
pub unsafe fn io_uring_cqe_shift(ring: *mut io_uring) -> c_uint
{
    io_uring_cqe_shift_from_flags((*ring).flags)
}

#[inline]
pub unsafe fn io_uring_cqe_iter_init(ring: *mut io_uring) -> io_uring_cqe_iter
{
    io_uring_cqe_iter { cqes: (*ring).cq.cqes,
                        mask: (*ring).cq.ring_mask,
                        shift: io_uring_cqe_shift(ring),
                        head: *(*ring).cq.khead,
                        /* Acquire ordering ensures tail is loaded before any CQEs */
                        tail: io_uring_smp_load_acquire((*ring).cq.ktail) }
}

#[inline]
pub unsafe fn io_uring_cqe_iter_next(iter: *mut io_uring_cqe_iter, cqe: *mut *mut io_uring_cqe)
                                     -> bool
{
    if (*iter).head == (*iter).tail {
        return false;
    }

    let head = (*iter).head;
    (*iter).head += 1;

    let offset = (head & (*iter).mask) << (*iter).shift;
    *cqe = (*iter).cqes.add(offset as usize);

    true
}

pub unsafe fn io_uring_for_each_cqe<F>(ring: *mut io_uring, mut f: F)
    where F: FnMut(*mut io_uring_cqe)
{
    let mut iter = io_uring_cqe_iter_init(ring);
    let mut cqe = ptr::null_mut::<io_uring_cqe>();
    while io_uring_cqe_iter_next(&raw mut iter, &raw mut cqe) {
        f(cqe);
    }
}

/*
 * Must be called after io_uring_for_each_cqe()
 */
#[inline]
pub unsafe fn io_uring_cq_advance(ring: *mut io_uring, nr: c_uint)
{
    if nr > 0 {
        let cq = &raw mut (*ring).cq;

        /*
         * Ensure that the kernel only sees the new value of the head
         * index after the CQEs have been read.
         */
        io_uring_smp_store_release((*cq).khead, *(*cq).khead + nr);
    }
}

/*
 * Must be called after io_uring_{peek,wait}_cqe() after the cqe has
 * been processed by the application.
 */
#[inline]
pub unsafe fn io_uring_cqe_seen(ring: *mut io_uring, cqe: *mut io_uring_cqe)
{
    if !cqe.is_null() {
        io_uring_cq_advance(ring, 1);
    }
}

/*
 * Command prep helpers
 */

/*
 * Associate pointer @data with the sqe, for later retrieval from the cqe
 * at command completion time with io_uring_cqe_get_data().
 */
#[inline]
pub unsafe fn io_uring_sqe_set_data(sqe: *mut io_uring_sqe, data: *mut c_void)
{
    (*sqe).user_data = data as u64;
}

#[must_use]
#[inline]
pub unsafe fn io_uring_cqe_get_data(cqe: *const io_uring_cqe) -> *mut c_void
{
    (*cqe).user_data as *mut c_void
}

/*
 * Assign a 64-bit value to this sqe, which can get retrieved at completion
 * time with io_uring_cqe_get_data64. Just like the non-64 variants, except
 * these store a 64-bit type rather than a data pointer.
 */
#[inline]
pub unsafe fn io_uring_sqe_set_data64(sqe: *mut io_uring_sqe, data: u64)
{
    (*sqe).user_data = data;
}

#[must_use]
#[inline]
pub unsafe fn io_uring_cqe_get_data64(cqe: *const io_uring_cqe) -> u64
{
    (*cqe).user_data
}

#[inline]
pub unsafe fn io_uring_sqe_set_flags(sqe: *mut io_uring_sqe, flags: c_uint)
{
    (*sqe).flags = flags as u8;
}

#[inline]
pub unsafe fn io_uring_sqe_set_buf_group(sqe: *mut io_uring_sqe, bgid: c_int)
{
    (*sqe).__liburing_anon_4.buf_group = bgid as u16;
}

#[inline]
pub unsafe fn __io_uring_set_target_fixed_file(sqe: *mut io_uring_sqe, file_index: c_uint)
{
    /* 0 means no fixed files, indexes should be encoded as "index + 1" */
    (*sqe).__liburing_anon_5.file_index = file_index + 1;
}

#[inline]
pub unsafe fn io_uring_initialize_sqe(sqe: *mut io_uring_sqe)
{
    (*sqe).flags = 0;
    (*sqe).ioprio = 0;
    (*sqe).__liburing_anon_3.rw_flags = 0;
    (*sqe).__liburing_anon_4.buf_index = 0;
    (*sqe).personality = 0;
    (*sqe).__liburing_anon_5.file_index = 0;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = 0;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().__pad2[0] = 0;
}

#[inline]
pub unsafe fn io_uring_prep_rw(op: c_uint, sqe: *mut io_uring_sqe, fd: c_int, addr: *const c_void,
                               len: c_uint, offset: __u64)
{
    (*sqe).opcode = op as u8;
    (*sqe).fd = fd;
    (*sqe).__liburing_anon_1.off = offset;
    (*sqe).__liburing_anon_2.addr = addr as u64;
    (*sqe).len = len;
}

/*
 * io_uring_prep_splice() - Either @fd_in or @fd_out must be a pipe.
 *
 * - If @fd_in refers to a pipe, @off_in is ignored and must be set to -1.
 *
 * - If @fd_in does not refer to a pipe and @off_in is -1, then @nbytes are read
 *   from @fd_in starting from the file offset, which is incremented by the
 *   number of bytes read.
 *
 * - If @fd_in does not refer to a pipe and @off_in is not -1, then the starting
 *   offset of @fd_in will be @off_in.
 *
 * This splice operation can be used to implement sendfile by splicing to an
 * intermediate pipe first, then splice to the final destination.
 * In fact, the implementation of sendfile in kernel uses splice internally.
 *
 * NOTE that even if fd_in or fd_out refers to a pipe, the splice operation
 * can still fail with EINVAL if one of the fd doesn't explicitly support splice
 * operation, e.g. reading from terminal is unsupported from kernel 5.7 to 5.11.
 * Check issue #291 for more information.
 */
#[inline]
pub unsafe fn io_uring_prep_splice(sqe: *mut io_uring_sqe, fd_in: c_int, off_in: i64,
                                   fd_out: c_int, off_out: i64, nbytes: c_uint,
                                   splice_flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_SPLICE, sqe, fd_out, ptr::null_mut(), nbytes, off_out as u64);
    (*sqe).__liburing_anon_2.splice_off_in = off_in as u64;
    (*sqe).__liburing_anon_5.splice_fd_in = fd_in;
    (*sqe).__liburing_anon_3.splice_flags = splice_flags;
}

#[inline]
pub unsafe fn io_uring_prep_tee(sqe: *mut io_uring_sqe, fd_in: c_int, fd_out: c_int,
                                nbytes: c_uint, splice_flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_TEE, sqe, fd_out, ptr::null_mut(), nbytes, 0);
    (*sqe).__liburing_anon_2.splice_off_in = 0;
    (*sqe).__liburing_anon_5.splice_fd_in = fd_in;
    (*sqe).__liburing_anon_3.splice_flags = splice_flags;
}

#[inline]
pub unsafe fn io_uring_prep_readv(sqe: *mut io_uring_sqe, fd: c_int, iovecs: *const iovec,
                                  nr_vecs: c_uint, offset: u64)
{
    io_uring_prep_rw(IORING_OP_READV, sqe, fd, iovecs.cast(), nr_vecs, offset);
}

#[inline]
pub unsafe fn io_uring_prep_readv2(sqe: *mut io_uring_sqe, fd: c_int, iovecs: *const iovec,
                                   nr_vecs: c_uint, offset: u64, flags: c_int)
{
    io_uring_prep_readv(sqe, fd, iovecs, nr_vecs, offset);
    (*sqe).__liburing_anon_3.rw_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_read_fixed(sqe: *mut io_uring_sqe, fd: c_int, buf: *mut c_void,
                                       nbytes: c_uint, offset: u64, buf_index: c_int)
{
    io_uring_prep_rw(IORING_OP_READ_FIXED, sqe, fd, buf, nbytes, offset);
    (*sqe).__liburing_anon_4.buf_index = buf_index as u16;
}

#[inline]
pub unsafe fn io_uring_prep_readv_fixed(sqe: *mut io_uring_sqe, fd: c_int, iovecs: *const iovec,
                                        nr_vecs: c_uint, offset: u64, flags: c_int,
                                        buf_index: c_int)
{
    io_uring_prep_readv2(sqe, fd, iovecs, nr_vecs, offset, flags);
    (*sqe).opcode = IORING_OP_READV_FIXED as _;
    (*sqe).__liburing_anon_4.buf_index = buf_index as u16;
}

#[inline]
pub unsafe fn io_uring_prep_writev(sqe: *mut io_uring_sqe, fd: c_int, iovecs: *const iovec,
                                   nr_vecs: c_uint, offset: u64)
{
    io_uring_prep_rw(IORING_OP_WRITEV, sqe, fd, iovecs.cast(), nr_vecs, offset);
}

#[inline]
pub unsafe fn io_uring_prep_writev2(sqe: *mut io_uring_sqe, fd: c_int, iovecs: *const iovec,
                                    nr_vecs: c_uint, offset: u64, flags: c_int)
{
    io_uring_prep_writev(sqe, fd, iovecs, nr_vecs, offset);
    (*sqe).__liburing_anon_3.rw_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_write_fixed(sqe: *mut io_uring_sqe, fd: c_int, buf: *const c_void,
                                        nbytes: c_uint, offset: u64, buf_index: c_int)
{
    io_uring_prep_rw(IORING_OP_WRITE_FIXED, sqe, fd, buf, nbytes, offset);
    (*sqe).__liburing_anon_4.buf_index = buf_index as u16;
}

#[inline]
pub unsafe fn io_uring_prep_writev_fixed(sqe: *mut io_uring_sqe, fd: c_int, iovecs: *const iovec,
                                         nr_vecs: c_uint, offset: u64, flags: c_int,
                                         buf_index: c_int)
{
    io_uring_prep_writev2(sqe, fd, iovecs, nr_vecs, offset, flags);
    (*sqe).opcode = IORING_OP_WRITEV_FIXED as _;
    (*sqe).__liburing_anon_4.buf_index = buf_index as u16;
}

#[inline]
pub unsafe fn io_uring_prep_recvmsg(sqe: *mut io_uring_sqe, fd: c_int, msg: *mut msghdr,
                                    flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_RECVMSG, sqe, fd, msg.cast(), 1, 0);
    (*sqe).__liburing_anon_3.msg_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_recvmsg_multishot(sqe: *mut io_uring_sqe, fd: c_int, msg: *mut msghdr,
                                              flags: c_uint)
{
    io_uring_prep_recvmsg(sqe, fd, msg, flags);
    (*sqe).ioprio |= IORING_RECV_MULTISHOT as u16;
}

#[inline]
pub unsafe fn io_uring_prep_sendmsg(sqe: *mut io_uring_sqe, fd: c_int, msg: *const msghdr,
                                    flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_SENDMSG, sqe, fd, msg.cast(), 1, 0);
    (*sqe).__liburing_anon_3.msg_flags = flags;
}

#[must_use]
#[inline]
pub fn __io_uring_prep_poll_mask(poll_mask: c_uint) -> c_uint
{
    poll_mask.to_le()
}

#[inline]
pub unsafe fn io_uring_prep_poll_add(sqe: *mut io_uring_sqe, fd: c_int, poll_mask: c_uint)
{
    io_uring_prep_rw(IORING_OP_POLL_ADD, sqe, fd, ptr::null_mut(), 0, 0);
    (*sqe).__liburing_anon_3.poll32_events = __io_uring_prep_poll_mask(poll_mask);
}

#[inline]
pub unsafe fn io_uring_prep_poll_multishot(sqe: *mut io_uring_sqe, fd: c_int, poll_mask: c_uint)
{
    io_uring_prep_poll_add(sqe, fd, poll_mask);
    (*sqe).len = IORING_POLL_ADD_MULTI;
}

#[inline]
pub unsafe fn io_uring_prep_poll_remove(sqe: *mut io_uring_sqe, user_data: u64)
{
    io_uring_prep_rw(IORING_OP_POLL_REMOVE, sqe, -1, ptr::null_mut(), 0, 0);
    (*sqe).__liburing_anon_2.addr = user_data;
}

#[inline]
pub unsafe fn io_uring_prep_poll_update(sqe: *mut io_uring_sqe, old_user_data: u64,
                                        new_user_data: u64, poll_mask: c_uint, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_POLL_REMOVE, sqe, -1, ptr::null_mut(), flags, new_user_data);
    (*sqe).__liburing_anon_2.addr = old_user_data;
    (*sqe).__liburing_anon_3.poll32_events = __io_uring_prep_poll_mask(poll_mask);
}

#[inline]
pub unsafe fn io_uring_prep_fsync(sqe: *mut io_uring_sqe, fd: c_int, fsync_flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_FSYNC, sqe, fd, ptr::null_mut(), 0, 0);
    (*sqe).__liburing_anon_3.fsync_flags = fsync_flags;
}

#[inline]
pub unsafe fn io_uring_prep_nop(sqe: *mut io_uring_sqe)
{
    io_uring_prep_rw(IORING_OP_NOP, sqe, -1, ptr::null_mut(), 0, 0);
}

#[inline]
pub unsafe fn io_uring_prep_timeout(sqe: *mut io_uring_sqe, ts: *mut __kernel_timespec,
                                    count: c_uint, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_TIMEOUT, sqe, -1, ts.cast(), 1, count.into());
    (*sqe).__liburing_anon_3.timeout_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_timeout_remove(sqe: *mut io_uring_sqe, user_data: __u64, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_TIMEOUT_REMOVE, sqe, -1, ptr::null_mut(), 0, 0);
    (*sqe).__liburing_anon_2.addr = user_data;
    (*sqe).__liburing_anon_3.timeout_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_timeout_update(sqe: *mut io_uring_sqe, ts: *mut __kernel_timespec,
                                           user_data: __u64, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_TIMEOUT_REMOVE, sqe, -1, ptr::null_mut(), 0, ts as u64);
    (*sqe).__liburing_anon_2.addr = user_data;
    (*sqe).__liburing_anon_3.timeout_flags = flags | IORING_TIMEOUT_UPDATE;
}

#[inline]
pub unsafe fn io_uring_prep_accept(sqe: *mut io_uring_sqe, fd: c_int, addr: *mut sockaddr,
                                   addrlen: *mut socklen_t, flags: c_int)
{
    io_uring_prep_rw(IORING_OP_ACCEPT, sqe, fd, addr.cast(), 0, uring_ptr_to_u64(addrlen.cast()));
    (*sqe).__liburing_anon_3.accept_flags = flags as u32;
}

/* accept directly into the fixed file table */
#[inline]
pub unsafe fn io_uring_prep_accept_direct(sqe: *mut io_uring_sqe, fd: c_int, addr: *mut sockaddr,
                                          addrlen: *mut socklen_t, flags: c_int,
                                          mut file_index: c_uint)
{
    io_uring_prep_accept(sqe, fd, addr, addrlen, flags);
    /* offset by 1 for allocation */
    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
pub unsafe fn io_uring_prep_multishot_accept(sqe: *mut io_uring_sqe, fd: c_int,
                                             addr: *mut sockaddr, addrlen: *mut socklen_t,
                                             flags: c_int)
{
    io_uring_prep_accept(sqe, fd, addr, addrlen, flags);
    (*sqe).ioprio |= IORING_ACCEPT_MULTISHOT as u16;
}

/* multishot accept directly into the fixed file table */
#[inline]
pub unsafe fn io_uring_prep_multishot_accept_direct(sqe: *mut io_uring_sqe, fd: c_int,
                                                    addr: *mut sockaddr, addrlen: *mut socklen_t,
                                                    flags: c_int)
{
    io_uring_prep_multishot_accept(sqe, fd, addr, addrlen, flags);
    __io_uring_set_target_fixed_file(sqe, (IORING_FILE_INDEX_ALLOC - 1) as u32);
}

#[inline]
pub unsafe fn io_uring_prep_cancel64(sqe: *mut io_uring_sqe, user_data: u64, flags: c_int)
{
    io_uring_prep_rw(IORING_OP_ASYNC_CANCEL, sqe, -1, ptr::null_mut(), 0, 0);
    (*sqe).__liburing_anon_2.addr = user_data;
    (*sqe).__liburing_anon_3.cancel_flags = flags as u32;
}

#[inline]
pub unsafe fn io_uring_prep_cancel(sqe: *mut io_uring_sqe, user_data: *mut c_void, flags: c_int)
{
    io_uring_prep_cancel64(sqe, user_data as usize as u64, flags);
}

#[inline]
pub unsafe fn io_uring_prep_cancel_fd(sqe: *mut io_uring_sqe, fd: c_int, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_ASYNC_CANCEL, sqe, fd, ptr::null_mut(), 0, 0);
    (*sqe).__liburing_anon_3.cancel_flags = flags | IORING_ASYNC_CANCEL_FD;
}

#[inline]
pub unsafe fn io_uring_prep_link_timeout(sqe: *mut io_uring_sqe, ts: *mut __kernel_timespec,
                                         flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_LINK_TIMEOUT, sqe, -1, ts.cast(), 1, 0);
    (*sqe).__liburing_anon_3.timeout_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_connect(sqe: *mut io_uring_sqe, fd: c_int, addr: *const sockaddr,
                                    addrlen: socklen_t)
{
    io_uring_prep_rw(IORING_OP_CONNECT, sqe, fd, addr.cast(), 0, addrlen.into());
}

#[inline]
pub unsafe fn io_uring_prep_bind(sqe: *mut io_uring_sqe, fd: c_int, addr: *mut sockaddr,
                                 addrlen: socklen_t)
{
    io_uring_prep_rw(IORING_OP_BIND, sqe, fd, addr.cast(), 0, addrlen.into());
}

#[inline]
pub unsafe fn io_uring_prep_listen(sqe: *mut io_uring_sqe, fd: c_int, backlog: c_int)
{
    io_uring_prep_rw(IORING_OP_LISTEN, sqe, fd, ptr::null_mut(), backlog as _, 0);
}

#[inline]
pub unsafe fn io_uring_prep_epoll_wait(sqe: *mut io_uring_sqe, fd: c_int,
                                       events: *mut epoll_event, maxevents: c_int, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_EPOLL_WAIT, sqe, fd, events.cast(), maxevents as _, 0);
    (*sqe).__liburing_anon_3.rw_flags = flags as _;
}

#[inline]
pub unsafe fn io_uring_prep_files_update(sqe: *mut io_uring_sqe, fds: *mut c_int, nr_fds: c_uint,
                                         offset: c_int)
{
    io_uring_prep_rw(IORING_OP_FILES_UPDATE, sqe, -1, fds.cast(), nr_fds, offset as u64);
}

#[inline]
pub unsafe fn io_uring_prep_fallocate(sqe: *mut io_uring_sqe, fd: c_int, mode: c_int, offset: u64,
                                      len: u64)
{
    io_uring_prep_rw(IORING_OP_FALLOCATE, sqe, fd, ptr::null_mut(), mode as c_uint, offset);
    (*sqe).__liburing_anon_2.addr = len;
}

#[inline]
pub unsafe fn io_uring_prep_openat(sqe: *mut io_uring_sqe, dfd: c_int, path: *const c_char,
                                   flags: c_int, mode: mode_t)
{
    io_uring_prep_rw(IORING_OP_OPENAT, sqe, dfd, path.cast(), mode, 0);
    (*sqe).__liburing_anon_3.open_flags = flags as u32;
}

/* open directly into the fixed file table */
#[inline]
pub unsafe fn io_uring_prep_openat_direct(sqe: *mut io_uring_sqe, dfd: c_int, path: *const c_char,
                                          flags: c_int, mode: mode_t, mut file_index: c_uint)
{
    io_uring_prep_openat(sqe, dfd, path, flags, mode);
    /* offset by 1 for allocation */
    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
pub unsafe fn io_uring_prep_open(sqe: *mut io_uring_sqe, path: *const c_char, flags: c_int,
                                 mode: mode_t)
{
    io_uring_prep_openat(sqe, AT_FDCWD, path, flags, mode);
}

/* open directly into the fixed file table */
#[inline]
pub unsafe fn io_uring_prep_open_direct(sqe: *mut io_uring_sqe, path: *const c_char, flags: c_int,
                                        mode: mode_t, file_index: c_uint)
{
    io_uring_prep_openat_direct(sqe, AT_FDCWD, path, flags, mode, file_index);
}

#[inline]
pub unsafe fn io_uring_prep_close(sqe: *mut io_uring_sqe, fd: c_int)
{
    io_uring_prep_rw(IORING_OP_CLOSE, sqe, fd, ptr::null_mut(), 0, 0);
}

#[inline]
pub unsafe fn io_uring_prep_close_direct(sqe: *mut io_uring_sqe, file_index: c_uint)
{
    io_uring_prep_close(sqe, 0);
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
pub unsafe fn io_uring_prep_read(sqe: *mut io_uring_sqe, fd: c_int, buf: *mut c_void,
                                 nbytes: c_uint, offset: u64)
{
    io_uring_prep_rw(IORING_OP_READ, sqe, fd, buf, nbytes, offset);
}

#[inline]
pub unsafe fn io_uring_prep_read_multishot(sqe: *mut io_uring_sqe, fd: c_int, nbytes: c_uint,
                                           offset: u64, buf_group: c_int)
{
    io_uring_prep_rw(IORING_OP_READ_MULTISHOT, sqe, fd, ptr::null_mut(), nbytes, offset);
    (*sqe).__liburing_anon_4.buf_group = buf_group as _;
    (*sqe).flags = IOSQE_BUFFER_SELECT as _;
}

#[inline]
pub unsafe fn io_uring_prep_write(sqe: *mut io_uring_sqe, fd: c_int, buf: *const c_void,
                                  nbytes: c_uint, offset: u64)
{
    io_uring_prep_rw(IORING_OP_WRITE, sqe, fd, buf, nbytes, offset);
}

#[inline]
pub unsafe fn io_uring_prep_statx(sqe: *mut io_uring_sqe, dfd: c_int, path: *const c_char,
                                  flags: c_int, mask: c_uint, statxbuf: *mut statx)
{
    io_uring_prep_rw(IORING_OP_STATX,
                     sqe,
                     dfd,
                     path.cast(),
                     mask,
                     uring_ptr_to_u64(statxbuf.cast()));
    (*sqe).__liburing_anon_3.statx_flags = flags as u32;
}

#[inline]
pub unsafe fn io_uring_prep_fadvise(sqe: *mut io_uring_sqe, fd: c_int, offset: u64, len: u32,
                                    advice: c_int)
{
    io_uring_prep_rw(IORING_OP_FADVISE, sqe, fd, ptr::null_mut(), len, offset);
    (*sqe).__liburing_anon_3.fadvise_advice = advice as u32;
}

#[inline]
pub unsafe fn io_uring_prep_madvise(sqe: *mut io_uring_sqe, addr: *mut c_void, length: u32,
                                    advice: c_int)
{
    io_uring_prep_rw(IORING_OP_MADVISE, sqe, -1, addr, length, 0);
    (*sqe).__liburing_anon_3.fadvise_advice = advice as u32;
}

#[inline]
pub unsafe fn io_uring_prep_fadvise64(sqe: *mut io_uring_sqe, fd: c_int, offset: u64, len: off_t,
                                      advice: c_int)
{
    io_uring_prep_rw(IORING_OP_FADVISE, sqe, fd, ptr::null_mut(), 0, offset);
    (*sqe).__liburing_anon_2.addr = len as _;
    (*sqe).__liburing_anon_3.fadvise_advice = advice as u32;
}

#[inline]
pub unsafe fn io_uring_prep_madvise64(sqe: *mut io_uring_sqe, addr: *mut c_void, length: off_t,
                                      advice: c_int)
{
    io_uring_prep_rw(IORING_OP_MADVISE, sqe, -1, addr, 0, length as _);
    (*sqe).__liburing_anon_3.fadvise_advice = advice as u32;
}

#[inline]
pub unsafe fn io_uring_prep_send(sqe: *mut io_uring_sqe, sockfd: c_int, buf: *const c_void,
                                 len: usize, flags: c_int)
{
    io_uring_prep_rw(IORING_OP_SEND, sqe, sockfd, buf, len as u32, 0);
    (*sqe).__liburing_anon_3.msg_flags = flags as u32;
}

#[inline]
pub unsafe fn io_uring_prep_send_bundle(sqe: *mut io_uring_sqe, sockfd: c_int, len: usize,
                                        flags: c_int)
{
    io_uring_prep_send(sqe, sockfd, ptr::null_mut(), len, flags);
    (*sqe).ioprio |= IORING_RECVSEND_BUNDLE as u16;
}

#[inline]
pub unsafe fn io_uring_prep_send_set_addr(sqe: *mut io_uring_sqe, dest_addr: *const sockaddr,
                                          addr_len: u16)
{
    (*sqe).__liburing_anon_1.addr2 = dest_addr as usize as u64;
    (*sqe).__liburing_anon_5.__liburing_anon_1.addr_len = addr_len;
}

#[inline]
pub unsafe fn io_uring_prep_sendto(sqe: *mut io_uring_sqe, sockfd: c_int, buf: *const c_void,
                                   len: usize, flags: c_int, addr: *const sockaddr,
                                   addrlen: socklen_t)
{
    io_uring_prep_send(sqe, sockfd, buf, len, flags);
    io_uring_prep_send_set_addr(sqe, addr, addrlen as _);
}

#[inline]
pub unsafe fn io_uring_prep_send_zc(sqe: *mut io_uring_sqe, sockfd: c_int, buf: *const c_void,
                                    len: usize, flags: c_int, zc_flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_SEND_ZC, sqe, sockfd, buf, len as u32, 0);
    (*sqe).__liburing_anon_3.msg_flags = flags as u32;
    (*sqe).ioprio = zc_flags as _;
}

#[inline]
pub unsafe fn io_uring_prep_send_zc_fixed(sqe: *mut io_uring_sqe, sockfd: c_int,
                                          buf: *const c_void, len: usize, flags: c_int,
                                          zc_flags: c_uint, buf_index: c_uint)
{
    io_uring_prep_send_zc(sqe, sockfd, buf, len, flags, zc_flags);
    (*sqe).ioprio |= IORING_RECVSEND_FIXED_BUF as u16;
    (*sqe).__liburing_anon_4.buf_index = buf_index as _;
}

#[inline]
pub unsafe fn io_uring_prep_sendmsg_zc(sqe: *mut io_uring_sqe, fd: c_int, msg: *const msghdr,
                                       flags: c_uint)
{
    io_uring_prep_sendmsg(sqe, fd, msg, flags);
    (*sqe).opcode = IORING_OP_SENDMSG_ZC as _;
}

#[inline]
pub unsafe fn io_uring_prep_sendmsg_zc_fixed(sqe: *mut io_uring_sqe, fd: c_int,
                                             msg: *const msghdr, flags: c_uint, buf_index: c_uint)
{
    io_uring_prep_sendmsg_zc(sqe, fd, msg, flags);
    (*sqe).ioprio |= IORING_RECVSEND_FIXED_BUF as u16;
    (*sqe).__liburing_anon_4.buf_index = buf_index as _;
}

#[inline]
pub unsafe fn io_uring_prep_recv(sqe: *mut io_uring_sqe, sockfd: c_int, buf: *mut c_void,
                                 len: usize, flags: c_int)
{
    io_uring_prep_rw(IORING_OP_RECV, sqe, sockfd, buf, len as u32, 0);
    (*sqe).__liburing_anon_3.msg_flags = flags as u32;
}

#[inline]
pub unsafe fn io_uring_prep_recv_multishot(sqe: *mut io_uring_sqe, sockfd: c_int,
                                           buf: *mut c_void, len: usize, flags: c_int)
{
    io_uring_prep_recv(sqe, sockfd, buf, len, flags);
    (*sqe).ioprio |= IORING_RECV_MULTISHOT as u16;
}

#[inline]
pub unsafe fn io_uring_recvmsg_validate(buf: *mut c_void, buf_len: c_int, msgh: *mut msghdr)
                                        -> *mut io_uring_recvmsg_out
{
    let header = (*msgh).msg_controllen
                 + (*msgh).msg_namelen as usize
                 + mem::size_of::<io_uring_recvmsg_out>();

    if buf_len < 0 || (buf_len as usize) < header {
        return ptr::null_mut();
    }

    buf.cast()
}

#[inline]
pub unsafe fn io_uring_recvmsg_name(o: *mut io_uring_recvmsg_out) -> *mut c_void
{
    o.add(1).cast()
}

#[inline]
pub unsafe fn io_uring_recvmsg_cmsg_firsthdr(o: *mut io_uring_recvmsg_out, msgh: *mut msghdr)
                                             -> *mut cmsghdr
{
    if ((*o).controllen as usize) < mem::size_of::<cmsghdr>() {
        return ptr::null_mut();
    }

    io_uring_recvmsg_name(o).cast::<u8>()
                            .add((*msgh).msg_namelen as _)
                            .cast()
}

#[inline]
pub unsafe fn io_uring_recvmsg_cmsg_nexthdr(o: *mut io_uring_recvmsg_out, msgh: *mut msghdr,
                                            cmsg: *mut cmsghdr)
                                            -> *mut cmsghdr
{
    #[allow(non_snake_case)]
    fn CMSG_ALIGN(len: usize) -> usize
    {
        ((len) + mem::size_of::<usize>() - 1) & !(mem::size_of::<usize>() - 1)
    }

    if (*cmsg).cmsg_len < mem::size_of::<cmsghdr>() {
        return ptr::null_mut();
    }

    let end = io_uring_recvmsg_cmsg_firsthdr(o, msgh).cast::<u8>()
                                                     .add((*o).controllen as _);

    let cmsg = cmsg.cast::<u8>()
                   .add(CMSG_ALIGN((*cmsg).cmsg_len))
                   .cast::<cmsghdr>();

    if cmsg.add(1).cast::<u8>() > end {
        return ptr::null_mut();
    }

    if cmsg.cast::<u8>().add(CMSG_ALIGN((*cmsg).cmsg_len)) > end {
        return ptr::null_mut();
    }

    cmsg
}

#[inline]
pub unsafe fn io_uring_recvmsg_payload(o: *mut io_uring_recvmsg_out, msgh: *mut msghdr)
                                       -> *mut c_void
{
    io_uring_recvmsg_name(o).cast::<u8>()
                            .add((*msgh).msg_namelen as usize + (*msgh).msg_controllen)
                            .cast::<c_void>()
}

#[inline]
pub unsafe fn io_uring_recvmsg_payload_length(o: *mut io_uring_recvmsg_out, buf_len: c_int,
                                              msgh: *mut msghdr)
                                              -> c_uint
{
    let payload_start = io_uring_recvmsg_payload(o, msgh) as usize;
    let payload_end = o as usize + buf_len as usize;
    (payload_end - payload_start) as _
}

#[inline]
pub unsafe fn io_uring_prep_openat2(sqe: *mut io_uring_sqe, dfd: c_int, path: *const c_char,
                                    how: *mut open_how)
{
    io_uring_prep_rw(IORING_OP_OPENAT2 as _,
                     sqe,
                     dfd,
                     path.cast(),
                     mem::size_of::<open_how>() as u32,
                     how as usize as u64);
}

/* open directly into the fixed file table */
#[inline]
pub unsafe fn io_uring_prep_openat2_direct(sqe: *mut io_uring_sqe, dfd: c_int,
                                           path: *const c_char, how: *mut open_how,
                                           mut file_index: c_uint)
{
    io_uring_prep_openat2(sqe, dfd, path, how);
    /* offset by 1 for allocation */
    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
pub unsafe fn io_uring_prep_epoll_ctl(sqe: *mut io_uring_sqe, epfd: c_int, fd: c_int, op: c_int,
                                      ev: *mut epoll_event)
{
    io_uring_prep_rw(IORING_OP_EPOLL_CTL, sqe, epfd, ev.cast(), op as u32, u64::from(fd as u32));
}

#[inline]
pub unsafe fn io_uring_prep_provide_buffers(sqe: *mut io_uring_sqe, addr: *mut c_void, len: c_int,
                                            nr: c_int, bgid: c_int, bid: c_int)
{
    io_uring_prep_rw(IORING_OP_PROVIDE_BUFFERS, sqe, nr, addr, len as u32, bid as u64);
    (*sqe).__liburing_anon_4.buf_group = bgid as u16;
}

#[inline]
pub unsafe fn io_uring_prep_remove_buffers(sqe: *mut io_uring_sqe, nr: c_int, bgid: c_int)
{
    io_uring_prep_rw(IORING_OP_REMOVE_BUFFERS, sqe, nr, ptr::null_mut(), 0, 0);
    (*sqe).__liburing_anon_4.buf_group = bgid as u16;
}

#[inline]
pub unsafe fn io_uring_prep_shutdown(sqe: *mut io_uring_sqe, fd: c_int, how: c_int)
{
    io_uring_prep_rw(IORING_OP_SHUTDOWN, sqe, fd, ptr::null_mut(), how as u32, 0);
}

#[inline]
pub unsafe fn io_uring_prep_unlinkat(sqe: *mut io_uring_sqe, dfd: c_int, path: *const c_char,
                                     flags: c_int)
{
    io_uring_prep_rw(IORING_OP_UNLINKAT, sqe, dfd, path.cast(), 0, 0);
    (*sqe).__liburing_anon_3.unlink_flags = flags as u32;
}

#[inline]
pub unsafe fn io_uring_prep_unlink(sqe: *mut io_uring_sqe, path: *const c_char, flags: c_int)
{
    io_uring_prep_unlinkat(sqe, AT_FDCWD, path, flags);
}

#[inline]
pub unsafe fn io_uring_prep_renameat(sqe: *mut io_uring_sqe, olddfd: c_int,
                                     oldpath: *const c_char, newdfd: c_int,
                                     newpath: *const c_char, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_RENAMEAT,
                     sqe,
                     olddfd,
                     oldpath.cast(),
                     newdfd as u32,
                     newpath as usize as u64);
    (*sqe).__liburing_anon_3.rename_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_rename(sqe: *mut io_uring_sqe, oldpath: *const c_char,
                                   newpath: *const c_char)
{
    io_uring_prep_renameat(sqe, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

#[inline]
pub unsafe fn io_uring_prep_sync_file_range(sqe: *mut io_uring_sqe, fd: c_int, len: c_uint,
                                            offset: u64, flags: c_int)
{
    io_uring_prep_rw(IORING_OP_SYNC_FILE_RANGE, sqe, fd, ptr::null_mut(), len, offset);
    (*sqe).__liburing_anon_3.sync_range_flags = flags as u32;
}

#[inline]
pub unsafe fn io_uring_prep_mkdirat(sqe: *mut io_uring_sqe, dfd: c_int, path: *const c_char,
                                    mode: mode_t)
{
    io_uring_prep_rw(IORING_OP_MKDIRAT, sqe, dfd, path.cast(), mode, 0);
}

#[inline]
pub unsafe fn io_uring_prep_mkdir(sqe: *mut io_uring_sqe, path: *const c_char, mode: mode_t)
{
    io_uring_prep_mkdirat(sqe, AT_FDCWD, path, mode);
}

#[inline]
pub unsafe fn io_uring_prep_symlinkat(sqe: *mut io_uring_sqe, target: *const c_char,
                                      newdirfd: c_int, linkpath: *const c_char)
{
    io_uring_prep_rw(IORING_OP_SYMLINKAT,
                     sqe,
                     newdirfd,
                     target.cast(),
                     0,
                     linkpath as usize as u64);
}
#[inline]
pub unsafe fn io_uring_prep_symlink(sqe: *mut io_uring_sqe, target: *const c_char,
                                    linkpath: *const c_char)
{
    io_uring_prep_symlinkat(sqe, target, AT_FDCWD, linkpath);
}

#[inline]
pub unsafe fn io_uring_prep_linkat(sqe: *mut io_uring_sqe, olddfd: c_int, oldpath: *const c_char,
                                   newdfd: c_int, newpath: *const c_char, flags: c_int)
{
    io_uring_prep_rw(IORING_OP_LINKAT,
                     sqe,
                     olddfd,
                     oldpath.cast(),
                     newdfd as u32,
                     newpath as usize as u64);
    (*sqe).__liburing_anon_3.hardlink_flags = flags as u32;
}

#[inline]
pub unsafe fn io_uring_prep_link(sqe: *mut io_uring_sqe, oldpath: *const c_char,
                                 newpath: *const c_char, flags: c_int)
{
    io_uring_prep_linkat(sqe, AT_FDCWD, oldpath, AT_FDCWD, newpath, flags);
}

#[inline]
pub unsafe fn io_uring_prep_msg_ring_cqe_flags(sqe: *mut io_uring_sqe, fd: c_int, len: c_uint,
                                               data: u64, flags: c_uint, cqe_flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_MSG_RING, sqe, fd, ptr::null_mut(), len, data);
    (*sqe).__liburing_anon_3.msg_ring_flags = IORING_MSG_RING_FLAGS_PASS | flags;
    (*sqe).__liburing_anon_5.file_index = cqe_flags;
}

#[inline]
pub unsafe fn io_uring_prep_msg_ring(sqe: *mut io_uring_sqe, fd: c_int, len: c_uint, data: u64,
                                     flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_MSG_RING, sqe, fd, ptr::null_mut(), len, data);
    (*sqe).__liburing_anon_3.msg_ring_flags = IORING_MSG_RING_FLAGS_PASS | flags;
}

#[inline]
pub unsafe fn io_uring_prep_msg_ring_fd(sqe: *mut io_uring_sqe, fd: c_int, source_fd: c_int,
                                        mut target_fd: c_int, data: u64, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_MSG_RING,
                     sqe,
                     fd,
                     IORING_MSG_SEND_FD as usize as *const c_void,
                     0,
                     data);
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = source_fd as _;
    /* offset by 1 for allocation */
    if target_fd == IORING_FILE_INDEX_ALLOC as _ {
        target_fd -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, target_fd as _);
    (*sqe).__liburing_anon_3.msg_ring_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_msg_ring_fd_alloc(sqe: *mut io_uring_sqe, fd: c_int, source_fd: c_int,
                                              data: u64, flags: c_uint)
{
    io_uring_prep_msg_ring_fd(sqe, fd, source_fd, IORING_FILE_INDEX_ALLOC, data, flags);
}

#[inline]
pub unsafe fn io_uring_prep_getxattr(sqe: *mut io_uring_sqe, name: *const c_char,
                                     value: *mut c_char, path: *const c_char, len: c_uint)
{
    io_uring_prep_rw(IORING_OP_GETXATTR, sqe, 0, name.cast(), len, value as usize as u64);
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = path as usize as u64;

    (*sqe).__liburing_anon_3.xattr_flags = 0;
}

#[inline]
pub unsafe fn io_uring_prep_setxattr(sqe: *mut io_uring_sqe, name: *const c_char,
                                     value: *const c_char, path: *const c_char, flags: c_int,
                                     len: c_uint)
{
    io_uring_prep_rw(IORING_OP_SETXATTR, sqe, 0, name.cast(), len, value as usize as u64);
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = path as usize as u64;
    (*sqe).__liburing_anon_3.xattr_flags = flags as _;
}

#[inline]
pub unsafe fn io_uring_prep_fgetxattr(sqe: *mut io_uring_sqe, fd: c_int, name: *const c_char,
                                      value: *mut c_char, len: c_uint)
{
    io_uring_prep_rw(IORING_OP_FGETXATTR, sqe, fd, name.cast(), len, value as usize as u64);
    (*sqe).__liburing_anon_3.xattr_flags = 0;
}

#[inline]
pub unsafe fn io_uring_prep_fsetxattr(sqe: *mut io_uring_sqe, fd: c_int, name: *const c_char,
                                      value: *mut c_char, flags: c_int, len: c_uint)
{
    io_uring_prep_rw(IORING_OP_FSETXATTR, sqe, fd, name.cast(), len, value as usize as u64);
    (*sqe).__liburing_anon_3.xattr_flags = flags as _;
}

#[inline]
pub unsafe fn io_uring_prep_socket(sqe: *mut io_uring_sqe, domain: c_int, r#type: c_int,
                                   protocol: c_int, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_SOCKET,
                     sqe,
                     domain,
                     ptr::null_mut(),
                     protocol as u32,
                     r#type as u64);
    (*sqe).__liburing_anon_3.rw_flags = flags as i32;
}

#[inline]
pub unsafe fn io_uring_prep_socket_direct(sqe: *mut io_uring_sqe, domain: c_int, r#type: c_int,
                                          protocol: c_int, mut file_index: c_uint, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_SOCKET,
                     sqe,
                     domain,
                     ptr::null_mut(),
                     protocol as u32,
                     r#type as u64);
    (*sqe).__liburing_anon_3.rw_flags = flags as i32;
    /* offset by 1 for allocation */
    if file_index == IORING_FILE_INDEX_ALLOC as _ {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

#[inline]
pub unsafe fn io_uring_prep_socket_direct_alloc(sqe: *mut io_uring_sqe, domain: c_int,
                                                r#type: c_int, protocol: c_int, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_SOCKET,
                     sqe,
                     domain,
                     ptr::null_mut(),
                     protocol as u32,
                     r#type as u64);
    (*sqe).__liburing_anon_3.rw_flags = flags as i32;
    __io_uring_set_target_fixed_file(sqe, (IORING_FILE_INDEX_ALLOC - 1) as _);
}

/*
 * Prepare commands for sockets
 */
#[inline]
pub unsafe fn io_uring_prep_cmd_sock(sqe: *mut io_uring_sqe, cmd_op: c_int, fd: c_int,
                                     level: c_int, optname: c_int, optval: *mut c_void,
                                     optlen: c_int)
{
    io_uring_prep_rw(IORING_OP_URING_CMD, sqe, fd, ptr::null_mut(), 0, 0);

    *(*sqe).__liburing_anon_6.optval.as_mut() = optval as usize as _;
    (*sqe).__liburing_anon_2.__liburing_anon_1.optname = optname as _;
    (*sqe).__liburing_anon_5.optlen = optlen as _;
    (*sqe).__liburing_anon_1.__liburing_anon_1.cmd_op = cmd_op as _;
    (*sqe).__liburing_anon_2.__liburing_anon_1.level = level as _;
}

#[inline]
pub unsafe fn io_uring_prep_waitid(sqe: *mut io_uring_sqe, idtype: idtype_t, id: id_t,
                                   infop: *mut siginfo_t, options: c_int, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_WAITID, sqe, id as _, ptr::null_mut(), idtype, 0);
    (*sqe).__liburing_anon_3.waitid_flags = flags;
    (*sqe).__liburing_anon_5.file_index = options as _;
    (*sqe).__liburing_anon_1.addr2 = infop as usize as u64;
}

#[inline]
pub unsafe fn io_uring_prep_futex_wake(sqe: *mut io_uring_sqe, futex: *mut u32, val: u64,
                                       mask: u64, futex_flags: u32, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_FUTEX_WAKE, sqe, futex_flags as _, futex.cast(), 0, val);
    (*sqe).__liburing_anon_3.futex_flags = flags;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = mask;
}

#[inline]
pub unsafe fn io_uring_prep_futex_wait(sqe: *mut io_uring_sqe, futex: *mut u32, val: u64,
                                       mask: u64, futex_flags: u32, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_FUTEX_WAIT, sqe, futex_flags as _, futex.cast(), 0, val);
    (*sqe).__liburing_anon_3.futex_flags = flags;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = mask;
}

#[inline]
pub unsafe fn io_uring_prep_futex_waitv(sqe: *mut io_uring_sqe, futex: *mut futex_waitv,
                                        nr_futex: u32, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_FUTEX_WAITV, sqe, 0, futex.cast(), nr_futex, 0);
    (*sqe).__liburing_anon_3.futex_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_fixed_fd_install(sqe: *mut io_uring_sqe, fd: c_int, flags: c_uint)
{
    io_uring_prep_rw(IORING_OP_FIXED_FD_INSTALL, sqe, fd, ptr::null_mut(), 0, 0);

    (*sqe).flags = IOSQE_FIXED_FILE as _;
    (*sqe).__liburing_anon_3.install_fd_flags = flags;
}

#[inline]
pub unsafe fn io_uring_prep_ftruncate(sqe: *mut io_uring_sqe, fd: c_int, len: c_longlong)
{
    io_uring_prep_rw(IORING_OP_FTRUNCATE, sqe, fd, ptr::null_mut(), 0, len as _);
}

#[inline]
pub unsafe fn io_uring_prep_cmd_discard(sqe: *mut io_uring_sqe, fd: c_int, offset: u64, nbytes: u64)
{
    io_uring_prep_rw(IORING_OP_URING_CMD, sqe, fd, ptr::null_mut(), 0, 0);

    // TODO: really someday fix this
    // We need bindgen to actually evaluate this macro's value during generation.
    // No idea is hard-coding this value like this is viable in practice.
    (*sqe).__liburing_anon_1.__liburing_anon_1.cmd_op = (0x12) << 8; // BLOCK_URING_CMD_DISCARD;
    (*sqe).__liburing_anon_2.addr = offset;
    (*sqe).__liburing_anon_6.__liburing_anon_1.as_mut().addr3 = nbytes;
}

#[inline]
pub unsafe fn io_uring_prep_pipe(sqe: *mut io_uring_sqe, fds: *mut c_int, pipe_flags: c_int)
{
    io_uring_prep_rw(IORING_OP_PIPE, sqe, 0, fds as *const _, 0, 0);
    (*sqe).__liburing_anon_3.pipe_flags = pipe_flags as u32;
}

/* setup pipe directly into the fixed file table */
#[inline]
pub unsafe fn io_uring_prep_pipe_direct(sqe: *mut io_uring_sqe, fds: *mut c_int,
                                        pipe_flags: c_int, mut file_index: c_uint)
{
    io_uring_prep_pipe(sqe, fds, pipe_flags);
    /* offset by 1 for allocation */
    if file_index == IORING_FILE_INDEX_ALLOC as u32 {
        file_index -= 1;
    }
    __io_uring_set_target_fixed_file(sqe, file_index);
}

/* Read the kernel's SQ head index with appropriate memory ordering */
#[inline]
pub unsafe fn io_uring_load_sq_head(ring: *mut io_uring) -> c_uint
{
    /*
     * Without acquire ordering, we could overwrite a SQE before the kernel
     * finished reading it. We don't need the acquire ordering for
     * non-SQPOLL since then we drive updates.
     */
    if (*ring).flags & IORING_SETUP_SQPOLL > 0 {
        return io_uring_smp_load_acquire((*ring).sq.khead);
    }

    *(*ring).sq.khead
}

/*
 * Returns number of unconsumed (if SQPOLL) or unsubmitted entries exist in
 * the SQ ring
 */
#[inline]
pub unsafe fn io_uring_sq_ready(ring: *mut io_uring) -> c_uint
{
    (*ring).sq.sqe_tail - io_uring_load_sq_head(ring)
}

/*
 * Returns how much space is left in the SQ ring.
 */
#[inline]
pub unsafe fn io_uring_sq_space_left(ring: *mut io_uring) -> c_uint
{
    (*ring).sq.ring_entries - io_uring_sq_ready(ring)
}

/*
 * Returns the bit shift needed to index the SQ.
 * This shift is 1 for rings with big SQEs, and 0 for rings with normal SQEs.
 * SQE `index` can be computed as &sq.sqes[(index & sq.ring_mask) << sqe_shift].
 */
#[must_use]
#[inline]
pub fn io_uring_sqe_shift_from_flags(flags: c_uint) -> c_uint
{
    u32::from(flags & IORING_SETUP_SQE128 != 0)
}

#[inline]
pub unsafe fn io_uring_sqe_shift(ring: *mut io_uring) -> c_uint
{
    io_uring_sqe_shift_from_flags((*ring).flags)
}

/*
 * Only applicable when using SQPOLL - allows the caller to wait for space
 * to free up in the SQ ring, which happens when the kernel side thread has
 * consumed one or more entries. If the SQ ring is currently non-full, no
 * action is taken. Note: may return -EINVAL if the kernel doesn't support
 * this feature.
 */
#[inline]
pub unsafe fn io_uring_sqring_wait(ring: *mut io_uring) -> c_int
{
    if (*ring).flags & IORING_SETUP_SQPOLL == 0 {
        return 0;
    }
    if io_uring_sq_space_left(ring) > 0 {
        return 0;
    }

    __io_uring_sqring_wait(ring)
}

/*
 * Returns how many unconsumed entries are ready in the CQ ring
 */
#[inline]
pub unsafe fn io_uring_cq_ready(ring: *mut io_uring) -> c_uint
{
    io_uring_smp_load_acquire((*ring).cq.ktail) - *(*ring).cq.khead
}

/*
 * Returns true if there are overflow entries waiting to be flushed onto
 * the CQ ring
 */
#[inline]
pub unsafe fn io_uring_cq_has_overflow(ring: *mut io_uring) -> bool
{
    IO_URING_READ_ONCE((*ring).sq.kflags) & IORING_SQ_CQ_OVERFLOW > 0
}

/*
 * Returns true if the eventfd notification is currently enabled
 */
#[inline]
pub unsafe fn io_uring_cq_eventfd_enabled(ring: *mut io_uring) -> bool
{
    if (*ring).cq.kflags.is_null() {
        return true;
    }
    (*(*ring).cq.kflags & IORING_CQ_EVENTFD_DISABLED) == 0
}

/*
 * Toggle eventfd notification on or off, if an eventfd is registered with
 * the ring.
 */
#[inline]
pub unsafe fn io_uring_cq_eventfd_toggle(ring: *mut io_uring, enabled: bool) -> c_int
{
    if enabled == io_uring_cq_eventfd_enabled(ring) {
        return 0;
    }

    if (*ring).cq.kflags.is_null() {
        return -(EOPNOTSUPP as c_int);
    }

    let mut flags = *(*ring).cq.kflags;

    if enabled {
        flags &= !IORING_CQ_EVENTFD_DISABLED;
    } else {
        flags |= IORING_CQ_EVENTFD_DISABLED;
    }

    IO_URING_WRITE_ONCE((*ring).cq.kflags, flags);

    0
}

/*
 * Return an IO completion, waiting for 'wait_nr' completions if one isn't
 * readily available. Returns 0 with cqe_ptr filled in on success, -errno on
 * failure.
 */
#[inline]
pub unsafe fn io_uring_wait_cqe_nr(ring: *mut io_uring, cqe_ptr: *mut *mut io_uring_cqe,
                                   wait_nr: c_uint)
                                   -> c_int
{
    __io_uring_get_cqe(ring, cqe_ptr, 0, wait_nr, ptr::null_mut())
}

/*
 * Internal helper, don't use directly in applications. Use one of the
 * "official" versions of this, io_uring_peek_cqe(), io_uring_wait_cqe(),
 * or io_uring_wait_cqes*().
 */
#[inline]
pub unsafe fn __io_uring_peek_cqe(ring: *mut io_uring, cqe_ptr: *mut *mut io_uring_cqe,
                                  nr_available: *mut c_uint)
                                  -> c_int
{
    let mut cqe;
    let mut err = 0;

    let mut available;
    let mask = (*ring).cq.ring_mask;
    let shift = io_uring_cqe_shift(ring);

    loop {
        let tail = io_uring_smp_load_acquire((*ring).cq.ktail);

        /*
         * A load_acquire on the head prevents reordering with the
         * cqe load below, ensuring that we see the correct cq entry.
         */
        let head = io_uring_smp_load_acquire((*ring).cq.khead);

        cqe = ptr::null_mut();
        available = tail - head;
        if available == 0 {
            break;
        }

        cqe = &raw mut *(*ring).cq.cqes.add(((head & mask) << shift) as usize);
        if ((*ring).features & IORING_FEAT_EXT_ARG) == 0
           && (*cqe).user_data == LIBURING_UDATA_TIMEOUT
        {
            if (*cqe).res < 0 {
                err = (*cqe).res;
            }
            io_uring_cq_advance(ring, 1);
            if err == 0 {
                continue;
            }
            cqe = ptr::null_mut();
        }

        break;
    }

    *cqe_ptr = cqe;
    if !nr_available.is_null() {
        *nr_available = available;
    }
    err
}

/*
 * Return an IO completion, if one is readily available. Returns 0 with
 * cqe_ptr filled in on success, -errno on failure.
 */
#[inline]
pub unsafe fn io_uring_peek_cqe(ring: *mut io_uring, cqe_ptr: *mut *mut io_uring_cqe) -> c_int
{
    if __io_uring_peek_cqe(ring, cqe_ptr, ptr::null_mut()) == 0 && !(*cqe_ptr).is_null() {
        return 0;
    }

    io_uring_wait_cqe_nr(ring, cqe_ptr, 0)
}

/*
 * Return an IO completion, waiting for it if necessary. Returns 0 with
 * cqe_ptr filled in on success, -errno on failure.
 */
#[inline]
pub unsafe fn io_uring_wait_cqe(ring: *mut io_uring, cqe_ptr: *mut *mut io_uring_cqe) -> c_int
{
    if __io_uring_peek_cqe(ring, cqe_ptr, ptr::null_mut()) == 0 && !(*cqe_ptr).is_null() {
        return 0;
    }

    io_uring_wait_cqe_nr(ring, cqe_ptr, 1)
}

/*
 * Return an sqe to fill. Application must later call io_uring_submit()
 * when it's ready to tell the kernel about it. The caller may call this
 * function multiple times before calling io_uring_submit().
 *
 * Returns a vacant sqe, or NULL if we're full.
 */
#[inline]
pub unsafe fn _io_uring_get_sqe(ring: *mut io_uring) -> *mut io_uring_sqe
{
    let sq = &raw mut (*ring).sq;

    let head = io_uring_load_sq_head(ring);
    let tail = (*sq).sqe_tail;

    if tail - head >= (*sq).ring_entries {
        return ptr::null_mut();
    }

    let offset = (tail & (*sq).ring_mask) << io_uring_sqe_shift(ring);
    let sqe = (*sq).sqes.add(offset as usize);
    (*sq).sqe_tail = tail + 1;
    io_uring_initialize_sqe(sqe);
    sqe
}

/*
 * Return the appropriate mask for a buffer ring of size 'ring_entries'
 */
#[must_use]
#[inline]
pub fn io_uring_buf_ring_mask(ring_entries: u32) -> c_int
{
    (ring_entries - 1) as _
}

#[inline]
pub unsafe fn io_uring_buf_ring_init(br: *mut io_uring_buf_ring)
{
    (*br).__liburing_anon_1.__liburing_anon_1.as_mut().tail = 0;
}

/*
 * Assign 'buf' with the addr/len/buffer ID supplied
 */
#[inline]
pub unsafe fn io_uring_buf_ring_add(br: *mut io_uring_buf_ring, addr: *mut c_void, len: c_uint,
                                    bid: c_ushort, mask: c_int, buf_offset: c_int)
{
    let tail = (*br).__liburing_anon_1.__liburing_anon_1.as_ref().tail;
    let buf = (*br).__liburing_anon_1
                   .bufs
                   .as_mut()
                   .as_mut_ptr()
                   .add(((i32::from(tail) + buf_offset) & mask) as usize);

    (*buf).addr = addr as usize as u64;
    (*buf).len = len;
    (*buf).bid = bid;
}

/*
 * Make 'count' new buffers visible to the kernel. Called after
 * io_uring_buf_ring_add() has been called 'count' times to fill in new
 * buffers.
 */
#[inline]
pub unsafe fn io_uring_buf_ring_advance(br: *mut io_uring_buf_ring, count: c_int)
{
    let tail = (*br).__liburing_anon_1.__liburing_anon_1.as_ref().tail;
    let new_tail = tail.wrapping_add(count as u16);

    io_uring_smp_store_release(&raw mut (*br).__liburing_anon_1.__liburing_anon_1.as_mut().tail,
                               new_tail);
}

#[inline]
pub unsafe fn __io_uring_buf_ring_cq_advance(ring: *mut io_uring, br: *mut io_uring_buf_ring,
                                             cq_count: i32, buf_count: c_int)
{
    io_uring_buf_ring_advance(br, buf_count);
    io_uring_cq_advance(ring, cq_count as _);
}

/*
 * Make 'count' new buffers visible to the kernel while at the same time
 * advancing the CQ ring seen entries. This can be used when the application
 * is using ring provided buffers and returns buffers while processing CQEs,
 * avoiding an extra atomic when needing to increment both the CQ ring and
 * the ring buffer index at the same time.
 */
#[inline]
pub unsafe fn io_uring_buf_ring_cq_advance(ring: *mut io_uring, br: *mut io_uring_buf_ring,
                                           count: c_int)
{
    __io_uring_buf_ring_cq_advance(ring, br, count, count);
}

#[inline]
pub unsafe fn io_uring_buf_ring_available(ring: *mut io_uring, br: *mut io_uring_buf_ring,
                                          bgid: c_ushort)
                                          -> c_int
{
    let mut head = 0;
    let ret = io_uring_buf_ring_head(ring, bgid.into(), &raw mut head);
    if ret > 0 {
        return ret;
    }
    c_int::from((*br).__liburing_anon_1.__liburing_anon_1.as_mut().tail - head)
}

#[inline]
pub unsafe fn io_uring_get_sqe(ring: *mut io_uring) -> *mut io_uring_sqe
{
    _io_uring_get_sqe(ring)
}

//-----------------------------------------------------------------------------

impl From<Duration> for timespec
{
    #[cfg(not(any(target_arch = "powerpc", target_arch = "arm")))]
    #[inline]
    fn from(duration: Duration) -> Self
    {
        let mut ts = unsafe { zeroed::<timespec>() };
        ts.tv_sec = duration.as_secs() as _;
        ts.tv_nsec = duration.subsec_nanos().into();
        ts
    }

    #[cfg(any(target_arch = "powerpc", target_arch = "arm"))]
    #[inline]
    fn from(duration: Duration) -> Self
    {
        let mut ts = unsafe { zeroed::<timespec>() };
        ts.tv_sec = duration.as_secs() as _;
        ts.tv_nsec = duration.subsec_nanos().try_into().unwrap();
        ts
    }
}

impl From<Duration> for __kernel_timespec
{
    #[inline]
    fn from(duration: Duration) -> Self
    {
        let mut ts = unsafe { zeroed::<__kernel_timespec>() };
        ts.tv_sec = duration.as_secs() as _;
        ts.tv_nsec = duration.subsec_nanos().into();
        ts
    }
}
