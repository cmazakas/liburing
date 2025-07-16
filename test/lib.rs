#![allow(clippy::missing_safety_doc, unsafe_op_in_unsafe_fn)]

extern crate liburing_rs;

pub use liburing_rs::{
    __kernel_timespec, AT_FDCWD, cmsghdr, epoll_event, futex_waitv, id_t, idtype_t, io_uring,
    io_uring_buf_ring, io_uring_cqe, io_uring_cqe_iter, io_uring_probe, io_uring_recvmsg_out,
    io_uring_sqe, iovec, mode_t, msghdr, off_t, open_how, siginfo_t, sockaddr, socklen_t, statx,
};

use std::os::raw::{c_char, c_int, c_longlong, c_uint, c_ushort, c_void};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn uring_ptr_to_u64(p: *const c_void) -> u64
{
    liburing_rs::uring_ptr_to_u64(p)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_opcode_supported(p: *mut io_uring_probe, op: c_int) -> c_int
{
    liburing_rs::io_uring_opcode_supported(p, op)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cqe_shift_from_flags(flags: c_uint) -> c_uint
{
    liburing_rs::io_uring_cqe_shift_from_flags(flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cqe_shift(ring: *mut io_uring) -> c_uint
{
    liburing_rs::io_uring_cqe_shift_from_flags((*ring).flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cqe_iter_init(ring: *mut io_uring) -> io_uring_cqe_iter
{
    liburing_rs::io_uring_cqe_iter_init(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cqe_iter_next(iter: *mut io_uring_cqe_iter,
                                                cqe: *mut *mut io_uring_cqe)
                                                -> bool
{
    liburing_rs::io_uring_cqe_iter_next(iter, cqe)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cq_advance(ring: *mut io_uring, nr: c_uint)
{
    liburing_rs::io_uring_cq_advance(ring, nr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cqe_seen(ring: *mut io_uring, cqe: *mut io_uring_cqe)
{
    liburing_rs::io_uring_cqe_seen(ring, cqe)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sqe_set_data(sqe: *mut io_uring_sqe, data: *mut c_void)
{
    liburing_rs::io_uring_sqe_set_data(sqe, data)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cqe_get_data(cqe: *const io_uring_cqe) -> *mut c_void
{
    liburing_rs::io_uring_cqe_get_data(cqe)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sqe_set_data64(sqe: *mut io_uring_sqe, data: u64)
{
    liburing_rs::io_uring_sqe_set_data64(sqe, data)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cqe_get_data64(cqe: *const io_uring_cqe) -> u64
{
    liburing_rs::io_uring_cqe_get_data64(cqe)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sqe_set_flags(sqe: *mut io_uring_sqe, flags: c_uint)
{
    liburing_rs::io_uring_sqe_set_flags(sqe, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sqe_set_buf_group(sqe: *mut io_uring_sqe, bgid: c_int)
{
    liburing_rs::io_uring_sqe_set_buf_group(sqe, bgid)
}

#[unsafe(no_mangle)]
pub unsafe fn __io_uring_set_target_fixed_file(sqe: *mut io_uring_sqe, file_index: c_uint)
{
    liburing_rs::__io_uring_set_target_fixed_file(sqe, file_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_rw(op: c_int, sqe: *mut io_uring_sqe, fd: c_int,
                                          addr: *const c_void, len: c_uint, offset: u64)
{
    liburing_rs::io_uring_prep_rw(op as _, sqe, fd, addr, len, offset)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_splice(sqe: *mut io_uring_sqe, fd_in: c_int, off_in: i64,
                                              fd_out: c_int, off_out: i64, nbytes: c_uint,
                                              splice_flags: c_uint)
{
    liburing_rs::io_uring_prep_splice(sqe, fd_in, off_in, fd_out, off_out, nbytes, splice_flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_tee(sqe: *mut io_uring_sqe, fd_in: c_int, fd_out: c_int,
                                           nbytes: c_uint, splice_flags: c_uint)
{
    liburing_rs::io_uring_prep_tee(sqe, fd_in, fd_out, nbytes, splice_flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_readv(sqe: *mut io_uring_sqe, fd: c_int,
                                             iovecs: *const iovec, nr_vecs: c_uint, offset: u64)
{
    liburing_rs::io_uring_prep_readv(sqe, fd, iovecs, nr_vecs, offset)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_readv2(sqe: *mut io_uring_sqe, fd: c_int,
                                              iovecs: *const iovec, nr_vecs: c_uint, offset: u64,
                                              flags: c_int)
{
    liburing_rs::io_uring_prep_readv2(sqe, fd, iovecs, nr_vecs, offset, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_read_fixed(sqe: *mut io_uring_sqe, fd: c_int,
                                                  buf: *mut c_void, nbytes: c_uint, offset: u64,
                                                  buf_index: c_int)
{
    liburing_rs::io_uring_prep_read_fixed(sqe, fd, buf, nbytes, offset, buf_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_readv_fixed(sqe: *mut io_uring_sqe, fd: c_int,
                                                   iovecs: *const iovec, nr_vecs: c_uint,
                                                   offset: u64, flags: c_int, buf_index: c_int)
{
    liburing_rs::io_uring_prep_readv_fixed(sqe, fd, iovecs, nr_vecs, offset, flags, buf_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_writev(sqe: *mut io_uring_sqe, fd: c_int,
                                              iovecs: *const iovec, nr_vecs: c_uint, offset: u64)
{
    liburing_rs::io_uring_prep_writev(sqe, fd, iovecs, nr_vecs, offset)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_writev2(sqe: *mut io_uring_sqe, fd: c_int,
                                               iovecs: *const iovec, nr_vecs: c_uint, offset: u64,
                                               flags: c_int)
{
    liburing_rs::io_uring_prep_writev2(sqe, fd, iovecs, nr_vecs, offset, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_write_fixed(sqe: *mut io_uring_sqe, fd: c_int,
                                                   buf: *const c_void, nbytes: c_uint,
                                                   offset: u64, buf_index: c_int)
{
    liburing_rs::io_uring_prep_write_fixed(sqe, fd, buf, nbytes, offset, buf_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_writev_fixed(sqe: *mut io_uring_sqe, fd: c_int,
                                                    iovecs: *const iovec, nr_vecs: c_uint,
                                                    offset: u64, flags: c_int, buf_index: c_int)
{
    liburing_rs::io_uring_prep_writev_fixed(sqe, fd, iovecs, nr_vecs, offset, flags, buf_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_recvmsg(sqe: *mut io_uring_sqe, fd: c_int,
                                               msg: *mut msghdr, flags: c_uint)
{
    liburing_rs::io_uring_prep_recvmsg(sqe, fd, msg, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_recvmsg_multishot(sqe: *mut io_uring_sqe, fd: c_int,
                                                         msg: *mut msghdr, flags: c_uint)
{
    liburing_rs::io_uring_prep_recvmsg_multishot(sqe, fd, msg, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_sendmsg(sqe: *mut io_uring_sqe, fd: c_int,
                                               msg: *const msghdr, flags: c_uint)
{
    liburing_rs::io_uring_prep_sendmsg(sqe, fd, msg, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_poll_add(sqe: *mut io_uring_sqe, fd: c_int,
                                                poll_mask: c_uint)
{
    liburing_rs::io_uring_prep_poll_add(sqe, fd, poll_mask)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_poll_multishot(sqe: *mut io_uring_sqe, fd: c_int,
                                                      poll_mask: c_uint)
{
    liburing_rs::io_uring_prep_poll_multishot(sqe, fd, poll_mask)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_poll_remove(sqe: *mut io_uring_sqe, user_data: u64)
{
    liburing_rs::io_uring_prep_poll_remove(sqe, user_data)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_poll_update(sqe: *mut io_uring_sqe, old_user_data: u64,
                                                   new_user_data: u64, poll_mask: c_uint,
                                                   flags: c_uint)
{
    liburing_rs::io_uring_prep_poll_update(sqe, old_user_data, new_user_data, poll_mask, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_fsync(sqe: *mut io_uring_sqe, fd: c_int, fsync_flags: c_uint)
{
    liburing_rs::io_uring_prep_fsync(sqe, fd, fsync_flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_nop(sqe: *mut io_uring_sqe)
{
    liburing_rs::io_uring_prep_nop(sqe)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_timeout(sqe: *mut io_uring_sqe, ts: *mut __kernel_timespec,
                                               count: c_uint, flags: c_uint)
{
    liburing_rs::io_uring_prep_timeout(sqe, ts, count, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_timeout_remove(sqe: *mut io_uring_sqe, user_data: u64,
                                                      flags: c_uint)
{
    liburing_rs::io_uring_prep_timeout_remove(sqe, user_data, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_timeout_update(sqe: *mut io_uring_sqe,
                                                      ts: *mut __kernel_timespec, user_data: u64,
                                                      flags: c_uint)
{
    liburing_rs::io_uring_prep_timeout_update(sqe, ts, user_data, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_accept(sqe: *mut io_uring_sqe, fd: c_int,
                                              addr: *mut sockaddr, addrlen: *mut socklen_t,
                                              flags: c_int)
{
    liburing_rs::io_uring_prep_accept(sqe, fd, addr, addrlen, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_accept_direct(sqe: *mut io_uring_sqe, fd: c_int,
                                                     addr: *mut sockaddr, addrlen: *mut socklen_t,
                                                     flags: c_int, file_index: c_uint)
{
    liburing_rs::io_uring_prep_accept_direct(sqe, fd, addr, addrlen, flags, file_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_multishot_accept(sqe: *mut io_uring_sqe, fd: c_int,
                                                        addr: *mut sockaddr,
                                                        addrlen: *mut socklen_t, flags: c_int)
{
    liburing_rs::io_uring_prep_multishot_accept(sqe, fd, addr, addrlen, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_multishot_accept_direct(sqe: *mut io_uring_sqe, fd: c_int,
                                                               addr: *mut sockaddr,
                                                               addrlen: *mut socklen_t,
                                                               flags: c_int)
{
    liburing_rs::io_uring_prep_multishot_accept_direct(sqe, fd, addr, addrlen, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_cancel64(sqe: *mut io_uring_sqe, user_data: u64,
                                                flags: c_int)
{
    liburing_rs::io_uring_prep_cancel64(sqe, user_data, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_cancel(sqe: *mut io_uring_sqe, user_data: *mut c_void,
                                              flags: c_int)
{
    liburing_rs::io_uring_prep_cancel(sqe, user_data, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_cancel_fd(sqe: *mut io_uring_sqe, fd: c_int, flags: c_uint)
{
    liburing_rs::io_uring_prep_cancel_fd(sqe, fd, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_link_timeout(sqe: *mut io_uring_sqe,
                                                    ts: *mut __kernel_timespec, flags: c_uint)
{
    liburing_rs::io_uring_prep_link_timeout(sqe, ts, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_connect(sqe: *mut io_uring_sqe, fd: c_int,
                                               addr: *const sockaddr, addrlen: socklen_t)
{
    liburing_rs::io_uring_prep_connect(sqe, fd, addr, addrlen)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_bind(sqe: *mut io_uring_sqe, fd: c_int,
                                            addr: *mut sockaddr, addrlen: socklen_t)
{
    liburing_rs::io_uring_prep_bind(sqe, fd, addr, addrlen)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_listen(sqe: *mut io_uring_sqe, fd: c_int, backlog: c_int)
{
    liburing_rs::io_uring_prep_listen(sqe, fd, backlog)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_epoll_wait(sqe: *mut io_uring_sqe, fd: c_int,
                                                  events: *mut epoll_event, maxevents: c_int,
                                                  flags: c_uint)
{
    liburing_rs::io_uring_prep_epoll_wait(sqe, fd, events, maxevents, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_files_update(sqe: *mut io_uring_sqe, fds: *mut c_int,
                                                    nr_fds: c_uint, offset: c_int)
{
    liburing_rs::io_uring_prep_files_update(sqe, fds, nr_fds, offset)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_fallocate(sqe: *mut io_uring_sqe, fd: c_int, mode: c_int,
                                                 offset: u64, len: u64)
{
    liburing_rs::io_uring_prep_fallocate(sqe, fd, mode, offset, len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_openat(sqe: *mut io_uring_sqe, dfd: c_int,
                                              path: *const c_char, flags: c_int, mode: mode_t)
{
    liburing_rs::io_uring_prep_openat(sqe, dfd, path, flags, mode)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_openat_direct(sqe: *mut io_uring_sqe, dfd: c_int,
                                                     path: *const c_char, flags: c_int,
                                                     mode: mode_t, file_index: c_uint)
{
    liburing_rs::io_uring_prep_openat_direct(sqe, dfd, path, flags, mode, file_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_open(sqe: *mut io_uring_sqe, path: *const c_char,
                                            flags: c_int, mode: mode_t)
{
    liburing_rs::io_uring_prep_open(sqe, path, flags, mode)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_open_direct(sqe: *mut io_uring_sqe, path: *const c_char,
                                                   flags: c_int, mode: mode_t, file_index: c_uint)
{
    liburing_rs::io_uring_prep_open_direct(sqe, path, flags, mode, file_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_close(sqe: *mut io_uring_sqe, fd: c_int)
{
    liburing_rs::io_uring_prep_close(sqe, fd)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_close_direct(sqe: *mut io_uring_sqe, file_index: c_uint)
{
    liburing_rs::io_uring_prep_close_direct(sqe, file_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_read(sqe: *mut io_uring_sqe, fd: c_int, buf: *mut c_void,
                                            nbytes: c_uint, offset: u64)
{
    liburing_rs::io_uring_prep_read(sqe, fd, buf, nbytes, offset)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_read_multishot(sqe: *mut io_uring_sqe, fd: c_int,
                                                      nbytes: c_uint, offset: u64,
                                                      buf_group: c_int)
{
    liburing_rs::io_uring_prep_read_multishot(sqe, fd, nbytes, offset, buf_group)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_write(sqe: *mut io_uring_sqe, fd: c_int,
                                             buf: *const c_void, nbytes: c_uint, offset: u64)
{
    liburing_rs::io_uring_prep_write(sqe, fd, buf, nbytes, offset)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_statx(sqe: *mut io_uring_sqe, dfd: c_int,
                                             path: *const c_char, flags: c_int, mask: c_uint,
                                             statxbuf: *mut statx)
{
    liburing_rs::io_uring_prep_statx(sqe, dfd, path, flags, mask, statxbuf)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_fadvise(sqe: *mut io_uring_sqe, fd: c_int, offset: u64,
                                               len: u32, advice: c_int)
{
    liburing_rs::io_uring_prep_fadvise(sqe, fd, offset, len, advice)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_madvise(sqe: *mut io_uring_sqe, addr: *mut c_void,
                                               length: u32, advice: c_int)
{
    liburing_rs::io_uring_prep_madvise(sqe, addr, length, advice)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_fadvise64(sqe: *mut io_uring_sqe, fd: c_int, offset: u64,
                                                 len: off_t, advice: c_int)
{
    liburing_rs::io_uring_prep_fadvise64(sqe, fd, offset, len, advice)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_madvise64(sqe: *mut io_uring_sqe, addr: *mut c_void,
                                                 length: off_t, advice: c_int)
{
    liburing_rs::io_uring_prep_madvise64(sqe, addr, length, advice)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_send(sqe: *mut io_uring_sqe, sockfd: c_int,
                                            buf: *const c_void, len: usize, flags: c_int)
{
    liburing_rs::io_uring_prep_send(sqe, sockfd, buf, len, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_send_bundle(sqe: *mut io_uring_sqe, sockfd: c_int,
                                                   len: usize, flags: c_int)
{
    liburing_rs::io_uring_prep_send_bundle(sqe, sockfd, len, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_send_set_addr(sqe: *mut io_uring_sqe,
                                                     dest_addr: *const sockaddr, addr_len: u16)
{
    liburing_rs::io_uring_prep_send_set_addr(sqe, dest_addr, addr_len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_sendto(sqe: *mut io_uring_sqe, sockfd: c_int,
                                              buf: *const c_void, len: usize, flags: c_int,
                                              addr: *const sockaddr, addrlen: socklen_t)
{
    liburing_rs::io_uring_prep_sendto(sqe, sockfd, buf, len, flags, addr, addrlen)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_send_zc(sqe: *mut io_uring_sqe, sockfd: c_int,
                                               buf: *const c_void, len: usize, flags: c_int,
                                               zc_flags: c_uint)
{
    liburing_rs::io_uring_prep_send_zc(sqe, sockfd, buf, len, flags, zc_flags)
}

pub unsafe extern "C" fn io_uring_prep_send_zc_fixed(sqe: *mut io_uring_sqe, sockfd: c_int,
                                                     buf: *const c_void, len: usize, flags: c_int,
                                                     zc_flags: c_uint, buf_index: c_uint)
{
    liburing_rs::io_uring_prep_send_zc_fixed(sqe, sockfd, buf, len, flags, zc_flags, buf_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_sendmsg_zc(sqe: *mut io_uring_sqe, fd: c_int,
                                                  msg: *const msghdr, flags: c_uint)
{
    liburing_rs::io_uring_prep_sendmsg_zc(sqe, fd, msg, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_sendmsg_zc_fixed(sqe: *mut io_uring_sqe, fd: c_int,
                                                        msg: *const msghdr, flags: c_uint,
                                                        buf_index: c_uint)
{
    liburing_rs::io_uring_prep_sendmsg_zc_fixed(sqe, fd, msg, flags, buf_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_recv(sqe: *mut io_uring_sqe, sockfd: c_int,
                                            buf: *mut c_void, len: usize, flags: c_int)
{
    liburing_rs::io_uring_prep_recv(sqe, sockfd, buf, len, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_recv_multishot(sqe: *mut io_uring_sqe, sockfd: c_int,
                                                      buf: *mut c_void, len: usize, flags: c_int)
{
    liburing_rs::io_uring_prep_recv_multishot(sqe, sockfd, buf, len, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_recvmsg_validate(buf: *mut c_void, buf_len: c_int,
                                                   msgh: *mut msghdr)
                                                   -> *mut io_uring_recvmsg_out
{
    liburing_rs::io_uring_recvmsg_validate(buf, buf_len, msgh)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_recvmsg_name(o: *mut io_uring_recvmsg_out) -> *mut c_void
{
    liburing_rs::io_uring_recvmsg_name(o)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_recvmsg_cmsg_firsthdr(o: *mut io_uring_recvmsg_out,
                                                        msgh: *mut msghdr)
                                                        -> *mut cmsghdr
{
    liburing_rs::io_uring_recvmsg_cmsg_firsthdr(o, msgh)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_recvmsg_cmsg_nexthdr(o: *mut io_uring_recvmsg_out,
                                                       msgh: *mut msghdr, cmsg: *mut cmsghdr)
                                                       -> *mut cmsghdr
{
    liburing_rs::io_uring_recvmsg_cmsg_nexthdr(o, msgh, cmsg)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_recvmsg_payload(o: *mut io_uring_recvmsg_out, msgh: *mut msghdr)
                                                  -> *mut c_void
{
    liburing_rs::io_uring_recvmsg_payload(o, msgh)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_recvmsg_payload_length(o: *mut io_uring_recvmsg_out,
                                                         buf_len: c_int, msgh: *mut msghdr)
                                                         -> c_uint
{
    liburing_rs::io_uring_recvmsg_payload_length(o, buf_len, msgh)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_openat2(sqe: *mut io_uring_sqe, dfd: c_int,
                                               path: *const c_char, how: *mut open_how)
{
    liburing_rs::io_uring_prep_openat2(sqe, dfd, path, how)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_openat2_direct(sqe: *mut io_uring_sqe, dfd: c_int,
                                                      path: *const c_char, how: *mut open_how,
                                                      file_index: c_uint)
{
    liburing_rs::io_uring_prep_openat2_direct(sqe, dfd, path, how, file_index)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_epoll_ctl(sqe: *mut io_uring_sqe, epfd: c_int, fd: c_int,
                                                 op: c_int, ev: *mut epoll_event)
{
    liburing_rs::io_uring_prep_epoll_ctl(sqe, epfd, fd, op, ev)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_provide_buffers(sqe: *mut io_uring_sqe, addr: *mut c_void,
                                                       len: c_int, nr: c_int, bgid: c_int,
                                                       bid: c_int)
{
    liburing_rs::io_uring_prep_provide_buffers(sqe, addr, len, nr, bgid, bid)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_remove_buffers(sqe: *mut io_uring_sqe, nr: c_int,
                                                      bgid: c_int)
{
    liburing_rs::io_uring_prep_remove_buffers(sqe, nr, bgid)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_shutdown(sqe: *mut io_uring_sqe, fd: c_int, how: c_int)
{
    liburing_rs::io_uring_prep_shutdown(sqe, fd, how)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_unlinkat(sqe: *mut io_uring_sqe, dfd: c_int,
                                                path: *const c_char, flags: c_int)
{
    liburing_rs::io_uring_prep_unlinkat(sqe, dfd, path, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_unlink(sqe: *mut io_uring_sqe, path: *const c_char,
                                              flags: c_int)
{
    liburing_rs::io_uring_prep_unlink(sqe, path, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_renameat(sqe: *mut io_uring_sqe, olddfd: c_int,
                                                oldpath: *const c_char, newdfd: c_int,
                                                newpath: *const c_char, flags: c_uint)
{
    liburing_rs::io_uring_prep_renameat(sqe, olddfd, oldpath, newdfd, newpath, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_rename(sqe: *mut io_uring_sqe, oldpath: *const c_char,
                                              newpath: *const c_char)
{
    liburing_rs::io_uring_prep_renameat(sqe, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_sync_file_range(sqe: *mut io_uring_sqe, fd: c_int,
                                                       len: c_uint, offset: u64, flags: c_int)
{
    liburing_rs::io_uring_prep_sync_file_range(sqe, fd, len, offset, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_mkdirat(sqe: *mut io_uring_sqe, dfd: c_int,
                                               path: *const c_char, mode: mode_t)
{
    liburing_rs::io_uring_prep_mkdirat(sqe, dfd, path, mode)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_mkdir(sqe: *mut io_uring_sqe, path: *const c_char,
                                             mode: mode_t)
{
    liburing_rs::io_uring_prep_mkdir(sqe, path, mode)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_symlinkat(sqe: *mut io_uring_sqe, target: *const c_char,
                                                 newdirfd: c_int, linkpath: *const c_char)
{
    liburing_rs::io_uring_prep_symlinkat(sqe, target, newdirfd, linkpath)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_symlink(sqe: *mut io_uring_sqe, target: *const c_char,
                                               linkpath: *const c_char)
{
    liburing_rs::io_uring_prep_symlink(sqe, target, linkpath)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_linkat(sqe: *mut io_uring_sqe, olddfd: c_int,
                                              oldpath: *const c_char, newdfd: c_int,
                                              newpath: *const c_char, flags: c_int)
{
    liburing_rs::io_uring_prep_linkat(sqe, olddfd, oldpath, newdfd, newpath, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_link(sqe: *mut io_uring_sqe, oldpath: *const c_char,
                                            newpath: *const c_char, flags: c_int)
{
    liburing_rs::io_uring_prep_link(sqe, oldpath, newpath, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_msg_ring_cqe_flags(sqe: *mut io_uring_sqe, fd: c_int,
                                                          len: c_uint, data: u64, flags: c_uint,
                                                          cqe_flags: c_uint)
{
    liburing_rs::io_uring_prep_msg_ring_cqe_flags(sqe, fd, len, data, flags, cqe_flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_msg_ring(sqe: *mut io_uring_sqe, fd: c_int, len: c_uint,
                                                data: u64, flags: c_uint)
{
    liburing_rs::io_uring_prep_msg_ring(sqe, fd, len, data, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_msg_ring_fd(sqe: *mut io_uring_sqe, fd: c_int,
                                                   source_fd: c_int, target_fd: c_int, data: u64,
                                                   flags: c_uint)
{
    liburing_rs::io_uring_prep_msg_ring_fd(sqe, fd, source_fd, target_fd, data, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_msg_ring_fd_alloc(sqe: *mut io_uring_sqe, fd: c_int,
                                                         source_fd: c_int, data: u64,
                                                         flags: c_uint)
{
    liburing_rs::io_uring_prep_msg_ring_fd_alloc(sqe, fd, source_fd, data, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_getxattr(sqe: *mut io_uring_sqe, name: *const c_char,
                                                value: *mut c_char, path: *const c_char,
                                                len: c_uint)
{
    liburing_rs::io_uring_prep_getxattr(sqe, name, value, path, len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_setxattr(sqe: *mut io_uring_sqe, name: *const c_char,
                                                value: *const c_char, path: *const c_char,
                                                flags: c_int, len: c_uint)
{
    liburing_rs::io_uring_prep_setxattr(sqe, name, value, path, flags, len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_fgetxattr(sqe: *mut io_uring_sqe, fd: c_int,
                                                 name: *const c_char, value: *mut c_char,
                                                 len: c_uint)
{
    liburing_rs::io_uring_prep_fgetxattr(sqe, fd, name, value, len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_fsetxattr(sqe: *mut io_uring_sqe, fd: c_int,
                                                 name: *const c_char, value: *mut c_char,
                                                 flags: c_int, len: c_uint)
{
    liburing_rs::io_uring_prep_fsetxattr(sqe, fd, name, value, flags, len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_socket(sqe: *mut io_uring_sqe, domain: c_int,
                                              r#type: c_int, protocol: c_int, flags: c_uint)
{
    liburing_rs::io_uring_prep_socket(sqe, domain, r#type, protocol, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_socket_direct(sqe: *mut io_uring_sqe, domain: c_int,
                                                     r#type: c_int, protocol: c_int,
                                                     file_index: c_uint, flags: c_uint)
{
    liburing_rs::io_uring_prep_socket_direct(sqe, domain, r#type, protocol, file_index, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_socket_direct_alloc(sqe: *mut io_uring_sqe, domain: c_int,
                                                           r#type: c_int, protocol: c_int,
                                                           flags: c_uint)
{
    liburing_rs::io_uring_prep_socket_direct_alloc(sqe, domain, r#type, protocol, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_cmd_sock(sqe: *mut io_uring_sqe, cmd_op: c_int, fd: c_int,
                                                level: c_int, optname: c_int, optval: *mut c_void,
                                                optlen: c_int)
{
    liburing_rs::io_uring_prep_cmd_sock(sqe, cmd_op, fd, level, optname, optval, optlen)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_waitid(sqe: *mut io_uring_sqe, idtype: idtype_t, id: id_t,
                                              infop: *mut siginfo_t, options: c_int, flags: c_uint)
{
    liburing_rs::io_uring_prep_waitid(sqe, idtype, id, infop, options, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_futex_wake(sqe: *mut io_uring_sqe, futex: *mut u32,
                                                  val: u64, mask: u64, futex_flags: u32,
                                                  flags: c_uint)
{
    liburing_rs::io_uring_prep_futex_wake(sqe, futex, val, mask, futex_flags, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_futex_wait(sqe: *mut io_uring_sqe, futex: *mut u32,
                                                  val: u64, mask: u64, futex_flags: u32,
                                                  flags: c_uint)
{
    liburing_rs::io_uring_prep_futex_wait(sqe, futex, val, mask, futex_flags, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_futex_waitv(sqe: *mut io_uring_sqe,
                                                   futex: *mut futex_waitv, nr_futex: u32,
                                                   flags: c_uint)
{
    liburing_rs::io_uring_prep_futex_waitv(sqe, futex, nr_futex, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_fixed_fd_install(sqe: *mut io_uring_sqe, fd: c_int,
                                                        flags: c_uint)
{
    liburing_rs::io_uring_prep_fixed_fd_install(sqe, fd, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_ftruncate(sqe: *mut io_uring_sqe, fd: c_int, len: c_longlong)
{
    liburing_rs::io_uring_prep_ftruncate(sqe, fd, len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_prep_cmd_discard(sqe: *mut io_uring_sqe, fd: c_int, offset: u64,
                                                   nbytes: u64)
{
    liburing_rs::io_uring_prep_cmd_discard(sqe, fd, offset, nbytes)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_load_sq_head(ring: *mut io_uring) -> c_uint
{
    liburing_rs::io_uring_load_sq_head(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sq_ready(ring: *mut io_uring) -> c_uint
{
    liburing_rs::io_uring_sq_ready(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sq_space_left(ring: *mut io_uring) -> c_uint
{
    liburing_rs::io_uring_sq_space_left(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sqe_shift_from_flags(flags: c_uint) -> c_uint
{
    liburing_rs::io_uring_sqe_shift_from_flags(flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sqe_shift(ring: *mut io_uring) -> c_uint
{
    liburing_rs::io_uring_sqe_shift(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_sqring_wait(ring: *mut io_uring) -> c_int
{
    liburing_rs::io_uring_sqring_wait(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cq_ready(ring: *mut io_uring) -> c_uint
{
    liburing_rs::io_uring_cq_ready(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cq_has_overflow(ring: *mut io_uring) -> bool
{
    liburing_rs::io_uring_cq_has_overflow(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cq_eventfd_enabled(ring: *mut io_uring) -> bool
{
    liburing_rs::io_uring_cq_eventfd_enabled(ring)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_cq_eventfd_toggle(ring: *mut io_uring, enabled: bool) -> c_int
{
    liburing_rs::io_uring_cq_eventfd_toggle(ring, enabled)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_wait_cqe_nr(ring: *mut io_uring,
                                              cqe_ptr: *mut *mut io_uring_cqe, wait_nr: c_uint)
                                              -> c_int
{
    liburing_rs::io_uring_wait_cqe_nr(ring, cqe_ptr, wait_nr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_peek_cqe(ring: *mut io_uring, cqe_ptr: *mut *mut io_uring_cqe)
                                           -> c_int
{
    liburing_rs::io_uring_peek_cqe(ring, cqe_ptr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_wait_cqe(ring: *mut io_uring, cqe_ptr: *mut *mut io_uring_cqe)
                                           -> c_int
{
    liburing_rs::io_uring_wait_cqe(ring, cqe_ptr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_buf_ring_mask(ring_entries: u32) -> c_int
{
    liburing_rs::io_uring_buf_ring_mask(ring_entries) as _
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_buf_ring_init(br: *mut io_uring_buf_ring)
{
    liburing_rs::io_uring_buf_ring_init(br)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_buf_ring_add(br: *mut io_uring_buf_ring, addr: *mut c_void,
                                               len: c_uint, bid: c_ushort, mask: c_int,
                                               buf_offset: c_int)
{
    liburing_rs::io_uring_buf_ring_add(br, addr, len, bid, mask, buf_offset)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_buf_ring_advance(br: *mut io_uring_buf_ring, count: c_int)
{
    liburing_rs::io_uring_buf_ring_advance(br, count)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_buf_ring_cq_advance(ring: *mut io_uring,
                                                      br: *mut io_uring_buf_ring, count: c_int)
{
    liburing_rs::io_uring_buf_ring_cq_advance(ring, br, count)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_buf_ring_available(ring: *mut io_uring,
                                                     br: *mut io_uring_buf_ring, bgid: c_ushort)
                                                     -> c_int
{
    liburing_rs::io_uring_buf_ring_available(ring, br, bgid)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_uring_get_sqe(ring: *mut io_uring) -> *mut io_uring_sqe
{
    liburing_rs::io_uring_get_sqe(ring)
}
