Prepare a vectored read using fixed buffers

# DESCRIPTION

The [io_uring_prep_readv_fixed] function prepares a vectored read
request using fixed (registered) buffers. The submission queue entry
*sqe* is setup to use the file descriptor *fd* to start reading
*nr_vecs* iovecs from the file position *offset*.

The *iovecs* argument points to an array of iovec structures describing
the read buffers. All buffers must be part of the registered buffer set
at index *buf_index*, previously registered with
[io_uring_register_buffers].

The *flags* argument can contain any per-request flags, such as
**RWF_NOWAIT** or other flags supported by [preadv2](https://man7.org/linux/man-pages/man2/preadv2.2.html).

Using fixed buffers avoids the overhead of mapping buffers for each I/O
operation, improving performance for applications that reuse the same
buffers.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation, the number
of bytes read on success. On error, a negative errno value is returned.

# NOTES

This function accepts an array of iovec's with a size_t number of bytes
each, but io_uring_cqe's result code is an \_\_s32 value, so in theory a
short read with a large enough iov_len value could generate an ambiguous
return. But the number of bytes actually transferred has the same limit
as [read](https://man7.org/linux/man-pages/man2/read.2.html) so this cannot happen in practice.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_readv], [io_uring_prep_readv2],
[io_uring_prep_read_fixed], [io_uring_prep_writev_fixed],
[io_uring_register_buffers]
