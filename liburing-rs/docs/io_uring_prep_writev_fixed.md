Prepare a vectored write using fixed.
buffers

# DESCRIPTION

The [io_uring_prep_writev_fixed] function prepares a vectored write
request using fixed (registered) buffers. The submission queue entry
*sqe* is setup to use the file descriptor *fd* to start writing
*nr_vecs* iovecs from the file position *offset*.

The *iovecs* argument points to an array of iovec structures describing
the write buffers. All buffers must be part of the registered buffer set
at index *buf_index*, previously registered with
[io_uring_register_buffers].

The *flags* argument can contain any per-request flags, such as
**RWF_APPEND** or other flags supported by [pwritev2](https://man7.org/linux/man-pages/man2/readv.2.html).

Using fixed buffers avoids the overhead of mapping buffers for each I/O
operation, improving performance for applications that reuse the same
buffers.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation, the number
of bytes written on success. On error, a negative errno value is
returned.

# NOTES

Despite accepting an array of iovec's with a size_t number of bytes
each, this function can transfer at most INT_MAX bytes per call (the
maximum for the underlying syscall interface).

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_writev], [io_uring_prep_writev2],
[io_uring_prep_write_fixed], [io_uring_prep_readv_fixed],
[io_uring_register_buffers]
