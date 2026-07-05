Prepare I/O read request with registered.
buffer

# DESCRIPTION

The [io_uring_prep_read_fixed] prepares an IO read request with a
previously registered IO buffer. The submission queue entry *sqe* is
setup to use the file descriptor *fd* to start reading *nbytes* into the
buffer *buf* at the specified *offset*, and with the buffer matching the
registered index of *buf_index*.

This works just like [io_uring_prep_read] except it requires the
use of buffers that have been registered with
[io_uring_register_buffers]. The *buf* and *nbytes* arguments must
fall within a region specified by *buf_index* in the previously
registered buffer. The buffer need not be aligned with the start of the
registered buffer.

After the read has been prepared it can be submitted with one of the
submit functions.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# NOTES

This function accepts an unsigned number of bytes, but io_uring_cqe's
result code is an \_\_s32 value, so in theory a short read with a large
enough nbytes value could generate an ambiguous return. But the number
of bytes actually transferred has the same limit as [read](https://man7.org/linux/man-pages/man2/read.2.html) so this
cannot happen in practice.

# SEE ALSO

[io_uring_prep_read], [io_uring_register_buffers]
