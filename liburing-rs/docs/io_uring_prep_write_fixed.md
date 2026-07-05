Prepare I/O write request with registered.
buffer

# DESCRIPTION

The [io_uring_prep_write_fixed] prepares an IO write request with a
previously registered IO buffer. The submission queue entry *sqe* is
setup to use the file descriptor *fd* to start writing *nbytes* from the
buffer *buf* at the specified *offset* and with the buffer matching the
registered index of *buf_index*.

This works just like [io_uring_prep_write] except it requires the
use of buffers that have been registered with
[io_uring_register_buffers]. The *buf* and *nbytes* arguments must
fall within a region specified by *buf_index* in the previously
registered buffer. The buffer need not be aligned with the start of the
registered buffer.

After the write has been prepared it can be submitted with one of the
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

Despite accepting an unsigned number of bytes, this function can
transfer at most INT_MAX bytes per call (the maximum for the underlying
syscall interface).

# SEE ALSO

[io_uring_prep_write], [io_uring_register_buffers]
