Prepare I/O write request.

# DESCRIPTION

The [io_uring_prep_write] prepares an IO write request. The
submission queue entry *sqe* is setup to use the file descriptor *fd* to
start writing *nbytes* from the buffer *buf* at the specified *offset*.

On files that support seeking, if the offset is set to **-1**, the write
operation commences at the file offset, and the file offset is
incremented by the number of bytes written. See [write] for more
details. Note that for an async API, reading and updating the current
file offset may result in unpredictable behavior, unless access to the
file is serialized. It is not encouraged to use this feature if it's
possible to provide the desired IO offset from the application or
library.

On files that are not capable of seeking, the offset must be 0 or -1.

After the write has been prepared, it can be submitted with one of the
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

[io_uring_get_sqe], [io_uring_submit]
