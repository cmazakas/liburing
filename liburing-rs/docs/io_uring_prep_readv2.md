Prepare vector I/O read request with flags

# DESCRIPTION

The [io_uring_prep_readv2] prepares a vectored IO read request. The
submission queue entry *sqe* is setup to use the file descriptor *fd* to
start reading *nr_vecs* into the *iovecs* array at the specified
*offset*. The behavior of the function can be controlled with the
*flags* parameter.

Supported values for *flags* are:

**RWF_HIPRI**\
High priority request, poll if possible

**RWF_DSYNC**\
per-IO O_DSYNC

**RWF_SYNC**\
per-IO O_SYNC

**RWF_NOWAIT**\
per-IO, return **-EAGAIN** if operation would block

**RWF_APPEND**\
per-IO O_APPEND

On files that support seeking, if the offset is set to **-1**, the read
operation commences at the file offset, and the file offset is
incremented by the number of bytes read. See [read](https://man7.org/linux/man-pages/man2/read.2.html) for more
details. Note that for an async API, reading and updating the current
file offset may result in unpredictable behavior, unless access to the
file is serialized. It is not encouraged to use this feature, if it's
possible to provide the desired IO offset from the application or
library.

On files that are not capable of seeking, the offset must be 0 or -1.

After the read has been prepared, it can be submitted with one of the
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

Unless an application explicitly needs to pass in more than one iovec,
it is more efficient to use [io_uring_prep_read] rather than this
function, as no state has to be maintained for a non-vectored IO
request. As with any request that passes in data in a struct, that data
must remain valid until the request has been successfully submitted. It
need not remain valid until completion. Once a request has been
submitted, the in-kernel state is stable. Very early kernels (5.4 and
earlier) required state to be stable until the completion occurred.
Applications can test for this behavior by inspecting the
**IORING_FEAT_SUBMIT_STABLE** flag passed back from
[io_uring_queue_init_params].

This function accepts an array of iovec's with a size_t number of bytes
each, but io_uring_cqe's result code is an \_\_s32 value, so in theory a
short read with a large enough iov_len value could generate an ambiguous
return. But the number of bytes actually transferred has the same limit
as [read](https://man7.org/linux/man-pages/man2/read.2.html) so this cannot happen in practice.

# SEE ALSO

[io_uring_get_sqe], [io_uring_prep_read],
[io_uring_prep_readv], [io_uring_submit]
