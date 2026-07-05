Prepare a symlinkat request.

# DESCRIPTION

The [io_uring_prep_symlinkat] function prepares a symlinkat
request. The submission queue entry *sqe* is setup to symlink the target
path pointed to by *target* to the new destination indicated by
*newdirfd* and *linkpath*.

The [io_uring_prep_symlink] function prepares a symlink request.
The submission queue entry *sqe* is setup to symlink the target path
pointed to by *target* to the new destination indicated by *linkpath*
relative to the current working directory. This function prepares an
async [symlink] request. See that man page for details.

These functions prepare an async [symlinkat] or [symlink]
request. See those man pages for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# NOTES

As with any request that passes in data in a struct, that data must
remain valid until the request has been successfully submitted. It need
not remain valid until completion. Once a request has been submitted,
the in-kernel state is stable. Very early kernels (5.4 and earlier)
required state to be stable until the completion occurred. Applications
can test for this behavior by inspecting the
**IORING_FEAT_SUBMIT_STABLE** flag passed back from
[io_uring_queue_init_params].

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [symlinkat],
[symlink]
