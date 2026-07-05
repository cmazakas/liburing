Prepare an openat2 request.

# DESCRIPTION

The [io_uring_prep_openat2] function prepares an openat2 request.
The submission queue entry *sqe* is setup to use the directory file
descriptor *dfd* to start opening a file described by *path* and using
the instructions on how to open the file given in *how*.

If the direct variant is used, the application must first have
registered a file table using [io_uring_register_files] of the
appropriate size. Once registered, a direct request may use any entry in
that table and is specified in *file_index* , as long as it is within
the size of the registered table. If the specified entry already
contains a file, the file will first be removed from the table and
closed. It's consistent with the behavior of updating an existing file
with [io_uring_register_files_update].

If **IORING_FILE_INDEX_ALLOC** is used as the *file_index* for a direct
open, then io_uring will allocate a free direct descriptor in the
existing table. The allocated descriptor is returned in the CQE *res*
field just like it would be for a non-direct open request. If no more
entries are available in the direct descriptor table, **-ENFILE** is
returned instead.

Direct descriptors are io_uring private file descriptors. They avoid
some of the overhead associated with thread shared file tables, and can
be used in any subsequent io_uring request that takes a file descriptor.
To do so, **IOSQE_FIXED_FILE** must be set in the SQE *flags* member,
and the SQE *fd* field should use the direct descriptor value rather
than the regular file descriptor. Direct descriptors are managed like
registered files.

The directory file descriptor *dfd* is always a regular file descriptor.

Note that old kernels don't check the SQE *file_index* field, which is
not a problem for liburing helpers, but users of the raw io_uring
interface need to zero SQEs to avoid unexpected behavior.

These functions prepare an async [openat2] request. See that man
page for details.

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

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register], [openat2]
