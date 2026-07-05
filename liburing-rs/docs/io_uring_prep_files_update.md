Prepare a registered file update request.

# DESCRIPTION

The [io_uring_prep_files_update] function prepares a request for
updating a number of previously registered file descriptors. The
submission queue entry *sqe* is setup to use the file descriptor array
pointed to by *fds* and of *nr_fds* in length to update that amount of
previously registered files starting at offset *offset*.

Once a previously registered file is updated with a new one, the
existing entry is updated and then removed from the table. This
operation is equivalent to first unregistering that entry and then
inserting a new one, just bundled into one combined operation.

If *offset* is specified as IORING_FILE_INDEX_ALLOC, io_uring will
allocate free direct descriptors instead of having the application to
pass, and store allocated direct descriptors into *fds* array,
*cqe-\>res* will return the number of direct descriptors allocated.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, *res* will contain the number of successfully updated file
descriptors. On error, the following errors can occur.

**-ENOMEM**\
The kernel was unable to allocate memory for the request.

**-EINVAL**\
One of the fields set in the SQE was invalid.

**-EFAULT**\
The kernel was unable to copy in the memory pointed to by *fds*.

**-EBADF**\
On of the descriptors located in *fds* didn't refer to a valid file
descriptor, or one of the file descriptors in the array referred to an
io_uring instance.

**-EOVERFLOW**\
The product of *offset* and *nr_fds* exceed the valid amount or
overflowed.

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
[io_uring_register]
