Prepare a file descriptor close request

# DESCRIPTION

The [io_uring_prep_close] function prepares a close request. The
submission queue entry *sqe* is setup to close the file descriptor
indicated by *fd*.

For a direct descriptor close request, the offset is specified by the
*file_index* argument instead of the *fd*. This is identical to
unregistering the direct descriptor, and is provided as a convenience.
Note that even though it's closing a direct descriptor, the application
must not set **IOSQE_FIXED_FILE** on the SQE. Otherwise the request will
complete with **-EBADF** as the result.

These functions prepare an async [close](https://man7.org/linux/man-pages/man2/close.2.html) request. See that man page
for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. For closing of a direct
descriptor, the only failure cases are the kernel running completely out
of memory, or if the application has specified an invalid direct
descriptor. Note that where synchronous system calls will return **-1**
on failure and set *errno* to the actual error value, io_uring never
uses *errno*. Instead it returns the negated *errno* directly in the CQE
*res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [close](https://man7.org/linux/man-pages/man2/close.2.html)
