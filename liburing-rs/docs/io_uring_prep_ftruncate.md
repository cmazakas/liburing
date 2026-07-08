Prepare an ftruncate request

# DESCRIPTION

The [io_uring_prep_ftruncate] function prepares an ftruncate
request. The submission queue entry *sqe* is setup to use the file
descriptor *fd* that should get truncated to the length indicated by the
*len* argument.

Applications must define **\_GNU_SOURCE** to obtain the definition of
this helper, as *loff_t* will not be defined without it.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [ftruncate](https://man7.org/linux/man-pages/man2/ftruncate.2.html),
