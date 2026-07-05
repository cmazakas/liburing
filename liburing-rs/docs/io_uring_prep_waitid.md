Prepare a waitid request.

# DESCRIPTION

The [io_uring_prep_waitid] function prepares a waitid request. The
submission queue entry *sqe* is setup to use the *idtype* and *id*
arguments select the child(ren), and *options* to specify the child
state changes to wait for. Upon successful return, it fills *infop* with
information of the child process, if any. *flags* is io_uring specific
modifier flags. They are currently unused, and hence **0** should be
passed.

This function prepares an async [waitid] request. See that man page
for details.

Available since kernel 6.7.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [waitid]
