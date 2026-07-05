Prepare a futex waitv request.

# DESCRIPTION

The [io_uring_prep_futex_waitv] function prepares a futex wait
request for multiple futexes at the same time. The submission queue
entry *sqe* is setup for waiting on all futexes given by *futexv* and
*nr_futex* is the number of futexes in that array. *flags* must be set
to the io_uring specific futex flags.

Unlike [io_uring_prep_futex_wait], the desired bitset mask and
values are passed in *futexv*.

*flags* are currently unused and hence **0** must be passed.

This function prepares an async [futex](https://man7.org/linux/man-pages/man2/futex.2.html) waitv request. See that man
page for details.

Available since kernel 6.7.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# NOTES

Unlike the sync futex syscalls that wait on a futex, io_uring does not
support passing in a timeout for the request. Instead, applications are
encouraged to use a linked timeout to abort the futex request at a given
time, if desired.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_futex_wait], [io_uring_prep_futex_wake],
[io_uring_prep_link_timeout], [futex](https://man7.org/linux/man-pages/man2/futex.2.html), [futex2](https://man7.org/linux/man-pages/man2/futex.2.html)
