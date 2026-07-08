Prepare a futex wait request

# DESCRIPTION

The [io_uring_prep_futex_wait] function prepares a futex wait
request. The submission queue entry *sqe* is setup for waiting on a
futex at address *futex* and which still has the value *val* and with
[futex2](https://man7.org/linux/man-pages/man2/futex2.2.html) flags of *futex_flags* and io_uring futex flags of *flags
.*

*mask* can be set to a specific bitset mask, which will be matched by
the waking side to decide who to wake up. To always get woken, an
application may use **FUTEX_BITSET_MATCH_ANY .**

*futex_flags* follows the [futex2](https://man7.org/linux/man-pages/man2/futex2.2.html) flags, not the [futex](https://man7.org/linux/man-pages/man2/futex.2.html) v1
interface flags.

*flags* are currently unused and hence **0** must be passed.

This function prepares an async [futex](https://man7.org/linux/man-pages/man2/futex.2.html) wait request. See that man
page for details. Note that the io_uring futex wait request is similar
to the **FUTEX_WAIT_BITSET** operation, as **FUTEX_WAIT** is a strict
subset of that.

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
[io_uring_prep_futex_waitv], [io_uring_prep_futex_wake],
[io_uring_prep_link_timeout], [futex](https://man7.org/linux/man-pages/man2/futex.2.html) [futex2](https://man7.org/linux/man-pages/man2/futex2.2.html)
