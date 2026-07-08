Prepare a futex wake request

# DESCRIPTION

The [io_uring_prep_futex_wake] function prepares a futex wake
request. The submission queue entry *sqe* is setup for waking any
waiters on the futex indicated by *futex* and at most *val* futexes.
*futex_flags* indicates the [futex2](https://man7.org/linux/man-pages/man2/futex2.2.html) modifier flags, and io_uring
futex flags of *flags .*

If a given bitset for who to wake is desired, then that must be set in
*mask .* Use **FUTEX_BITSET_MATCH_ANY** to match any waiter on the given
futex.

*flags* are currently unused and hence **0** must be passed.

This function prepares an async [futex](https://man7.org/linux/man-pages/man2/futex.2.html) wake request. See that man
page for details. Note that the io_uring futex wake request is similar
to the **FUTEX_WAKE_BITSET** operation, as **FUTEX_WAKE** is a strict
subset of that.

Available since kernel 6.7.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. On
success, the value will be the index into *futexv* which received a
wakeup. See the related man page for details on possible values for
errors. Note that where synchronous system calls will return **-1** on
failure and set *errno* to the actual error value, io_uring never uses
*errno*. Instead it returns the negated *errno* directly in the CQE
*res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_futex_wait], [io_uring_prep_futex_waitv],
[futex](https://man7.org/linux/man-pages/man2/futex.2.html) [futex2](https://man7.org/linux/man-pages/man2/futex2.2.html)
