Prepare an epoll wait request

# DESCRIPTION

The [io_uring_prep_epoll_wait] function prepares an epoll_wait
request. The submission queue entry *sqe* is setup to wait on a maximum
of *maxevents* events on the epoll file descriptor indicated by *fd*,
and filling the received events into the memory pointed to by *events*.

This function prepares an async [epoll_wait](https://man7.org/linux/man-pages/man2/epoll_wait.2.html) request. See that man
page for details. The use case is mostly for legacy event loops, where
certain file descriptors may still be using epoll for readiness
notifications. Normally this would necessitate using epoll_wait with the
io_uring fd added to that set as well, which is suboptimal as epoll
doesn't provide the same kind of fine grained batch control and wakeup
reductions that io_uring does. By using io_uring to read epoll events,
the event loop can be entirely switched to io_uring, and reap the
benefits of batch waiting and context switch reductions.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [epoll_wait](https://man7.org/linux/man-pages/man2/epoll_wait.2.html)
