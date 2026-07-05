Prepare an epoll_ctl request.

# DESCRIPTION

The [io_uring_prep_epoll_ctl] function prepares an epoll control
request. The submission queue entry *sqe* is setup to use the epoll
instance referred to by *epfd*, performing the operation *op* on the
file descriptor *fd*. The *ev* argument points to an *epoll_event*
structure as defined in [epoll_ctl].

The *op* argument can be one of:

**EPOLL_CTL_ADD**\
Add *fd* to the epoll instance.

**EPOLL_CTL_MOD**\
Modify the settings for *fd*.

**EPOLL_CTL_DEL**\
Remove *fd* from the epoll instance. *ev* is ignored for this operation.

This function prepares an async [epoll_ctl] request. See that man
page for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation, 0 on
success. On error, a negative errno value is returned. See
[epoll_ctl] for possible error values.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_epoll_wait], [epoll_ctl]
