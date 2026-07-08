Check if eventfd notifications are enabled

# DESCRIPTION

The [io_uring_cq_eventfd_enabled] function returns whether eventfd
notifications are currently enabled for the io_uring instance specified
by *ring*.

An eventfd can be registered with a ring using
[io_uring_register_eventfd] or
[io_uring_register_eventfd_async]. Once registered, notifications
can be temporarily disabled using [io_uring_cq_eventfd_toggle].

# RETURN VALUE

Returns **true** if eventfd notifications are enabled, or **false** if
disabled.

# SEE ALSO

[io_uring_register_eventfd],
[io_uring_register_eventfd_async],
[io_uring_cq_eventfd_toggle]
