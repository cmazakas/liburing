Toggle eventfd notifications on or off

# DESCRIPTION

The [io_uring_cq_eventfd_toggle] function toggles eventfd
notifications for the io_uring instance specified by *ring*. If
*enabled* is **true**, eventfd notifications are enabled. If *enabled*
is **false**, they are disabled.

An eventfd must first be registered with the ring using
[io_uring_register_eventfd] or
[io_uring_register_eventfd_async] before this function can be used.

This can be useful when the application wants to temporarily stop
receiving eventfd notifications, for example during a batch processing
phase.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned:

**-EOPNOTSUPP**  
The kernel does not support toggling eventfd notifications, or no
eventfd is registered.

# SEE ALSO

[io_uring_register_eventfd],
[io_uring_register_eventfd_async],
[io_uring_cq_eventfd_enabled]
