Register an eventfd with a ring

# DESCRIPTION

[io_uring_register_eventfd] registers the eventfd file descriptor
*fd* with the ring identified by *ring*.

Whenever completions are posted to the CQ ring, an eventfd notification
is generated with the registered eventfd descriptor. If
[io_uring_register_eventfd_async] is used, only events that
completed out-of-line will trigger a notification.

If notifications are no longer desired,
[io_uring_unregister_eventfd] may be called to remove the eventfd
registration. No eventfd argument is needed, as a ring can only have a
single eventfd registered.

# NOTES

While io_uring generally takes care to avoid spurious events, they can
occur. Similarly, batched completions of CQEs may only trigger a single
eventfd notification even if multiple CQEs are posted. The application
should make no assumptions on number of events being available having a
direct correlation to eventfd notifications posted. An eventfd
notification must thus only be treated as a hint to check the CQ ring
for completions.

# RETURN VALUE

Returns 0 on success, or **-errno** on error.

# SEE ALSO

[eventfd](https://man7.org/linux/man-pages/man2/eventfd.2.html)
