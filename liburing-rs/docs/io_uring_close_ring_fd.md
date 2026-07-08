Close a ring file descriptor and use it only
via registered index

# DESCRIPTION

[io_uring_close_ring_fd] closes the ring file descriptor, which
must have been previously registered. The file will remain open, but
accessible only via the registered index, not via any file descriptor.
Subsequent liburing calls will continue to work, using the registered
ring fd.

The kernel must support **IORING_FEAT_REG_REG_RING**.

Libraries that must avoid disrupting their users' uses of file
descriptors, and must continue working even in the face of
[close_range](https://man7.org/linux/man-pages/man2/close_range.2.html) and similar, can use [io_uring_close_ring_fd] to
work with liburing without having any open file descriptor.

# NOTES

Each thread that wants to make use of io_uring must register the fd. A
library that may get called from arbitrary theads may need to detect
when it gets called on a previously unseen thread and create and
register a ring for that thread.

# RETURN VALUE

Returns 1 on success, or **-errno** on error.

# SEE ALSO

[io_uring_register_ring_fd]
