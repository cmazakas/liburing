Wait for free space in the SQ ring

# DESCRIPTION

The function [io_uring_sqring_wait] allows the caller to wait for
space to free up in the SQ ring belonging to the *ring* param, which
happens when the kernel side thread has consumed one or more entries. If
the SQ ring is currently non-full, no action is taken.

This feature can only be used when the ring has been setup with
**IORING_SETUP_SQPOLL** and hence is using an offloaded approach to
request submissions.

# RETURN VALUE

On success it returns the free space. If the kernel does not support the
feature, -EINVAL is returned.

# SEE ALSO

[io_uring_submit], [io_uring_wait_cqe],
[io_uring_wait_cqes]
