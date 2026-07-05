Toggle of iowait usage when waiting on CQEs.

# DESCRIPTION

By default, io_uring marks a waiting task as being in iowait if it's
sleeping waiting on events and there are pending requests. This isn't
necessarily always useful, and may be confusing on non-storage setups
where iowait isn't expected. It can also cause extra power usage by
preventing the CPU from entering lower sleep states.

The [io_uring_set_iowait] function allows the user to toggle this
behavior. If **enable_iowait** is set to true, the iowait behavior is
enabled. If it is set to false, the iowait behavior is disabled. The
iowait behavior is enabled by default when a ring is created.

If the iowait is disabled, the submit functions will set
**IORING_ENTER_NO_IOWAIT** in the **flags** argument to
[io_uring_enter].

If the kernel supports this feature, it will be marked by having the
**IORING_FEAT_NO_IOWAIT** feature flag set.

Available since kernel 6.15.

# RETURN VALUE

On success, [io_uring_set_iowait] returns 0. On failure, it returns
**-EOPNOTSUPP**.

# SEE ALSO

[io_uring_enter], [io_uring_submit],
[io_uring_submit_and_wait]
