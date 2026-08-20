Prepare a zone_reset_all command

# DESCRIPTION

The [io_uring_prep_cmd_zone_reset_all] function prepares a
zone_reset_all command request. The submission queue entry *sqe* is
setup to reset all sequential write required zones on the block device
pointed to by *fd*.

This command does not synchronize against concurrent file operations,
including but not limited to reads, write, ioctls and other uring_cmds
and only performs a best effort invalidation of the page cache for the
device. The user has to make sure that no other in-flight requests are
modifying or reading the range(s). If that is the case, it might result
in stale page cache and data inconsistencies.

Available since Linux 7.TBD.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. On
success, this field will be set to **0 .** On error, a negative error
value is returned. Note that where synchronous system calls will return
**-1** on failure and set *errno* to the actual error value, io_uring
never uses *errno*. Instead it returns the negated *errno* directly in
the CQE *res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
