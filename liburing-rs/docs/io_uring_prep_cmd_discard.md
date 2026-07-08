Prepare a discard command

# DESCRIPTION

The [io_uring_prep_cmd_discard] function prepares a discard command
request. The submission queue entry *sqe* is setup to use the file
descriptor *fd* to start discarding *nbytes* at the specified *offset*.

The command is an asynchronous equivalent of **BLOCK_URING_CMD_DISCARD**
ioctl with a few differences. It allows multiple parallel discards, and
it does not exclude concurrent writes and reads. As a result, it may
lead to races for the data on the disk, if the application has IO
inflight for the same ranges that the discard operates on. It's the
user's responsibility to account for that. Furthermore, only best
efforts are done to invalidate page caches. The user has to make sure
that no other inflight requests are modifying or reading the range(s).
If that is the case, it might result in stale page cache and data
inconsistencies.

Available since 6.12.

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
