Prepare a command request for a socket

# DESCRIPTION

The [io_uring_prep_cmd_sock] function prepares an cmd request for a
socket. The submission queue entry *sqe* is setup to use the socket file
descriptor pointed to by *fd* to start an command operation defined by
*cmd_op.*

This is a generic function, and each command has their own individual
*level, optname, optval* values. The optlen defines the size pointed by
*optval.*

# Available commands

**SOCKET_URING_OP_SIOCINQ**  
Returns the amount of queued unread data in the receive buffer. The
socket must not be in LISTEN state, otherwise an error **-EINVAL** is
returned in the CQE *res* field. The following arguments are not used
for this command *level, optname, optval* and *optlen.*

Negative return value means an error.

For more information about this command, please check **unix(7).**

Available since 6.7.

<!-- -->

**SOCKET_URING_OP_SIOCOUTQ**  
Returns the amount of unsent data in the socket send queue. The socket
must not be in LISTEN state, otherwise an error **-EINVAL** is returned
in the CQE *res.* field. The following arguments are not used for this
command *level, optname, optval* and *optlen.*

Negative return value means an error.

For more information about this command, please check **unix(7).**

<!-- -->

**SOCKET_URING_OP_GETSOCKOPT**  
Command to get options for the socket referred to by the socket file
descriptor *fd.* The arguments are similar to the **getsockopt(2)**
system call.

The **SOCKET_URING_OP_GETSOCKOPT** command is limited to **SOL_SOCKET**
*level.*

Differently from the **getsockopt(2)** system call, the updated *optlen*
value is returned in the CQE *res* field, on success. On failure, the
CQE *res* contains a negative error number.

<!-- -->

**SOCKET_URING_OP_SETSOCKOPT**  
Command to set options for the socket referred to by the socket file
descriptor *fd.* The arguments are similar to the **setsockopt(2)**
system call.

Available since 6.7.

<!-- -->

**SOCKET_URING_OP_TX_TIMESTAMP**  
Retrieve transmit timestamps from the socket's error queue. This
provides an alternative to the traditional **recvmsg(2)** error queue
interface for obtaining TX timestamps.

The command operates in a polled multishot mode: io_uring will poll the
socket and keep posting timestamps as CQEs until the request is
cancelled or fails. The ring must be created with **IORING_SETUP_CQE32**
or **IORING_SETUP_CQE_MIXED** to provide space for the timestamp data.

The socket must first be configured for timestamping via
**setsockopt(2)** with **SO_TIMESTAMPING** at the **SOL_SOCKET** level,
specifying the desired timestamp types (e.g.
**SOF_TIMESTAMPING_TX_SOFTWARE**, **SOF_TIMESTAMPING_TX_SCHED**,
**SOF_TIMESTAMPING_TX_ACK**) along with **SOF_TIMESTAMPING_SOFTWARE**
and **SOF_TIMESTAMPING_OPT_TSONLY**.

The following arguments are not used for this command: *level, optname,
optval* and *optlen.*

Each timestamp is delivered as a CQE with **IORING_CQE_F_MORE** set in
*cqe-\>flags* to indicate more timestamps may follow. The *cqe-\>res*
field contains the timestamp key (*tskey*), which corresponds to the
byte offset (for TCP) or packet count (for UDP). The timestamp type
(*SCM_TSTAMP_SCHED*, *SCM_TSTAMP_SND* or *SCM_TSTAMP_ACK*) is stored in
the upper bits of *cqe-\>flags* at offset
**IORING_TIMESTAMP_TYPE_SHIFT**. If the timestamp is a hardware
timestamp, the **IORING_CQE_F_TSTAMP_HW** flag is set.

The actual timestamp value is stored in the extended CQE area as a
**struct io_timespec** (with 64-bit *tv_sec* and *tv_nsec* fields),
accessible at *(cqe + 1)*.

The final CQE will not have **IORING_CQE_F_MORE** set, and its
*cqe-\>res* will contain 0 on success or a negative error code on
failure.

Available since 6.17.

<!-- -->

**SOCKET_URING_OP_GETSOCKNAME**  
Returns the current address to which the socket is bound. The result is
stored in the buffer pointed to by *optval,* which should be a pointer
to a *struct sockaddr* (or appropriate variant). The *optlen* argument
specifies the size of the buffer. On success, the CQE *res* field
contains the actual size of the socket address. If the buffer is too
small, the result is truncated.

This is the io_uring equivalent of [getsockname](https://man7.org/linux/man-pages/man2/getsockname.2.html).

Available since 6.19.

# NOTES

The memory block pointed by *optval* needs to be valid/live until the
CQE returns.

# RETURN VALUE

Dependent on the command.

# ERRORS

The CQE *res* field will contain the result of the operation.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register], [unix](https://man7.org/linux/man-pages/man2/unix.2.html)
