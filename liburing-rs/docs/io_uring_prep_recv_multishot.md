Prepare a recv request.

# DESCRIPTION

The [io_uring_prep_recv] function prepares a recv request. The
submission queue entry *sqe* is setup to use the file descriptor
*sockfd* to start receiving the data into the destination buffer *buf*
of size *len* and with modifier flags *flags*.

This function prepares an async [recv] request. See that man page
for details on the arguments specified to this prep helper.

The multishot version allows the application to issue a single receive
request, which repeatedly posts a CQE when data is available. Length can
either be set to 0, in which case there are no limits on how much data a
single invocation of the receive will transfer, or it can be set to a
positive value. If the latter is the case, then each trigger invocation
of the receive multishot will transfer at most length bytes. This can be
useful if the ring is handling many receive multishot operations on
different sockets, to ensure fairness between them, particularly when
used with bundles. The **IOSQE_BUFFER_SELECT** flag to be set and no
**MSG_WAITALL** flag to be set. Therefore each CQE will take a buffer
out of a provided buffer pool for receiving. The application should
check the flags of each CQE, regardless of its result. If a posted CQE
does not have the **IORING_CQE_F_MORE** flag set, then the multishot
receive is done and the application must issue a new request if it still
wishes to receive data from the socket. Multishot variants are available
since kernel 6.0.

After calling this function, additional io_uring internal modifier flags
may be set in the SQE *ioprio* field. The following flags are supported:

**IORING_RECVSEND_POLL_FIRST**\
If set, io_uring will assume the socket is currently empty and
attempting to receive data will be unsuccessful. For this case, io_uring
will arm internal poll and trigger a receive of the data when the socket
has data to be read. This initial receive attempt can be wasteful for
the case where the socket is expected to be empty, setting this flag
will bypass the initial receive attempt and go straight to arming poll.
If poll does indicate that data is ready to be received, the operation
will proceed.

Can be used with the CQE **IORING_CQE_F_SOCK_NONEMPTY** flag, which
io_uring will set on CQEs after a [recv] or [recvmsg]
operation. If set, the socket still had data to be read after the
operation completed. Both these flags are available since 5.19.

<!-- -->

**IORING_RECVSEND_BUNDLE**\
If set and provided buffers are used with **IOSQE_BUFFER_SELECT ,** the
receive operation will attempt to fill multiple buffers with rather than
just pick a single buffer to fill. To receive multiple buffers in a
single receive, the buffer group ID set in the SQE must be of the ring
provided type. If set, the CQE *res* field indicates the total number of
bytes received, and the buffer ID returned in the CQE *flags* field
indicates the first buffer in the receive operation. The application
must process the indicated initial buffer ID and until all *res* bytes
have been seen to know which is the last buffer in the receive
operation. The buffers consumed will be contiguous from the initial
buffer, in the order in which they appear in the buffer ring. The CQE
struct does not contain the position of the buffer in the buffer ring,
therefore in order to identify buffers contained by the bundle, it is
advised to maintain the cached head index per buffer ring. This uint16_t
index represents the position of the next buffer to be consumed within
the ring. Upon completion of a receive operation, the cached head index
should be incremented accordingly. Receiving in bundles can improve
performance when more than one chunk of data is available to receive, by
eliminating redundant round trips through the networking stack. Receive
bundles may be used by both single shot and multishot receive
operations. Note that, internally, bundles rely on the networking stack
passing back how much data is left in the socket after the initial
receive. This means that the initial receive may contain less buffers
than what is available, with the followup receive(s) containing more
buffers. Available since 6.10.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# NOTES

Despite accepting a size_t number of bytes, these functions can transfer
at most INT_MAX bytes per call (the maximum for the underlying syscall
interface).

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_buf_ring_init], [io_uring_buf_ring_add], [recv]
