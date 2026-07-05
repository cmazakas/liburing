Prepare a send request.

# DESCRIPTION

The [io_uring_prep_send] function prepares a send request. The
submission queue entry *sqe* is setup to use the file descriptor
*sockfd* to start sending the data from *buf* of size *len* bytes and
with modifier flags *flags*.

After calling this function, additional io_uring internal modifier flags
may be set in the SQE *ioprio* field. The following flags are supported:

**IORING_RECVSEND_POLL_FIRST**\
If set, io_uring will assume the socket is currently full and attempting
to send data will be unsuccessful. For this case, io_uring will arm
internal poll and trigger a send of the data when the socket has space
available. If poll does indicate that space is available in the socket,
the operation will proceed immediately.

<!-- -->

**IORING_RECVSEND_BUNDLE**\
If set, the send operation will attempt to fill multiple buffers with
rather than just pick a single buffer to fill. To send multiple buffers
in a single send, the buffer group ID set in the SQE must be of the ring
provided type. If set, the CQE *res* field indicates the total number of
bytes sent, and the buffer ID returned in the CQE *flags* field
indicates the first buffer in the send operation. The application must
process the indicated initial buffer ID and until all *res* bytes have
been seen to know which is the last buffer in the send operation. The
buffers consumed will be contiguous from the initial buffer, in the
order in which they appear in the buffer ring. The CQE struct does not
contain the position of the buffer in the buffer ring, therefore in
order to identify buffers contained by the bundle, it is advised to
maintain the cached head index per buffer ring. This uint16_t index
represents the position of the next buffer to be consumed within the
ring. Upon completion of a bundle send operation, the cached head index
should be incremented accordingly. Sending in bundles can improve
performance when more than one chunk of data is available by eliminating
redundant round trips through the networking stack.

**IORING_SEND_VECTORIZED**\
If set, *addr must point to an array of* *struct iovec* and *len* must
be the number of vectors in that array. This enables use of vectorized
IO for a normal send operation, rather than needing a sendmsg variant to
accomplish that.

Note that using **IOSQE_IO_LINK** with this request type requires the
setting of **MSG_WAITALL** in the *flags* argument, as a short send
isn't a considered an error condition without that being set.

This function prepares an async [send] request. See that man page
for details.

The [io_uring_prep_sendto] function prepares a sendto request. The
submission queue entry *sqe* is setup to use the file descriptor
*sockfd* to start sending the data from *buf* of size *len* bytes and
with modifier flags *flags*. The destination address is specified by
*addr* and *addrlen* and must be a valid address for the socket type.

This function prepares an async [sendto] request. See that man page
for details.

Both of the above send variants may be used with provided buffers, where
rather than pass a buffer in directly with the request,
**IOSQE_BUFFER_SELECT** is set in the SQE *flags* field, and
additionally a buffer group ID is set in the SQE *buf_group* field. By
using provided buffers with send requests, the application can prevent
any kind of reordering of the outgoing data which can otherwise occur if
the application has more than one send request inflight for a single
socket. This provides better pipelining of data, where previously the
app needed to manually serialize sends.

The bundle version allows the application to issue a single send
request, with a buffer group ID given in the SQE *buf_group* field,
which keeps sending from that buffer group until it runs out of buffers.
As with any other request using provided buffers,
**IOSQE_BUFFER_SELECT** must also be set in the SQE *flags* before
submission. Currently *len* must be given as **0** otherwise the request
will be errored with **-EINVAL** as the result code. Future versions may
allow setting *to limit the transfer size. A single CQE is posted for
the send, with the result* being how many bytes were sent, on success.
When used with provided buffers, send or send bundle will contain the
starting buffer group ID in the CQE *flags* field. The number of bytes
sent starts from there, and will be in contiguous buffer IDs after that.
Send bundle, and send with provided buffers in general, are available
since kernel 6.10, and can be further identified by checking for the
**IORING_FEAT_SEND_BUF_SELECT** flag returned in when using
[io_uring_queue_init_params] to setup the ring.

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
[io_uring_buf_ring_init], [io_uring_buf_ring_add], [send]
[sendto]
