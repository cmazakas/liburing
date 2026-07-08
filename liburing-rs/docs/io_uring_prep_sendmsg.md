Prepare a sendmsg request

# DESCRIPTION

The [io_uring_prep_sendmsg] function prepares a sendmsg request.
The submission queue entry *sqe* is setup to use the file descriptor
*fd* to start sending the data indicated by *msg* with the
[sendmsg](https://man7.org/linux/man-pages/man2/sendmsg.2.html) defined flags in the *flags* argument.

The [io_uring_prep_sendmsg_zc] accepts the same parameters as
[io_uring_prep_sendmsg] but prepares a zerocopy sendmsg request.

See [io_uring_prep_send] for a description of flags that can be set
in the SQE *ioprio* field. In addition to those, the zero-copy send also
supports setting **IORING_SEND_ZC_REPORT_USAGE .** If set, the
notification CQE *res* field will report the number of bytes that were
copied rather than sent with zero copy. A value of **0** indicates
success. If the value is **IORING_NOTIF_USAGE_ZC_COPIED ,** then data
was copied.

As opposed to non-zerocopy send requests, a zerocopy send will usually
generate two CQEs. The first CQE holds the result of the send operation
itself, and if that CQE has **IORING_CQE_F_MORE** set in the CQE *flags*
field, then a second notification CQE will be posted for the operation.
This second notification tells the application that the memory
associated with the send is safe to get reused. The second CQE will have
**IORING_CQE_F_NOTIF** set in the CQE *flags* field. Also see the
[io_uring_enter] man page for a fuller description of the
notification CQE.

Note that using **IOSQE_IO_LINK** with this request type requires the
setting of **MSG_WAITALL** in the *flags* argument, as a short send
isn't considered an error condition without that being set.

This function prepares an async [sendmsg](https://man7.org/linux/man-pages/man2/sendmsg.2.html) request. See that man
page for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field. Some common
error cases are:

**-ENOMEM**\
The [ulimit](https://man7.org/linux/man-pages/man2/ulimit.2.html) -l setting is too low to support the size of the
attempted zero copy send. Increasing the limit may help

**-ENOMEM**\
The kernel ran out of memory.

# NOTES

As with any request that passes in data in a struct, that data must
remain valid until the request has been successfully submitted. It need
not remain valid until completion. Once a request has been submitted,
the in-kernel state is stable. Very early kernels (5.4 and earlier)
required state to be stable until the completion occurred. Applications
can test for this behavior by inspecting the
**IORING_FEAT_SUBMIT_STABLE** flag passed back from
[io_uring_queue_init_params].

Despite accepting an array of iovec's with a size_t number of bytes
each, these functions can transfer at most INT_MAX bytes per call (the
maximum for the underlying syscall interface).

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_buf_ring_init], [io_uring_buf_ring_add],
[sendmsg](https://man7.org/linux/man-pages/man2/sendmsg.2.html)
