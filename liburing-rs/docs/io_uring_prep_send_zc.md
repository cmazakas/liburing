Prepare a zerocopy send request

# DESCRIPTION

The [io_uring_prep_send_zc] function prepares a zerocopy send
request. The submission queue entry *sqe* is setup to use the file
descriptor *sockfd* to start sending the data from *buf* of size *len*
bytes with send modifier flags *flags* and zerocopy modifier flags
*zc_flags*.

The [io_uring_prep_send_zc_fixed] works just like
[io_uring_prep_send_zc] except it requires the use of buffers that
have been registered with [io_uring_register_buffers]. The *buf*
and *len* arguments must fall within a region specified by *buf_index*
in the previously registered buffer. The buffer need not be aligned with
the start of the registered buffer.

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

These functions prepare an async zerocopy [send](https://man7.org/linux/man-pages/man2/send.2.html) request. See that
man page for details. For details on the zerocopy nature of it, see
[io_uring_enter]**.**

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field. Some common
error cases are:

**-ENOMEM**  
The [ulimit](https://man7.org/linux/man-pages/man2/ulimit.2.html) -l setting is too low to support the size of the
attempted zero copy send. Increasing the limit may help

**-ENOMEM**  
The kernel ran out of memory.

# NOTES

Despite accepting a size_t number of bytes, these functions can transfer
at most INT_MAX bytes per call (the maximum for the underlying syscall
interface).

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_send], [io_uring_enter], [send](https://man7.org/linux/man-pages/man2/send.2.html)
