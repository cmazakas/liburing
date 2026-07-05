Prepare a zero-copy sendmsg using fixed.
buffers

# DESCRIPTION

The [io_uring_prep_sendmsg_zc_fixed] function prepares a zero-copy
sendmsg request using fixed (registered) buffers. The submission queue
entry *sqe* is setup to send data on the socket indicated by the file
descriptor *fd* using the message structure *msg*.

The *flags* argument contains flags for the sendmsg operation, as
described in [sendmsg].

The *buf_index* specifies the index of the registered buffer set to use.
The buffers in *msg* must be part of the registered buffer set
previously registered with [io_uring_register_buffers].

Zero-copy sends avoid copying data from user to kernel space, improving
performance for large transfers. Using fixed buffers additionally avoids
the overhead of mapping buffers for each I/O operation.

Note that zero-copy sends require the application to wait for a
notification before reusing the buffer. See [io_uring_prep_send_zc]
for more details on zero-copy semantics.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation, the number
of bytes sent on success. On error, a negative errno value is returned.

Despite accepting an array of iovec's with a size_t number of bytes
each, this function can transfer at most INT_MAX bytes per call (the
maximum for the underlying syscall interface).

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_sendmsg_zc], [io_uring_prep_sendmsg],
[io_uring_prep_send_zc_fixed], [io_uring_register_buffers],
[sendmsg]
