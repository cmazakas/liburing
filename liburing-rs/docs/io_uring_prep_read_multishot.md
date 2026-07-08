Prepare I/O read multishot request

# DESCRIPTION

The [io_uring_prep_read_multishot] helper prepares an IO read
multishot request. The submission queue entry *sqe* is setup to use the
file descriptor *fd* to start reading into a buffer from the provided
buffer group with ID *buf_group* at the specified *offset*.

*nbytes* must be set to zero, as the size read will be given by the size
of the buffers in the indicated buffer group IO.

On files that are not capable of seeking, the offset must be 0 or -1.

If *nbytes* exceeds the size of the buffers in the specified buffer
group, or if *nbytes* is **0 ,** then the size of the buffer in that
group will be used for the transfer.

A multishot read request will repeatedly trigger a completion event
whenever data is available to read from the file. Because of that, this
type of request can only be used with a file type that is pollable.
Examples of that include pipes, tun devices, etc. If used with a regular
file, or a wrong file type in general, the request will fail with
**-EBADFD** in the CQE *res* field.

Since multishot requests repeatedly trigger completion events as data
arrives, it must be used with provided buffers. With provided buffers,
the application provides buffers to io_uring upfront, and then the
kernel picks a buffer from the specified group in *buf_group* when the
request is ready to transfer data.

A multishot request will persist as long as no errors are encountered
doing handling of the request. For each CQE posted on behalf of this
request, the CQE *flags* will have **IORING_CQE_F_MORE** set if the
application should expect more completions from this request. If this
flag isn't set, then that signifies termination of the multishot read
request.

After the read has been prepared it can be submitted with one of the
submit functions.

Available since 6.7.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

This function accepts an unsigned number of bytes, but io_uring_cqe's
result code is an \_\_s32 value, so in theory a short read with a large
enough nbytes value could generate an ambiguous return. But the number
of bytes actually transferred has the same limit as [read](https://man7.org/linux/man-pages/man2/read.2.html) so this
cannot happen in practice.

# SEE ALSO

[io_uring_get_sqe], [io_uring_prep_read],
[io_uring_buf_ring_init] [io_uring_buf_ring_add],
[io_uring_submit]
