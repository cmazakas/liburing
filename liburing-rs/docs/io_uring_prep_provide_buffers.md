Prepare a provide buffers request

# DESCRIPTION

The [io_uring_prep_provide_buffers] function prepares a request for
providing the kernel with buffers. The submission queue entry *sqe* is
setup to consume *nr* number of *len* sized buffers starting at *addr*
and identified by the buffer group ID of *bgid* and numbered
sequentially starting at *bid*.

This function sets up a request to provide buffers to the io_uring
context that can be used by read or receive operations. This is done by
filling in the SQE *buf_group* field and setting **IOSQE_BUFFER_SELECT**
in the SQE *flags* member. If buffer selection is used for a request, no
buffer should be provided in the address field. Instead, the group ID is
set to match one that was previously provided to the kernel. The kernel
will then select a buffer from this group for the IO operation. On
successful completion of the IO request, the CQE *flags* field will have
**IORING_CQE_F_BUFFER** set and the selected buffer ID will be indicated
by the upper 16-bits of the *flags* field.

Different buffer group IDs can be used by the application to have
different sizes or types of buffers available. Once a buffer has been
consumed for an operation, it is no longer known to io_uring. It must be
re-provided if so desired or freed by the application if no longer
needed.

The buffer IDs are internally tracked from *bid* and sequentially
ascending from that value. If **16** buffers are provided and start with
an initial *bid* of 0, then the buffer IDs will range from **0..15**.
The application must be aware of this to make sense of the buffer ID
passed back in the CQE.

Buffer IDs always range from **0** to **65535 ,** as there are only
16-bits available in the CQE to pass them back. This range is
independent of how the buffer group initially got created. Attempting to
add buffer IDs larger than that, or buffer IDs that will wrap when cast
to a 16-bit value, will cause the request to fail with **-E2BIG** or
**-EINVAL .**

Not all requests support buffer selection, as it only really makes sense
for requests that receive data from the kernel rather than write or
provide data. Currently, this mode of operation is supported for any
file read or socket receive request. Attempting to use
**IOSQE_BUFFER_SELECT** with a command that doesn't support it will
result in a CQE *res* error of **-EINVAL**. Buffer selection will work
with operations that take a **struct iovec** as its data destination,
but only if 1 iovec is provided.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, *res* will contain **0** or the number of successfully provided
buffers.

**-ENOMEM**  
The kernel was unable to allocate memory for the request.

**-EINVAL**  
One of the fields set in the SQE was invalid.

**-E2BIG**  
The number of buffers provided was too big, or the *bid* was too big. A
max value of **USHRT_MAX** buffers can be specified.

**-EFAULT**  
Some of the user memory given was invalid for the application.

**-EOVERFLOW**  
The product of *len* and *nr* exceed the valid amount or overflowed, or
the sum of *addr* and the length of buffers overflowed.

**-EBUSY**  
Attempt to update a slot that is already used.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register], [io_uring_prep_remove_buffers]
