Send a message to another ring.

# DESCRIPTION

[io_uring_prep_msg_ring] prepares to send a CQE to an io_uring file
descriptor. The submission queue entry *sqe* is setup to use the file
descriptor *fd*, which must identify a io_uring context, to post a CQE
on that ring where the target CQE **res** field will contain the content
of *len* and the **user_data** of *data* with the request modifier flags
set by *flags*. Currently there are no valid flag modifiers, this field
must contain **0**.

The targeted ring may be any ring that the user has access to, even the
ring itself. This request can be used for simple message passing to
another ring, allowing 32+64 bits of data to be transferred through the
*len* and *data* fields. The use case may be anything from simply waking
up someone waiting on the targeted ring, or it can be used to pass
messages between the two rings.

[io_uring_prep_msg_ring_cqe_flags] is similar to
[io_uring_prep_msg_ring]**.** But has an addition *cqe_flags*
parameter, which is used to set *flags* field on CQE side. That way, you
can set the CQE flags field *cqe-\>flags* when sending a message. Be
aware that io_uring could potentially set additional bits into this
field.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field.

**-ENOMEM**\
The kernel was unable to allocate memory for the request.

**-EINVAL**\
One of the fields set in the SQE was invalid.

**-EBADFD**\
The descriptor passed in *fd* does not refer to an io_uring file
descriptor, or the ring is in a disabled state.

**-EOVERFLOW**\
The kernel was unable to fill a CQE on the target ring. This can happen
if the target CQ ring is in an overflow state and the kernel wasn't able
to allocate memory for a new CQE entry.
