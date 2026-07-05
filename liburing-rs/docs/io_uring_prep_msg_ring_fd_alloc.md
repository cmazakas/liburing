Send a direct descriptor to another ring.

# DESCRIPTION

[io_uring_prep_msg_ring_fd] prepares an SQE to send a direct file
descriptor to another ring. The submission queue entry *sqe* is setup to
use the file descriptor *fd*, which must identify a target io_uring
context, to send the locally registered file descriptor with value
*source_fd* to the destination ring into index *target_fd* and passing
*data* as the user data in the target CQE with the request modifier
flags set by *flags*. Currently there are no valid flag modifiers, this
field must contain **0**.

[io_uring_prep_msg_ring_fd_alloc] is similar to
[io_uring_prep_msg_ring_fd]**,** but doesn't specify a target index
for the direct descriptor. Instead, this index is allocated in the
target ring and returned in the CQE *res* field.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field.

**-ENOMEM**\
The kernel was unable to allocate memory for the request.

**-EINVAL**\
One of the fields set in the SQE was invalid.

**-EINVAL**\
Target ring is identical to the source ring.

**-EBADFD**\
The descriptor passed in *fd* does not refer to an io_uring file
descriptor, or the ring is in a disabled state.

**-EOVERFLOW**\
The kernel was unable to fill a CQE on the target ring. This can happen
if the target CQ ring is in an overflow state and the kernel wasn't able
to allocate memory for a new CQE entry.

**-ENFILE**\
The direct descriptor table in the target ring was full, no new
descriptors could be successfully allocated.
