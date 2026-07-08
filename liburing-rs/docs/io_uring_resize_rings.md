Resize the SQ and CQ rings

# DESCRIPTION

The [io_uring_resize_rings] function performs resizes the SQ and/or
CQ ring associated with *ring* by the parameters specified in *p .*

The *p* argument must be filled in with the appropriate information for
the resize operations, most notably the *sq_entries* and *cq_entries*
fields must be filled out. The *flags* field can also be set, see below
for potential values that may be used with a resize operation.

It's fairly uncommon to need to resize the SQ ring, but not that
uncommon that the CQ ring would need resizing. For networked workloads,
it can be hard to appropriately size the CQ ring upfront, as it's not
always known what load a given ring will see. If overflow conditions are
seen for the CQ ring, then resizing it larger may be a good idea.

When a ring is resized, any pending SQ or CQ entries are copied along
the way. It is not legal to resize a CQ ring that is in an overflow
condition, and attempting to do so will fail.

Currently doesn't support resizing rings setup with
**IORING_SETUP_NO_MMAP .** This is purely a liburing limitation, the
kernel does support it.

Also note that ring resizing is currently only supported on rings setup
with **IORING_SETUP_DEFER_TASKRUN .** Attempting to resize differently
configured rings will result in an **-EINVAL** error.

Valid flags in *flags*:

**IORING_SETUP_CQSIZE**\
If this isn't set, then the CQ ring size is set based on the specified
SQ ring size. The default is twice as many CQ ring entries as there are
SQ ring entries. If set, then *cq_entries* will be used to size the CQ
ring.

**IORING_SETUP_CLAMP**\
If set, then SQ and CQ ring entries are clamped to the maximum allowable
size, if they exceed that. If not set, setting sizes too large will
cause the operation to fail.

Other flags are inherited from the way the ring was setup, that includes
flags like **IORING_SETUP_NO_SQARRAY ,** **IORING_SETUP_SQE128 ,**
**IORING_SETUP_CQE32 ,** and **IORING_SETUP_NO_MMAP .**

Other fields in *p* should be cleared to zero.

Available since kernel 6.13.

Also see [io_uring_setup] for a detailed description of the setup
flags.

# RETURN VALUE

Returns 0 on success, and \< 0 on failure. Potential common failure
cases:

**-EEXIST**\
Attempting to resize a ring setup with **IORING_SETUP_SINGLE_ISSUER**
and the resizing task is different from the one that created/enabled the
ring.

**-EFAULT**\
Copying of *p* was unsuccessful.

**-EINVAL**\
Invalid flags were specified for the operation

**-EINVAL**\
Attempt to resize a ring not setup with **IORING_SETUP_DEFER_TASKRUN**.

**-EOVERFLOW**\
The values specified for SQ or CQ entries would cause an overflow.

# SEE ALSO

[io_uring_setup]
