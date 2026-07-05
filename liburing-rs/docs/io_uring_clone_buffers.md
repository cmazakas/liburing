Clones registered buffers between rings.

# DESCRIPTION

The **io_uring_clone_buffers**(3) function clones registered buffers
from the ring indicated by *src* to the ring indicated by *dst*. Upon
successful completion of this operation, *src* and *dst* will have the
same set of registered buffers. This operation is identical to
performing a **io_uring_register_buffers**(3) operation on the *dst*
ring, if the *src* ring previously had that same buffer registration
operating done.

The *dst* ring must not have any buffers currently registered. If
buffers are currently registered on the destination ring, they must be
unregistered with **io_uring_unregister_buffers**(3) first.

For **\_\_io_uring_clone_buffers**(3)**,** the only difference is that
it takes a *flags* argument. By default, if the destination ring has a
registered file descriptor through **io_uring_register_ring_fd**(3) AND
the calling application is not the thread that registered that ring,
then the kernel doesn't know how to look up the destination. This is
problematic as **io_uring_clone_buffers**(3) defaults to using the
registered index if the destination is setup as such. Use
**\_\_io_uring_clone_buffers**(3) which doesn't set
**IORING_REGISTER_SRC_REGISTERED** by default. This requires the
application to still have the original ring file descriptor open. See
below for the flag definition.

Available since kernel 6.12.

The **io_uring_clone_buffers_offset**(3) function also clones buffers
from the *src* ring to the *dst* ring, however it supports cloning only
a subset of the buffers, where **io_uring_clone_buffers**(3) always
clones all of them. *dst_off* indicates at what offset cloning should
start in the destination, *src_off* indicates at what offset cloning
should start in the source, and *nr* indicates how many buffers to clone
at the given offset. If both *dst_off*, *src_off*, and *nr* are given as
**0 ,** then **io_uring_clone_buffers_offset**(3) performs the same
action as **io_uring_clone_buffers**(3)**.**

While **io_uring_clone_buffers_offset**(3) sets
**IORING_REGISTER_SRC_REGISTERED** by default, the
**\_\_io_uring_clone_buffers_offset**(3) does not. See the explanation
for **\_\_io_uring_clone_buffers**(3) for details.

*flags* may be set to the following value:

**IORING_REGISTER_SRC_REGISTERED**\

If the source ring is registered AND the calling thread is the one that
originally registered its ring fd, then this flag may be set to lookup
the registered index rather than use the normal file descriptor. If the
normal file descriptor wasn't closed after registering it, there's no
need to set this flag.

**IORING_REGISTER_DST_REPLACE**\

If set, cloning may happen for a destination ring that already has a
buffer table assigned. In that case, existing nodes that overlap with
the specified range will be released and replaced.

Available since kernel 6.13.

# NOTES

The source and target ring must shared address spaces, and hence
internal kernel accounting.

# RETURN VALUE

On success **io_uring_clone_buffers**(3) and
**io_uring_clone_buffers_offset**(3) return 0. On failure, they returns
**-errno**, specifically

## -EBUSY
The destination ring already has buffers registered, and
**IORING_REGISTER_DST_REPLACE** wasn't set.

## -ENOMEM
The kernel ran out of memory.

## -ENXIO
The source ring doesn't have any buffers registered.

# SEE ALSO

[io_uring_register], [io_uring_unregister_buffers],
[io_uring_register_buffers], [io_uring_prep_read_fixed],
[io_uring_prep_write_fixed]
