Register buffers for fixed buffer operations

# DESCRIPTION

The [io_uring_register_buffers] function registers *nr_iovecs*
number of buffers defined by the array *iovecs* belonging to the *ring*.

The [io_uring_register_buffers_tags] function behaves the same as
[io_uring_register_buffers] function but additionally takes *tags*
parameter. See **IORING_REGISTER_BUFFERS2** for the resource tagging
description.

The [io_uring_register_buffers_sparse] function registers
*nr_iovecs* empty buffers belonging to the *ring*. These buffers must be
updated before use, using eg
[io_uring_register_buffers_update_tag].

After the caller has registered the buffers, they can be used with one
of the fixed buffers functions.

Registered buffers is an optimization that is useful in conjunction with
**O_DIRECT** reads and writes, where it maps the specified range into
the kernel once when the buffer is registered rather than doing a map
and unmap for each IO every time IO is performed to that region.
Additionally, it also avoids manipulating the page reference counts for
each IO.

The [io_uring_register_buffers_update_tag] function updates
registered buffers with new ones, either turning a sparse entry into a
real one, or replacing an existing entry. The *off* is offset on which
to start the update *nr* number of buffers defined by the array *iovecs*
belonging to the *ring*. The *tags* points to an array of tags. See
**IORING_REGISTER_BUFFERS2** for the resource tagging description.

# RETURN VALUE

On success [io_uring_register_buffers],
[io_uring_register_buffers_tags] and
[io_uring_register_buffers_sparse] return 0.
[io_uring_register_buffers_update_tag] return number of buffers
updated. On failure they return **-errno**.

# SEE ALSO

[io_uring_register], [io_uring_get_sqe],
[io_uring_unregister_buffers], [io_uring_clone_buffers],
[io_uring_register_buf_ring], [io_uring_prep_read_fixed],
[io_uring_prep_write_fixed]
