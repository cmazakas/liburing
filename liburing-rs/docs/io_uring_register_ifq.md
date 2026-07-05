Register a zero-copy receive interface queue.

# DESCRIPTION

The [io_uring_register_ifq] function registers a zero-copy receive
interface queue with the io_uring instance specified by *ring*.
Zero-copy receive allows the kernel to place incoming network data
directly into application-provided memory without copying.

The *reg* argument is a pointer to a *struct io_uring_zcrx_ifq_reg* that
describes the interface queue to register. See [io_uring_register]
for a description of the **IORING_REGISTER_ZCRX_IFQ** operation and the
structure fields.

The io_uring ring must have been created with
**IORING_SETUP_DEFER_TASKRUN** and either **IORING_SETUP_CQE32** or
**IORING_SETUP_CQE_MIXED** flags set. The caller must have the
**CAP_NET_ADMIN** capability.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# SEE ALSO

[io_uring_register], [io_uring_setup]
