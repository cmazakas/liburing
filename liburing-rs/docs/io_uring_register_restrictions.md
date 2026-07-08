Register restrictions with io_uring

# DESCRIPTION

The [io_uring_register_restrictions] function registers
restrictions with the io_uring instance specified by *ring*. The *res*
argument is a pointer to an array of *struct io_uring_restriction* of
*nr_res* entries.

Restrictions allow limiting which opcodes, register operations, or SQE
flags are allowed on a ring. This can be used to sandbox io_uring usage.

Restrictions can only be registered if the io_uring ring was started in
a disabled state (with **IORING_SETUP_R_DISABLED** specified in the call
to [io_uring_setup]). All restrictions must be registered in a
single call before enabling the ring with [io_uring_enable_rings].

See [io_uring_register] for a description of the
**IORING_REGISTER_RESTRICTIONS** operation and the restriction
structure.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# SEE ALSO

[io_uring_enable_rings], [io_uring_register],
[io_uring_setup]
