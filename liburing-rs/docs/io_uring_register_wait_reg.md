Register wait regions with io_uring

# DESCRIPTION

The [io_uring_register_wait_reg] function registers wait regions
with the io_uring instance specified by *ring*. The *reg* argument is a
pointer to an array of *struct io_uring_reg_wait* of *nr* entries.

Wait regions allow registering timeout and signal mask information that
can be reused across multiple wait operations without copying the data
for each call. This is used in conjunction with
[io_uring_submit_and_wait_reg] to reduce the overhead of wait
operations.

See [io_uring_register_region] for registering the underlying
memory region.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# SEE ALSO

[io_uring_submit_and_wait_reg], [io_uring_register_region],
[io_uring_register]
