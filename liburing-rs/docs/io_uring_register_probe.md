Register probe with io_uring.

# DESCRIPTION

The [io_uring_register_probe] function queries the kernel for
supported io_uring opcodes and fills in the probe structure *p*. The
*ring* argument specifies the io_uring instance to query, and *nr*
specifies the maximum number of opcodes to query.

The probe structure contains information about which opcodes are
supported by the kernel. Applications can use
[io_uring_opcode_supported] to check if a specific opcode is
supported after calling this function.

Most applications should use [io_uring_get_probe] or
[io_uring_get_probe_ring] instead, which allocate and fill in the
probe structure automatically.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# SEE ALSO

[io_uring_get_probe], [io_uring_get_probe_ring],
[io_uring_opcode_supported], [io_uring_free_probe],
[io_uring_register]
