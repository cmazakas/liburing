Query io_uring capabilities and feature
support

# DESCRIPTION

The [io_uring_register_query] function queries io_uring
capabilities and feature support. It provides information about
supported opcodes, flags, and subsystem-specific capabilities.

The *query* argument must point to a *struct io_uring_query_hdr*
structure that describes the query to perform:

    struct io_uring_query_hdr {
        __u64 next_entry;
        __u64 query_data;
        __u32 query_op;
        __u32 size;
        __s32 result;
        __u32 __resv[3](https://man7.org/linux/man-pages/man2/3.2.html);
    };

The *next_entry* field can be used to chain multiple queries together.
It should point to the next *struct io_uring_query_hdr* structure, or be
set to 0 for the last entry in the chain.

The *query_data* field must point to a data structure appropriate for
the query type specified in *query_op*.

The *query_op* field specifies the type of query to perform and can be
one of:

**IO_URING_QUERY_OPCODES**  
Returns information about supported opcodes and flags. The *query_data*
field must point to a *struct io_uring_query_opcode* structure, which
will be filled with information about supported request opcodes,
register opcodes, feature flags, setup flags, enter flags, and SQE
flags.

<!-- -->

**IO_URING_QUERY_ZCRX**  
Returns information about zero-copy receive support. The *query_data*
field must point to a *struct io_uring_query_zcrx* structure, which will
be filled with information about supported zero-copy receive flags,
features, and configuration details.

<!-- -->

**IO_URING_QUERY_SCQ**  
Returns information about the SQ/CQ ring layout. The *query_data* field
must point to a *struct io_uring_query_scq* structure, which will be
filled with information about ring header size and alignment
requirements.

The *size* field should be set to the size of the data structure pointed
to by *query_data*.

Upon return, the *result* field will contain 0 on success, or a negative
error code on failure.

The reserved *\_\_resv* fields must be cleared to zero.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# NOTES

This function is available since Linux kernel 6.15.

Multiple queries can be efficiently performed in a single system call by
chaining them together using the *next_entry* field.

# SEE ALSO

[io_uring_register], [io_uring_setup]
