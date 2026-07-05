Perform control operations on a zero-copy.
receive context

# DESCRIPTION

The [io_uring_register_zcrx_ctrl] function performs control
operations on a previously registered zero-copy receive context. See
[io_uring_register_ifq] for details on registering a zero-copy
receive context.

The *ctrl* argument must point to a *struct zcrx_ctrl* structure that
describes the control operation to perform:

```c
    struct zcrx_ctrl {
        __u32 zcrx_id;
        __u32 op;
        __u64 __resv[2];
        union {
            struct zcrx_ctrl_export     zc_export;
            struct zcrx_ctrl_flush_rq   zc_flush;
        };
    };
```

The *zcrx_id* field must be set to the ID of the zero-copy receive
context returned from [io_uring_register_ifq]. The *op* field
specifies the control operation to perform and can be one of:

**ZCRX_CTRL_FLUSH_RQ**\

Flushes pending buffers from the refill queue. Uses the *zc_flush*
member of the union.

<!-- -->

**ZCRX_CTRL_EXPORT**\

Exports the zero-copy receive context for use by other rings. Uses the
*zc_export* member of the union. Upon successful export, the *zcrx_fd*
field in *zc_export* will contain the file descriptor that can be used
to share this context with other io_uring instances.

The reserved *\_\_resv* fields must be cleared to zero.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# NOTES

This function is available since Linux kernel 6.15.

# SEE ALSO

[io_uring_register], [io_uring_register_ifq]
