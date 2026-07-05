io_uring_register_bpf_filter, io_uring_register_bpf_filter_task -
register classic BPF filters for io_uring operations

# DESCRIPTION

These functions register classic BPF (cBPF) filters to restrict io_uring
operations. Filters can be used to implement security policies by
allowing or denying specific operations based on their parameters.

[io_uring_register_bpf_filter] registers a filter on a specific
*ring*. The filter only applies to operations submitted through that
ring.

[io_uring_register_bpf_filter_task] registers a filter on the
calling task. The filter applies to all io_uring rings created by the
task after the filter is registered, and is inherited by child processes
created via [fork](https://man7.org/linux/man-pages/man2/fork.2.html). Rings that were created before the filter was
registered are not affected. Task-level filters cannot be removed and
child processes cannot loosen restrictions set by their parent.

The *bpf* argument is a pointer to a **struct io_uring_bpf** with
*cmd_type* set to **IO_URING_BPF_CMD_FILTER**. The embedded **struct
io_uring_bpf_filter** describes the filter to register:

```c
    struct io_uring_bpf_filter {
        __u32   opcode;      /* io_uring opcode to filter */
        __u32   flags;       /* IO_URING_BPF_FILTER_* */
        __u32   filter_len;  /* number of BPF instructions */
        __u8    pdu_size;    /* expected pdu size for opcode */
        __u8    resv[3];
        __u64   filter_ptr;  /* pointer to BPF filter */
        __u64   resv2[5];
    };
```

*opcode* specifies which io_uring operation the filter applies to (e.g.,
**IORING_OP_SOCKET**, **IORING_OP_NOP**, **IORING_OP_READ**).

*filter_ptr* points to an array of *filter_len* BPF instructions
(**struct sock_filter**). The filter is executed for each matching
operation and must return non-zero to allow the operation or zero to
deny it (resulting in **-EACCES** being returned to the application).

*pdu_size* specifies the expected size in bytes of the
operation-specific payload data for the given opcode (e.g., the socket
or open structs inside **struct io_uring_bpf_ctx**). For opcodes that
have no extra payload, this should be zero. For **IORING_OP_SOCKET**
this would be 12 (three 4-byte members), and for **IORING_OP_OPENAT**
and **IORING_OP_OPENAT2** this would be 24 (three 8-byte members).

If the application's *pdu_size* matches the kernel's expected size for
the opcode, registration succeeds. If the sizes differ, the behavior
depends on whether **IO_URING_BPF_FILTER_SZ_STRICT** is set in *flags*:

Register classic BPF filters for io_uring operations.
>   **-EMSGSIZE** if the sizes differ.
>
Register classic BPF filters for io_uring operations.
>   allowed if the application's *pdu_size* is smaller than the
>   kernel's. This permits older applications that were compiled against
>   a smaller payload to still load filters, as the kernel can safely
>   evaluate the filter on the subset of data the application expects.
>
Register classic BPF filters for io_uring operations.
>   fails with **-EMSGSIZE** if the application's *pdu_size* is larger
>   than the kernel's, since the kernel cannot provide data that it does
>   not support.

On an **-EMSGSIZE** failure, the kernel writes back the kernel's
expected *pdu_size* into the **struct io_uring_bpf_filter** passed by
the application. This allows the application to discover the kernel's
expected payload size and adjust or retry accordingly.

*flags* can be zero or a bitwise OR of the following:

**IO_URING_BPF_FILTER_DENY_REST**
When set, any opcode that does not have a filter registered will be
denied. This allows creating an allowlist of permitted operations.

**IO_URING_BPF_FILTER_SZ_STRICT**
When set, registration of a filter will fail with **-EMSGSIZE** if the
application's *pdu_size* does not exactly match the kernel's expected
payload size for the opcode. Without this flag, the kernel permits
filters where the application's *pdu_size* is smaller than or equal to
the kernel's.

**Filter**\ Context

The BPF filter receives a context structure that can be inspected using
**BPF_LD** instructions with absolute addressing. The context layout is:

```c
    struct io_uring_bpf_ctx {
        __u64   user_data;     /* offset 0: user_data from SQE */
        __u8    opcode;        /* offset 8: io_uring opcode */
        __u8    sqe_flags;     /* offset 9: SQE flags */
        __u8    pdu_size;      /* offset 10: aux data size for filter */
        __u8    pad[5];        /* offset 11-15: padding */
        union {
            struct {
                __u32   family;    /* offset 16: socket family */
                __u32   type;      /* offset 20: socket type */
                __u32   protocol;  /* offset 24: socket protocol */
            } socket;
            struct {
                __u64   flags;     /* offset 16: open flags */
                __u64   mode;      /* offset 24: file mode */
                __u64   resolve;   /* offset 32: resolve flags */
            } open;
        };
    };
```

The *pdu_size* field indicates the size in bytes of the
operation-specific data passed in the union. A filter can check this
value to verify it is receiving the expected payload. This is useful for
forward compatibility: if a future kernel adds new members to an
operation's context, the filter can inspect *pdu_size* to determine
whether those fields are present.

For **IORING_OP_SOCKET** operations, the socket family, type, and
protocol fields are populated and can be used to filter based on socket
parameters. *pdu_size* is set to 12 (three 4-byte members).

For **IORING_OP_OPENAT** and **IORING_OP_OPENAT2** operations, the open
flags, mode, and resolve fields are populated. The flags field contains
the open flags (e.g., **O_RDONLY**, **O_CREAT**). The resolve field is
only meaningful for **IORING_OP_OPENAT2** and contains resolve flags
(e.g., **RESOLVE_IN_ROOT**). *pdu_size* is set to 24 (three 8-byte
members).

**Filter**\ Stacking

Multiple filters can be registered for the same opcode. When multiple
filters exist, they are evaluated in order and all must return non-zero
for the operation to be allowed. For task-level filters, the child's
filters are evaluated before the parent's filters.

# RETURN VALUE

On success, these functions return 0. On failure, they return a negative
error code.

# ERRORS

**-EINVAL**
Invalid filter, opcode, or flags specified.

**-EMSGSIZE**
The application's *pdu_size* does not match the kernel's expected
payload size for the opcode. This occurs when
**IO_URING_BPF_FILTER_SZ_STRICT** is set and the sizes differ, or when
the application's *pdu_size* is larger than the kernel's regardless of
flags.

**-ENOMEM**
Insufficient memory to register the filter.

**-EFAULT**
The filter pointer is invalid.

**-EACCES**
The caller does not have the **CAP_SYS_ADMIN** capability and the
**no_new_privs** attribute is not set on the calling task. See
[prctl](https://man7.org/linux/man-pages/man2/prctl.2.html) with **PR_SET_NO_NEW_PRIVS**.

# EXAMPLES

**Deny**\ all NOP operations

```c
    #include <sys/prctl.h>
    #include <linux/filter.h>
    #include <liburing.h>
    #include <liburing/io_uring/bpf_filter.h>

    struct sock_filter deny_filter[] = {
        BPF_STMT(BPF_RET | BPF_K, 0),  /* return 0 (deny) */
    };

    struct io_uring_bpf bpf = {
        .cmd_type = IO_URING_BPF_CMD_FILTER,
        .filter = {
            .opcode = IORING_OP_NOP,
            .filter_len = 1,
            .filter_ptr = (unsigned long) deny_filter,
        },
    };

    /* Must set no_new_privs before registering task filters */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    /* Register on a specific ring */
    io_uring_register_bpf_filter(&ring, &bpf);

    /* Or register on the task */
    io_uring_register_bpf_filter_task(&bpf);
```

**Allow**\ only AF_INET sockets

```c
    #include <sys/prctl.h>
    #include <linux/filter.h>
    #include <sys/socket.h>
    #include <liburing.h>
    #include <liburing/io_uring/bpf_filter.h>

    #define CTX_OFF_SOCKET_FAMILY  16

    struct sock_filter inet_only_filter[] = {
        /* Load socket family from context */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, CTX_OFF_SOCKET_FAMILY),
        /* If family == AF_INET, jump to allow */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 1),
        /* Allow: return 1 */
        BPF_STMT(BPF_RET | BPF_K, 1),
        /* Deny: return 0 */
        BPF_STMT(BPF_RET | BPF_K, 0),
    };

    struct io_uring_bpf bpf = {
        .cmd_type = IO_URING_BPF_CMD_FILTER,
        .filter = {
            .opcode = IORING_OP_SOCKET,
            .filter_len = 4,
            .filter_ptr = (unsigned long) inet_only_filter,
            .pdu_size = 12,  /* 3x __u32: family, type, protocol */
        },
    };

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    io_uring_register_bpf_filter_task(&bpf);
```

**Allow**\ only NOP, deny everything else

```c
    struct sock_filter allow_filter[] = {
        BPF_STMT(BPF_RET | BPF_K, 1),  /* return 1 (allow) */
    };

    struct io_uring_bpf bpf = {
        .cmd_type = IO_URING_BPF_CMD_FILTER,
        .filter = {
            .opcode = IORING_OP_NOP,
            .flags = IO_URING_BPF_FILTER_DENY_REST,
            .filter_len = 1,
            .filter_ptr = (unsigned long) allow_filter,
        },
    };

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    io_uring_register_bpf_filter_task(&bpf);
```

**Discover**\ kernel pdu_size for an opcode

This example demonstrates how to use the **-EMSGSIZE** write-back to
discover the kernel's expected payload size.

```c
    struct sock_filter allow[] = {
        BPF_STMT(BPF_RET | BPF_K, 1),
    };

    struct io_uring_bpf bpf = {
        .cmd_type = IO_URING_BPF_CMD_FILTER,
        .filter = {
            .opcode = IORING_OP_SOCKET,
            .flags = IO_URING_BPF_FILTER_SZ_STRICT,
            .filter_len = 1,
            .filter_ptr = (unsigned long) allow,
            .pdu_size = 0,  /* intentionally wrong */
        },
    };
    int ret;

    ret = io_uring_register_bpf_filter(&ring, &bpf);
    if (ret == -EMSGSIZE) {
        /* kernel wrote back expected size */
        printf("kernel pdu_size for SOCKET: %u\n",
               bpf.filter.pdu_size);
        /* retry with correct size */
        ret = io_uring_register_bpf_filter(&ring, &bpf);
    }
```

# NOTES

**Privilege**\ Requirements

Similar to [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html), registering BPF filters requires either the
**CAP_SYS_ADMIN** capability or the **no_new_privs** attribute to be set
on the calling task. This prevents an unprivileged process from
installing a filter and then executing a setuid binary, which would run
with elevated privileges but under the attacker-controlled filter.

To set the **no_new_privs** attribute, call:

```c
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
```

Once set, **no_new_privs** cannot be unset and is inherited by child
processes across [fork](https://man7.org/linux/man-pages/man2/fork.2.html) and preserved across [execve](https://man7.org/linux/man-pages/man2/execve.2.html).

**Inheritance**\

Task-level filters registered with
[io_uring_register_bpf_filter_task] are inherited by child
processes. This allows a parent process to establish security
restrictions that apply to all descendants. Children can add additional
restrictions but cannot remove or weaken filters set by their ancestors.

Ring-level filters registered with [io_uring_register_bpf_filter]
only apply to that specific ring and are not inherited.

# SEE ALSO

[io_uring_register], [io_uring_setup], [bpf](https://man7.org/linux/man-pages/man2/bpf.2.html),
[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)
