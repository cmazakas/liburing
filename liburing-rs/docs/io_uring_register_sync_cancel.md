Issue a synchronous cancelation request

# DESCRIPTION

The [io_uring_register_sync_cancel] function performs a synchronous
cancelation request based on the parameters specified in *reg .*

The *reg* argument must be filled in with the appropriate information
for the cancelation request. It looks as follows:

    struct io_uring_sync_cancel_reg {
        __u64 addr;
        __s32 fd;
        __u32 flags;
        struct __kernel_timespec timeout;
        __u8 opcode;
        __u8 pad[7](https://man7.org/linux/man-pages/man2/7.2.html);
        __u64 pad2[3](https://man7.org/linux/man-pages/man2/3.2.html);
    };

The arguments largely mirror what the async prep functions support, see
[io_uring_prep_cancel] for details. Similarly, the return value is
the same. The exception is the *timeout* argument, which can be used to
limit the time that the kernel will wait for cancelations to be
successful. If the *tv_sec* and *tv_nsec* values are set to anything but
**-1UL ,** then they indicate a relative timeout upon which cancelations
should be completed by.

The *pad* values must be zero filled.

# RETURN VALUE

See [io_uring_prep_cancel] for details on the return value. If
*timeout* is set to indicate a timeout, then **-ETIME** will be returned
if exceeded. If an unknown value is set in the request, or if the pad
values are not cleared to zero, then *-EINVAL* is returned.

# SEE ALSO

[io_uring_prep_cancel]
