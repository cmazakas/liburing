Register a memory region

# DESCRIPTION

The [io_uring_register_region] function registers a memory region
to io_uring. Upon successful completion, the memory region may then be
used, for example, to pass waiting parameters to the
[io_uring_enter] system call in a more efficient manner as it
avoids copying wait related data for each wait event. The *ring*
argument should point to the ring in question, and the *reg* argument
should be a pointer to a **struct io_uring_mem_region_reg .**

The *reg* argument must be filled in with the appropriate information.
It looks as follows:

``` c
struct io_uring_mem_region_reg {
    __u64 region_uptr;
    __u64 flags;
    __u64 __resv[2];
};
```

The *region_uptr* field must contain a pointer to an appropriately
filled **struct io_uring_region_desc.**

The *flags* field must contain a bitmask of the following values:

**IORING_MEM_REGION_REG_WAIT_ARG**\
allows use of the region to pass waiting parameters to the
[io_uring_enter] system call. If set, the registration is only
allowed while the ring is in a disabled mode. See
**IORING_SETUP_R_DISABLED.**

The \_\_resv fields must be filled with zeroes.

**struct io_uring_region_desc** is defined as following:

``` c
struct io_uring_region_desc {
    __u64 user_addr;
    __u64 size;
    __u32 flags;
    __u32 id;
    __u64 mmap_offset;
    __u64 __resv[4];
};
```

The *user_addr* field must contain a pointer to the memory the user
wants to register. It's valid only if **IORING_MEM_REGION_TYPE_USER** is
set, and should be zero otherwise.

The *size* field should contain the size of the region.

The *flags* field must contain a bitmask of the following values:

**IORING_MEM_REGION_TYPE_USER**\
tells the kernel to use memory specified by the *user_addr* field. If
not set, the kernel will allocate memory for the region, which can then
be mapped into the user space.

On successful registration of a region with kernel provided memory, the
*mmap_offset* field will contain an offset that can be passed to the
**mmap(2)** system call to map the region into the user space.

The *id* field is reserved and must be set to zero.

The *\_\_resv* fields must be filled with zeroes.

Available since kernel 6.13.

# RETURN VALUE

On success [io_uring_register_region] returns 0. On failure it
returns **-errno**.
