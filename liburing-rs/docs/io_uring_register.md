Register files or user buffers for asynchronous I/O

# DESCRIPTION

The **io_uring_register**(2) system call registers resources (e.g. user
buffers, files, eventfd, personality, restrictions) for use in an
**io_uring**(7) instance referenced by *fd*. Registering files or user
buffers allows the kernel to take long term references to internal data
structures or create long term mappings of application memory, greatly
reducing per-I/O overhead.

*fd* is the file descriptor returned by a call to **io_uring_setup**(2).
If *opcode* has the flag **IORING_REGISTER_USE_REGISTERED_RING** ored
into it, *fd* is instead the index of a registered ring fd.

*opcode* can be one of:

**IORING_REGISTER_BUFFERS**\*arg* points to a *struct iovec* array of *nr_args* entries. The buffers
associated with the iovecs will be locked in memory and charged against
the user's **RLIMIT_MEMLOCK** resource limit. See **getrlimit**(2) for
more information. Additionally, there is a size limit of 1GiB per
buffer. Currently, the buffers must be anonymous, non-file-backed
memory, such as that returned by **malloc**(3) or **mmap**(2) with the
**MAP_ANONYMOUS** flag set. It is expected that this limitation will be
lifted in the future. Huge pages are supported as well. Note that the
entire huge page will be pinned in the kernel, even if only a portion of
it is used.

After a successful call, the supplied buffers are mapped into the kernel
and eligible for I/O. To make use of them, the application must specify
the **IORING_OP_READ_FIXED** or **IORING_OP_WRITE_FIXED** opcodes in the
submission queue entry (see the *struct io_uring_sqe* definition in
**io_uring_enter**(2)), and set the *buf_index* field to the desired
buffer index. The memory range described by the submission queue entry's
*addr* and *len* fields must fall within the indexed buffer.

It is perfectly valid to setup a large buffer and then only use part of
it for an I/O, as long as the range is within the originally mapped
region.

An application can increase or decrease the size or number of registered
buffers by first unregistering the existing buffers, and then issuing a
new call to **io_uring_register**(2) with the new buffers.

Note that before 5.13 registering buffers would wait for the ring to
idle. If the application currently has requests in-flight, the
registration will wait for those to finish before proceeding.

An application need not unregister buffers explicitly before shutting
down the io_uring instance. Note, however, that shutdown processing may
run asynchronously within the kernel. As a result, it is not guaranteed
that pages are immediately unpinned in this case. Available since 5.1.

<!-- -->

**IORING_REGISTER_BUFFERS2**\
Register buffers for I/O. Similar to **IORING_REGISTER_BUFFERS** but
aims to have a more extensible ABI.

*arg* points to a *struct* *io_uring_rsrc_register*, and *nr_args*
should be set to the number of bytes in the structure.

```c
    struct io_uring_rsrc_register {
        __u32 nr;
        __u32 flags;
        __u64 resv2;
        __aligned_u64 data;
        __aligned_u64 tags;
    };
```

The *data* field contains a pointer to a *struct iovec* array of *nr*
entries. The *tags* field should either be 0, then tagging is disabled,
or point to an array of *nr* "tags" (unsigned 64 bit integers). If a tag
is zero, then tagging for this particular resource (a buffer in this
case) is disabled. Otherwise, after the resource had been unregistered
and it's not used anymore, a CQE will be posted with *user_data* set to
the specified tag and all other fields zeroed.

The *flags* field supports the following flags:

**IORING_RSRC_REGISTER_SPARSE**\
If set, io_uring will register *nr*
empty buffers, which need to be updated before use. When this flag is
set, *data* and *tags* must be NULL. Available since 5.19.

Note that resource updates, e.g. **IORING_REGISTER_BUFFERS_UPDATE**,
don't necessarily deallocate resources by the time it returns, but they
might be held alive until all requests using it complete.

Available since 5.13.

**IORING_REGISTER_BUFFERS_UPDATE**\
Updates registered buffers with new ones, either turning a sparse entry
into a real one, or replacing an existing entry.

*arg* must contain a pointer to a *struct* *io_uring_rsrc_update2*,
which contains an offset on which to start the update, and an array of
*struct* *iovec*. *tags* points to an array of tags. *nr* must contain
the number of descriptors in the passed in arrays. See
**IORING_REGISTER_BUFFERS2** for the resource tagging description.

<!-- -->

```c
    struct io_uring_rsrc_update2 {
        __u32 offset;
        __u32 resv;
        __aligned_u64 data;
        __aligned_u64 tags;
        __u32 nr;
        __u32 resv2;
    };
```

Available since 5.13.

**IORING_UNREGISTER_BUFFERS**\
This operation takes no argument, and *arg* must be passed as NULL. All
previously registered buffers associated with the io_uring instance will
be released synchronously. Available since 5.1.

<!-- -->

**IORING_REGISTER_FILES**\
Register files for I/O. *arg* contains a pointer to an array of
*nr_args* file descriptors (signed 32 bit integers).

To make use of the registered files, the **IOSQE_FIXED_FILE** flag must
be set in the *flags* member of the *struct io_uring_sqe*, and the *fd*
member is set to the index of the file in the file descriptor array.

The file set may be sparse, meaning that the **fd** field in the array
may be set to **-1**. See **IORING_REGISTER_FILES_UPDATE** for how to
update files in place.

Note that before 5.13 registering files would wait for the ring to idle.
If the application currently has requests in-flight, the registration
will wait for those to finish before proceeding. See
**IORING_REGISTER_FILES_UPDATE** for how to update an existing set
without that limitation.

Files are automatically unregistered when the io_uring instance is torn
down. An application needs only unregister if it wishes to register a
new set of fds. Available since 5.1.

<!-- -->

**IORING_REGISTER_FILES2**\
Register files for I/O. Similar to **IORING_REGISTER_FILES**.

*arg* points to a *struct* *io_uring_rsrc_register*, and *nr_args*
should be set to the number of bytes in the structure.

The *data* field contains a pointer to an array of *nr* file descriptors
(signed 32 bit integers). *tags* field should either be 0 or or point to
an array of *nr* "tags" (unsigned 64 bit integers). See
**IORING_REGISTER_BUFFERS2** for more info on resource tagging.

Note that resource updates, e.g. **IORING_REGISTER_FILES_UPDATE**, don't
necessarily deallocate resources, they might be held until all requests
using that resource complete.

Available since 5.13.

<!-- -->

**IORING_REGISTER_FILES_UPDATE**\
This operation replaces existing files in the registered file set with
new ones, either turning a sparse entry (one where fd is equal to
**-1**) into a real one, removing an existing entry (new one is set to
**-1**), or replacing an existing entry with a new existing entry.

*arg* must contain a pointer to a *struct* *io_uring_rsrc_update*, which
contains an offset on which to start the update, and an array of file
descriptors to use for the update. *nr_args* must contain the number of
descriptors in the passed in array. Available since 5.5.

File descriptors can be skipped if they are set to
**IORING_REGISTER_FILES_SKIP**. Skipping an fd will not touch the file
associated with the previous fd at that index. Available since 5.12.

<!-- -->

**IORING_REGISTER_FILES_UPDATE2**\
Similar to **IORING_REGISTER_FILES_UPDATE**, replaces existing files in
the registered file set with new ones, either turning a sparse entry
(one where fd is equal to **-1**) into a real one, removing an existing
entry (new one is set to **-1**), or replacing an existing entry with a
new existing entry.

*arg* must contain a pointer to a *struct* *io_uring_rsrc_update2*,
which contains an offset on which to start the update, and an array of
file descriptors to use for the update stored in *data*. *tags* points
to an array of tags. *nr* must contain the number of descriptors in the
passed in arrays. See **IORING_REGISTER_BUFFERS2** for the resource
tagging description.

Available since 5.13.

<!-- -->

**IORING_UNREGISTER_FILES**\
This operation requires no argument, and *arg* must be passed as NULL.
All previously registered files associated with the io_uring instance
will be unregistered. Available since 5.1.

<!-- -->

**IORING_REGISTER_EVENTFD**\
It's possible to use **eventfd**(2) to get notified of completion events
on an io_uring instance. If this is desired, an eventfd file descriptor
can be registered through this operation. *arg* must contain a pointer
to the eventfd file descriptor, and *nr_args* must be 1. Note that while
io_uring generally takes care to avoid spurious events, they can occur.
Similarly, batched completions of CQEs may only trigger a single eventfd
notification even if multiple CQEs are posted. The application should
make no assumptions on number of events being available having a direct
correlation to eventfd notifications posted. An eventfd notification
must thus only be treated as a hint to check the CQ ring for
completions. Available since 5.2.

An application can temporarily disable notifications, coming through the
registered eventfd, by setting the **IORING_CQ_EVENTFD_DISABLED** bit in
the *flags* field of the CQ ring. Available since 5.8.

<!-- -->

**IORING_REGISTER_EVENTFD_ASYNC**\
This works just like **IORING_REGISTER_EVENTFD**, except notifications
are only posted for events that complete in an async manner. This means
that events that complete inline while being submitted do not trigger a
notification event. The arguments supplied are the same as for
**IORING_REGISTER_EVENTFD**. Available since 5.6.

<!-- -->

**IORING_UNREGISTER_EVENTFD**\
Unregister an eventfd file descriptor to stop notifications. Since only
one eventfd descriptor is currently supported, this operation takes no
argument, and *arg* must be passed as NULL and *nr_args* must be zero.
Available since 5.2.

<!-- -->

**IORING_REGISTER_PROBE**\
This operation returns a structure, io_uring_probe, which contains
information about the opcodes supported by io_uring on the running
kernel. *arg* must contain a pointer to a struct io_uring_probe, and
*nr_args* must contain the size of the ops array in that probe struct.
The ops array is of the type io_uring_probe_op, which holds the value of
the opcode and a flags field. If the flags field has
**IO_URING_OP_SUPPORTED** set, then this opcode is supported on the
running kernel. Available since 5.6.

<!-- -->

**IORING_REGISTER_PERSONALITY**\
This operation registers credentials of the running application with
io_uring, and returns an id associated with these credentials.
Applications wishing to share a ring between separate users/processes
can pass in this credential id in the sqe **personality** field. If set,
that particular sqe will be issued with these credentials. Must be
invoked with *arg* set to NULL and *nr_args* set to zero. Available
since 5.6.

<!-- -->

**IORING_UNREGISTER_PERSONALITY**\
This operation unregisters a previously registered personality with
io_uring. *nr_args* must be set to the id in question, and *arg* must be
set to NULL. Available since 5.6.

<!-- -->

**IORING_REGISTER_ENABLE_RINGS**\
This operation enables an io_uring ring started in a disabled state
(**IORING_SETUP_R_DISABLED** was specified in the call to
**io_uring_setup**(2)). While the io_uring ring is disabled, submissions
are not allowed and registrations are not restricted.

After the execution of this operation, the io_uring ring is enabled:
submissions and registration are allowed, but they will be validated
following the registered restrictions (if any). This operation takes no
argument, must be invoked with *arg* set to NULL and *nr_args* set to
zero. Available since 5.10.

<!-- -->

**IORING_REGISTER_RESTRICTIONS**\
*arg* points to a *struct io_uring_restriction* array of *nr_args*
entries.

With an entry it is possible to allow an **io_uring_register**(2)
*opcode*, or specify which *opcode* and *flags* of the submission queue
entry are allowed, or require certain *flags* to be specified (these
flags must be set on each submission queue entry).

All the restrictions must be submitted with a single
**io_uring_register**(2) call and they are handled as an allowlist
(opcodes and flags not registered, are not allowed).

Restrictions can be registered only if the io_uring ring started in a
disabled state (**IORING_SETUP_R_DISABLED** must be specified in the
call to **io_uring_setup**(2)).

Available since 5.10.

<!-- -->

**IORING_REGISTER_IOWQ_AFF**\
By default, async workers created by io_uring will inherit the CPU mask
of its parent. This is usually all the CPUs in the system, unless the
parent is being run with a limited set. If this isn't the desired
outcome, the application may explicitly tell io_uring what CPUs the
async workers may run on. *arg* must point to a **cpu_set_t** mask, and
*nr_args* the byte size of that mask.

Available since 5.14.

<!-- -->

**IORING_UNREGISTER_IOWQ_AFF**\
Undoes a CPU mask previously set with **IORING_REGISTER_IOWQ_AFF**. Must
not have *arg* or *nr_args* set.

Available since 5.14.

<!-- -->

**IORING_REGISTER_IOWQ_MAX_WORKERS**\
By default, io_uring limits the unbounded workers created to the maximum
processor count set by *RLIMIT_NPROC* and the bounded workers is a
function of the SQ ring size and the number of CPUs in the system.
Sometimes this can be excessive (or too little, for bounded), and this
command provides a way to change the count per ring (per NUMA node)
instead.

*arg* must be set to an *unsigned int* pointer to an array of two
values, with the values in the array being set to the maximum count of
workers per NUMA node. Index 0 holds the bounded worker count, and index
1 holds the unbounded worker count. On successful return, the passed in
array will contain the previous maximum values for each type. If the
count being passed in is 0, then this command returns the current
maximum values and doesn't modify the current setting. *nr_args* must be
set to 2, as the command takes two values.

Available since 5.15.

<!-- -->

**IORING_REGISTER_RING_FDS**\
Whenever **io_uring_enter**(2) is called to submit request or wait for
completions, the kernel must grab a reference to the file descriptor. If
the application using io_uring is threaded, the file table is marked as
shared, and the reference grab and put of the file descriptor count is
more expensive than it is for a non-threaded application.

Similarly to how io_uring allows registration of files, this allow
registration of the ring file descriptor itself. This reduces the
overhead of the **io_uring_enter**(2) system call.

*arg* must be set to a pointer to an array of type *struct
io_uring_rsrc_update* of *nr_args* number of entries. The **data** field
of this struct must contain an io_uring file descriptor, and the
**offset** field can be either **-1** or an explicit offset desired for
the registered file descriptor value. If **-1** is used, then upon
successful return of this system call, the field will contain the value
of the registered file descriptor to be used for future
**io_uring_enter**(2) system calls.

On successful completion of this request, the returned descriptors may
be used instead of the real file descriptor for **io_uring_enter**(2),
provided that **IORING_ENTER_REGISTERED_RING** is set in the *flags* for
the system call. This flag tells the kernel that a registered descriptor
is used rather than a real file descriptor.

Each thread or process using a ring must register the file descriptor
directly by issuing this request.

The maximum number of supported registered ring descriptors is currently
limited to **16.**

Available since 5.18.

<!-- -->

**IORING_UNREGISTER_RING_FDS**\
Unregister descriptors previously registered with
**IORING_REGISTER_RING_FDS**.

*arg* must be set to a pointer to an array of type *struct
io_uring_rsrc_update* of *nr_args* number of entries. Only the
**offset** field should be set in the structure, containing the
registered file descriptor offset previously returned from
**IORING_REGISTER_RING_FDS** that the application wishes to unregister.

Note that this isn't done automatically on ring exit, if the thread or
task that previously registered a ring file descriptor isn't exiting. It
is recommended to manually unregister any previously registered ring
descriptors if the ring is closed and the task persists. This will free
up a registration slot, making it available for future use.

Available since 5.18.

<!-- -->

**IORING_REGISTER_PBUF_RING**\
Registers a shared buffer ring to be used with provided buffers. This is
a newer alternative to using **IORING_OP_PROVIDE_BUFFERS** which is more
efficient, to be used with request types that support the
**IOSQE_BUFFER_SELECT** flag.

The *arg* argument must be filled in with the appropriate information.
It looks as follows:

<!-- -->

```c
    struct io_uring_buf_reg {
        __u64 ring_addr;
        __u32 ring_entries;
        __u16 bgid;
        __u16 flags;
        __u32 min_left;
        __u32 resv[5];
    };
```

The *ring_addr* field must contain the address to the memory allocated
to fit this ring. The memory must be page aligned and hence allocated
appropriately using eg **posix_memalign**(3) or similar. The size of the
ring is the product of *ring_entries* and the size of *struct
io_uring_buf*. *ring_entries* is the desired size of the ring, and must
be a power-of-2 in size. The maximum size allowed is 2^15 (32768).
*bgid* is the buffer group ID associated with this ring. SQEs that
select a buffer have a buffer group associated with them in their
*buf_group* field, and the associated CQEs will have
**IORING_CQE_F_BUFFER** set in their *flags* member, which will also
contain the specific ID of the buffer selected. *min_left* is the
minimum value that should be left in an incrementally consumed buffer
ring for the buffer to be considered valid. If not set, defaults to a
single byte. Only valid with **IOU_PBUF_RING_INC** set in *flags .* The
rest of the fields are reserved and must be cleared to zero.

*nr_args* must be set to 1.

Also see **io_uring_register_buf_ring**(3) for more details. Available
since 5.19.

**IORING_UNREGISTER_PBUF_RING**\
Unregister a previously registered provided buffer ring. *arg* must be
set to the address of a struct io_uring_buf_reg, with just the *bgid*
field set to the buffer group ID of the previously registered provided
buffer group. *nr_args* must be set to 1. Also see
**IORING_REGISTER_PBUF_RING**.

Available since 5.19.

<!-- -->

**IORING_REGISTER_SYNC_CANCEL**\
Performs a synchronous cancelation request, which works in a similar
fashion to **IORING_OP_ASYNC_CANCEL** except it completes inline. This
can be useful for scenarios where cancelations should happen
synchronously, rather than needing to issue an SQE and wait for
completion of that specific CQE.

*arg* must be set to a pointer to a struct io_uring_sync_cancel_reg
structure, with the details filled in for what request(s) to target for
cancelation. See **io_uring_register_sync_cancel**(3) for details on
that. The return values are the same, except they are passed back
synchronously rather than through the CQE *res* field. *nr_args* must be
set to 1.

Available since 6.0.

<!-- -->

**IORING_REGISTER_FILE_ALLOC_RANGE**\
sets the allowable range for fixed file index allocations within the
kernel. When requests that can instantiate a new fixed file are used
with **IORING_FILE_INDEX_ALLOC**, the application is asking the kernel
to allocate a new fixed file descriptor rather than pass in a specific
value for one. By default, the kernel will pick any available fixed file
descriptor within the range available. This effectively allows the
application to set aside a range just for dynamic allocations, with the
remainder being used for specific values.

*nr_args* must be set to 1 and *arg* must be set to a pointer to a
struct io_uring_file_index_range:

<!-- -->

```c
    struct io_uring_file_index_range {
        __u32 off;
        __u32 len;
        __u64 resv;
    };
```

with *off* being set to the starting value for the range, and *len*
being set to the number of descriptors. The reserved *resv* field must
be cleared to zero.

The application must have registered a file table first.

Available since 6.0.

**IORING_REGISTER_PBUF_STATUS**\
Can be used to retrieve the current head of a ringbuffer provided
earlier via **IORING_REGISTER_PBUF_RING**. *arg* must point to a

<!-- -->

```c
    struct io_uring_buf_status {
    	__u32	buf_group;	/* input */
    	__u32	head;		/* output */
    	__u32	resv[8];
    };
```

of which *arg-\>buf_group* should contain the buffer group ID for the
buffer ring in question, *nr_args* should be set to 1 and *arg-\>resv*
should be zeroed out. The current head of the ringbuffer will be
returned in *arg-\>head*.

Available since 6.8.

**IORING_REGISTER_NAPI**\
Registers a napi instance with the io_uring instance of *fd*. *arg*
should point to a

<!-- -->

```c
    struct io_uring_napi {
    	__u32	busy_poll_to;
    	__u8	prefer_busy_poll;
    	__u8	pad[3];
    	__u64	resv;
    };
```

in which *arg-\>busy_poll_to* should contain the busy poll timeout in
micro seconds and *arg-\>prefer_busy_poll* should specify whether busy
polling should be used rather than IRQs. *nr_args* should be set to 1
and *arg-\>pad* and *arg-\>resv* should be zeroed out. On successful
return the *io_uring_napi* struct pointed to by *arg* will contain the
previously used settings.

Available since 6.9.

**IORING_UNREGISTER_NAPI**\
Unregisters a napi instance previously registered via
**IORING_REGISTER_NAPI** to the io_uring instance of *fd*. *arg* should
point to a *struct* *io_uring_napi*. On successful return the
*io_uring_napi* struct pointed to by *arg* will contain the previously
used settings.

Available since 6.9.

<!-- -->

**IORING_REGISTER_CLOCK**\
Specifies which clock id io_uring will use for timers while waiting for
completion events with **IORING_ENTER_GETEVENTS**. It's only effective
if the timeout argument in *struct io_uring_getevents_arg* is passed,
ignored otherwise. When used in conjunction with
**IORING_ENTER_ABS_TIMER**, interprets the timeout argument as absolute
time of the specified clock.

The default clock is **CLOCK_MONOTONIC**.

Available since 6.12 and supports **CLOCK_MONOTONIC** and
**CLOCK_BOOTTIME**.

<!-- -->

**IORING_REGISTER_CLONE_BUFFERS**\
Supports cloning buffers from a source ring to a destination ring,
duplicating previously registered buffers from source to destination.
*arg* must be set to a pointer to a *struct io_uring_clone_buffers* and
*nr_args* must be set to **1 .** *struct io_uring_buf_reg* looks as
follows:

<!-- -->

```c
    struct io_uring_clone_buffers {
        __u32 src_fd;
        __u32 flags;
        __u32 src_off;
        __u32 dst_off;
        __u32 nr;
        __u32 pad[3];
    };
```

where *src_fd* indicates the fd of the source ring, *flags* are modifier
flags for the operation, *src_off* indicates the offset from where to
start the cloning from the source ring, *dst_off* indicates the offset
from where to start the cloning into the destination ring, and *nr*
indicates the number of buffers to clone at the given offsets. *pad*
must be zero filled. Kernel 6.12 added support for full range cloning,
where *src_off*, *dst_off*, and *nr* must all be set to 0, indicating
cloning of the entire table in source to destination. Kernel 6.13 added
support for specifying the offsets and how many buffers to clone.
Additionally, it added support for cloning into a previously registered
table in the destination as well, 6.12 would fail that operation with
**-EBUSY** if attempted. To replace existing nodes, or clone into an
existing table, **IORING_REGISTER_DST_REPLACE** must be set in the
*flags* member.

**IORING_REGISTER_SEND_MSG_RING**\
Supports sending of the equivalent of a **IORING_OP_MSG_RING** request,
but without having a source ring available. Takes a pointer to a
*struct*io_uring_sqe which must be prepared with
**io_uring_prep_msg_ring**(3) before being submitted. Only supports
**IORING_MSG_DATA** type of requests. Available since kernel 6.13.

<!-- -->

**IORING_REGISTER_RESIZE_RINGS**\
Supports resizing the SQ and CQ rings. Takes a pointer to a
*struct*io_uring_params as the argument, where *sq_entries* and
*cq_entries* may be set to the desired values. Only supports a limited
set of flags set in the *struct*io_uring_params argument, notably
**IORING_SETUP_CQSIZE** and **IORING_SETUP_CLAMP** to modify the CQ ring
sizing. See **io_uring_resize_rings**(3) for details. Note that while
liburing takes care of the ring unmap and mapping for a resize
operation, manual users of this register syscall must perform those
operations, similarly to when a new ring is created. The
*struct*io_uring_params structure will get the necessary offsets copied
back upon successful completion of this system call, which can be used
to memory map the ring just like how a new ring would've been mapped.
Available since kernel 6.13.

<!-- -->

**IORING_REGISTER_MEM_REGION**\
Supports registering multiple purposes memory regions, avoiding
unnecessary copying in of *struct*io_uring_getevents_arg for wait
operations that specify a timeout or minimum timeout. Takes a pointer to
a *struct*io_uring_mem_region_reg structure, which looks as follows:

<!-- -->

```c
    struct io_uring_mem_region_reg {
        __u64 region_uptr;
        __u64 flags;
        __u64 __resv[2];
    };
```

where *region_uptr* must be set to the region being registered as memory
regions, *flags* specifies modifier flags (must currently be
**IORING_MEM_REGION_REG_WAIT_ARG ). The pad fields must all be cleared
to** **0 .** Each memory regions looks as follows:

```c
    struct io_uring_region_desc {
        __u64 user_addr;
        __u64 size;
        __u32 flags;
        __u32 id;
        __u64 mmap_offset;
        __u64 __resv[4];
    };
```

where *user_addr* points to userspace memory mappings, *size* is the
size of userspace memory. Current supported userspace memory regions
looks as follows:

```c
    struct io_uring_reg_wait {
        struct __kernel_timespec ts;
        __u32                    min_wait_usec;
        __u32                    flags;
        __u64                    sigmask;
        __u32                    sigmask_sz;
        __u32                    pad[3];
        __u64                    pad2[2];
    };
```

where *ts* holds the timeout information for this region *flags* holds
information about the timeout region, *sigmask* is a pointer to a signal
mask, if used, and *sigmask_sz* is the size of that signal mask. The pad
fields must all be cleared to **0 .** Currently the only valid flag is
**IORING_REG_WAIT_TS ,** which, if set, says that the values in *ts* are
valid and should be used for a timeout operation. The *user_addr* field
of *struct*io_uring_region_desc must be set to an address of
*struct*io_uring_reg_wait members, an up to a page size can be mapped.
At the size of 64 bytes per region, that allows at least 64 individual
regions on a 4k page size system. The offsets of these regions are used
for an **io_uring_enter**(2) system call, with the first one being 0,
second one 1, and so forth. After registration of the wait regions,
**io_uring_enter**(2) may be used with the enter flag of
**IORING_ENTER_EXT_ARG_REG and an** *argp* set to the wait region
offset, rather than a pointer to a *struct*io_uring_getevent_arg
structure. If used with **IORING_ENTER_GETEVENTS ,** then the wait
operation will use the information in the registered wait region rather
than needing a io_uring_getevent_arg structure copied for each
operation. For high frequency waits, this can save considerable CPU
cycles. Note: once a region has been registered, it cannot get
unregistered. It lives for the life of the ring. Individual wait region
offset may be modified before any **io_uring_enter**(2) system call.
Available since kernel 6.13.

**IORING_REGISTER_ZCRX_IFQ**\
Registers a zero-copy receive interface queue for network receive
operations. Zero-copy receive allows the kernel to place incoming
network data directly into application-provided memory without copying,
reducing CPU overhead for high-bandwidth network workloads. *arg* must
point to a *struct io_uring_zcrx_ifq_reg* structure, and *nr_args* must
be set to 1.

<!-- -->

```c
    struct io_uring_zcrx_ifq_reg {
        __u32 if_idx;
        __u32 if_rxq;
        __u32 rq_entries;
        __u32 flags;
        __u64 area_ptr;
        __u64 region_ptr;
        struct io_uring_zcrx_offsets offsets;
        __u32 zcrx_id;
        __u32 __resv2;
        __u64 __resv[3];
    };
```

where *if_idx* is the network interface index, *if_rxq* is the receive
queue index, *rq_entries* is the number of entries in the refill queue
(will be rounded up to a power of two), *flags* contains modifier flags,
*area_ptr* points to a *struct io_uring_zcrx_area_reg* describing the
memory area to use, *region_ptr* points to a *struct
io_uring_region_desc* describing the memory region, and upon successful
return *zcrx_id* will contain the ID of the registered zero-copy receive
context. The *offsets* field is filled in by the kernel and contains the
ring offsets for the refill queue.

The io_uring ring must have been created with
**IORING_SETUP_DEFER_TASKRUN** and either **IORING_SETUP_CQE32** or
**IORING_SETUP_CQE_MIXED** flags set. The caller must have the
**CAP_NET_ADMIN** capability.

Available since kernel 6.15.

**IORING_REGISTER_QUERY**\
Queries io_uring capabilities and feature support. This operation does
not require an io_uring ring and can be called with *fd* set to -1. It
provides information about supported opcodes, flags, and
subsystem-specific capabilities. *arg* must point to a *struct
io_uring_query_hdr* and *nr_args* must be 0.

<!-- -->

```c
    struct io_uring_query_hdr {
        __u64 next_entry;
        __u64 query_data;
        __u32 query_op;
        __u32 size;
        __s32 result;
        __u32 __resv[3];
    };
```

Multiple queries can be chained together via *next_entry* which points
to the next *struct io_uring_query_hdr* (or 0 for the last entry).
*query_data* points to a data structure appropriate for the query type.
*query_op* specifies the query type and can be one of:

- **IO_URING_QUERY_OPCODES** - Returns information about supported
  opcodes and flags in a *struct io_uring_query_opcode*

- **IO_URING_QUERY_ZCRX** - Returns information about zero-copy receive
  support in a *struct io_uring_query_zcrx*

- **IO_URING_QUERY_SCQ** - Returns information about the SQ/CQ ring
  layout in a *struct io_uring_query_scq*

*size* should be set to the size of the data structure pointed to by
*query_data*. Upon return, *result* will be 0 on success, or a negative
error code.

Available since kernel 6.15.

**IORING_REGISTER_ZCRX_CTRL**\
Performs control operations on a previously registered zero-copy receive
context. *arg* must point to a *struct zcrx_ctrl* and *nr_args* must be
0.

<!-- -->

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

where *zcrx_id* is the ID of the zero-copy receive context returned from
**IORING_REGISTER_ZCRX_IFQ**, and *op* specifies the control operation:

- **ZCRX_CTRL_FLUSH_RQ** - Flushes pending buffers from the refill queue

- **ZCRX_CTRL_EXPORT** - Exports the zero-copy receive context for use
  by other rings

Available since kernel 6.15.

# RETURN VALUE

On success, **io_uring_register**(2) returns either 0 or a positive
value, depending on the *opcode* used. On error, a negative error value
is returned. The caller should not rely on the *errno* variable.

# ERRORS

**EACCES**\
The *opcode* field is not allowed due to registered restrictions.

**EBADF**\
One or more fds in the *fd* array are invalid.

**EBADFD**\
**IORING_REGISTER_ENABLE_RINGS** or **IORING_REGISTER_RESTRICTIONS** was
specified, but the io_uring ring is not disabled.

**EBUSY**\
**IORING_REGISTER_BUFFERS** or **IORING_REGISTER_FILES** or
**IORING_REGISTER_RESTRICTIONS** was specified, but there were already
buffers, files, or restrictions registered.

**EEXIST**\
The thread performing the registration is invalid.

**EFAULT**\
buffer is outside of the process' accessible address space, or *iov_len*
is greater than 1GiB.

**EINVAL**\
**IORING_REGISTER_BUFFERS** or **IORING_REGISTER_FILES** was specified,
but *nr_args* is 0.

**EINVAL**\
**IORING_REGISTER_BUFFERS** was specified, but *nr_args* exceeds
**UIO_MAXIOV**

**EINVAL**\
**IORING_UNREGISTER_BUFFERS** or **IORING_UNREGISTER_FILES** was
specified, and *nr_args* is non-zero or *arg* is non-NULL.

**EINVAL**\
**IORING_REGISTER_RESTRICTIONS** was specified, but *nr_args* exceeds
the maximum allowed number of restrictions or restriction *opcode* is
invalid.

**EMFILE**\
**IORING_REGISTER_FILES** was specified and *nr_args* exceeds the
maximum allowed number of files in a fixed file set.

**EMFILE**\
**IORING_REGISTER_FILES** was specified and adding *nr_args* file
references would exceed the maximum allowed number of files the user is
allowed to have according to the **RLIMIT_NOFILE** resource limit and
the caller does not have **CAP_SYS_RESOURCE** capability. Note that this
is a per user limit, not per process.

**ENOMEM**\
Insufficient kernel resources are available, or the caller had a
non-zero **RLIMIT_MEMLOCK** soft resource limit, but tried to lock more
memory than the limit permitted. This limit is not enforced if the
process is privileged (**CAP_IPC_LOCK**).

**ENXIO**\
**IORING_UNREGISTER_BUFFERS** or **IORING_UNREGISTER_FILES** was
specified, but there were no buffers or files registered.

**ENXIO**\
Attempt to register files or buffers on an io_uring instance that is
already undergoing file or buffer registration, or is being torn down.

**EOPNOTSUPP**\
User buffers point to file-backed memory.

**EFAULT**\
User buffers point to file-backed memory (newer kernels).

**ENOENT**\
**IORING_REGISTER_PBUF_STATUS** was specified, but *buf_group* did not
refer to a currently valid buffer group.

**EINVAL**\
**IORING_REGISTER_PBUF_STATUS** was specified, but the valid buffer
group specified by *buf_group* did not refer to a buffer group
registered via **IORING_REGISTER_PBUF_RING**.

**EINVAL**\
**IORING_REGISTER_NAPI** was specified, but the ring associated with
*fd* has not been created with **IORING_SETUP_IOPOLL**.
