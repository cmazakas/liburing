Register buffer ring for provided buffers.

# DESCRIPTION

The [io_uring_register_buf_ring] function registers a shared buffer
ring to be used with provided buffers. For the request types that
support it, provided buffers are given to the ring and one is selected
by a request if it has **IOSQE_BUFFER_SELECT** set in the SQE *flags*,
when the request is ready to receive data. This allows both clear
ownership of the buffer lifetime, and a way to have more read/receive
type of operations in flight than buffers available.

The *reg* argument must be filled in with the appropriate information.
It looks as follows:

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
appropriately using eg [posix_memalign](https://man7.org/linux/man-pages/man3/posix_memalign.3.html) or similar. The size of the
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

The *flags* argument can be set to one of the following values:

**IOU_PBUF_RING_INC**
The buffers in this ring can be incrementally consumed. With partial
consumption, each completion of a given buffer ID will continue where
the previous one left off, or from the start if no completions have been
seen yet. When more completions should be expected for a given buffer
ID, the CQE will have **IORING_CQE_F_BUF_MORE** set in the *flags*
member. Available since 6.12.

A shared buffer ring looks as follows:

```c
    struct io_uring_buf_ring {
        union {
            struct {
                __u64 resv1;
                __u32 resv2;
                __u16 resv3;
                __u16 tail;
            };
            struct io_uring_buf bufs[0];
        };
    };
```

where *tail* is the index at which the application can insert new
buffers for consumption by requests, and *struct io_uring_buf* is buffer
definition:

```c
    struct io_uring_buf {
        __u64 addr;
        __u32 len;
        __u16 bid;
        __u16 resv;
    };
```

where *addr* is the address for the buffer, *len* is the length of the
buffer in bytes, and *bid* is the buffer ID that will be returned in the
CQE once consumed.

Reserved fields must not be touched. Applications must use
[io_uring_buf_ring_init] to initialise the buffer ring before use.
Applications may use [io_uring_buf_ring_add] and
[io_uring_buf_ring_advance] or [io_uring_buf_ring_cq_advance]
to provide buffers, which will set these fields and update the tail.

Available since 5.19.

# RETURN VALUE

On success [io_uring_register_buf_ring] returns 0. On failure it
returns **-errno**.

# NOTES

Unless manual setup is needed, it's recommended to use
[io_uring_setup_buf_ring] as it provides a simpler way to setup a
provided buffer ring.

# SEE ALSO

[io_uring_buf_ring_init], [io_uring_buf_ring_add],
[io_uring_setup_buf_ring], [io_uring_buf_ring_advance],
[io_uring_buf_ring_cq_advance]
