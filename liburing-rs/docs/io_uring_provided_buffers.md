io_uring provided buffer rings overview

# DESCRIPTION

Provided buffer rings allow applications to supply a pool of buffers to
the kernel that can be dynamically selected at operation completion
time. This is particularly useful for operations where the buffer
requirements are not known upfront, such as receiving data from network
sockets or reading from pipes.

## Why use provided buffers?

Traditional I/O operations require the application to specify a buffer
when submitting the request. For receive operations on sockets or reads
from pipes, this presents a challenge: the application doesn't know how
much data will arrive, so it must either:

- Allocate a large buffer for each pending operation, wasting memory

- Use small buffers and potentially require multiple operations

- Limit the number of pending operations to control memory usage

Provided buffer rings solve this by letting the kernel select an
appropriately-sized buffer from a shared pool at completion time.
Multiple operations can share the same buffer pool, and buffers are only
consumed when data actually arrives.

Provided buffers are most beneficial for:

- Network servers with many concurrent connections

- Applications receiving variable-length messages

- Scenarios where memory efficiency is important

## Buffer ring concepts

A provided buffer ring is a circular buffer shared between the
application and kernel:

- The application adds buffers to the ring by writing entries and
  advancing the tail

- The kernel consumes buffers from the ring by reading entries and
  advancing the head

- Each buffer has a unique buffer ID (bid) within its buffer group

- Buffer groups are identified by a buffer group ID (bgid)

Multiple buffer rings can exist simultaneously, each with a different
buffer group ID. Operations specify which buffer group to use.

## Setting up a buffer ring

Buffer rings are set up using [io_uring_setup_buf_ring], which
handles allocation, registration, and initialization:

``` c
struct io_uring_buf_ring *br;
int bgid = 1;  /* buffer group ID */
int err;

br = io_uring_setup_buf_ring(ring, 128, bgid, 0, &err);
if (!br) {
    fprintf(stderr, "buffer ring setup failed: %d\n", err);
    return err;
}
```

The ring must have a power-of-two number of entries, up to a maximum of
32768 (2^15).

Alternatively, applications can use [io_uring_register_buf_ring]
for more control over the setup process, including kernel-allocated
rings using the **IOU_PBUF_RING_MMAP** flag.

## Adding buffers to the ring

Buffers are added using [io_uring_buf_ring_add] and made visible to
the kernel with [io_uring_buf_ring_advance]:

``` c
int mask = io_uring_buf_ring_mask(128);

for (int i = 0; i < 128; i++) {
    void *buf = malloc(4096);
    io_uring_buf_ring_add(br, buf, 4096, i, mask, i);
}
io_uring_buf_ring_advance(br, 128);
```

Each buffer is assigned a buffer ID (the third parameter). Buffer IDs
should be unique within the buffer group but can be reused after a
buffer is returned.

## Using provided buffers in operations

To use provided buffers, set the **IOSQE_BUFFER_SELECT** flag on the SQE
and specify the buffer group ID:

``` c
struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
io_uring_prep_recv(sqe, sockfd, NULL, 4096, 0);
io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
io_uring_sqe_set_buf_group(sqe, bgid);
```

Note that *addr* is set to NULL (or ignored) since the kernel will
select the buffer. The *len* field specifies the maximum amount of data
to receive.

Operations that support provided buffers include:

- **IORING_OP_READ** / **IORING_OP_RECV**

- **IORING_OP_READV** (single vector only)

- **IORING_OP_RECVMSG**

## Handling completions

When an operation using provided buffers completes, the CQE indicates
which buffer was used:

- **IORING_CQE_F_BUFFER** is set in *cqe-\>flags*

- The buffer ID is in the upper 16 bits of *cqe-\>flags*, extractable
  via **cqe-\>flags \>\> IORING_CQE_BUFFER_SHIFT**

- *cqe-\>res* contains the number of bytes transferred

``` c
struct io_uring_cqe *cqe;
io_uring_wait_cqe(ring, &cqe);

if (cqe->flags & IORING_CQE_F_BUFFER) {
    int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    void *buf = buffers[bid];  /* application's buffer tracking */
    int len = cqe->res;

    /* process data in buf */
    process_data(buf, len);

    /* return buffer to ring for reuse */
    io_uring_buf_ring_add(br, buf, 4096, bid, mask, 0);
    io_uring_buf_ring_advance(br, 1);
}
io_uring_cqe_seen(ring, cqe);
```

If no buffer was available when the operation completed, the operation
fails with **-ENOBUFS**.

## Multishot operations

Provided buffers are particularly powerful with multishot operations
like [io_uring_prep_recv_multishot]. A single SQE can generate
multiple completions, each consuming a buffer from the ring:

``` c
struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
io_uring_prep_recv_multishot(sqe, sockfd, NULL, 0, 0);
io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
io_uring_sqe_set_buf_group(sqe, bgid);
```

Completions with **IORING_CQE_F_MORE** set indicate more completions
will follow. The multishot operation continues until an error occurs,
the buffer ring is exhausted, or the operation is canceled.

## Incremental buffer consumption

Buffer rings can be set up with the **IOU_PBUF_RING_INC** flag to enable
incremental consumption. With this mode, large buffers can be partially
consumed across multiple operations:

- Completions with **IORING_CQE_F_BUF_MORE** indicate the buffer will be
  used for more completions

- Each completion picks up where the previous left off

- The buffer is only returned when consumed completely or on error

This is useful for registering large buffer regions that are consumed in
smaller chunks.

## Returning buffers

When finished with a buffer, return it to the ring using
[io_uring_buf_ring_add] followed by
[io_uring_buf_ring_advance]. For efficiency when processing
multiple CQEs, use [io_uring_buf_ring_cq_advance] to advance both
the CQ and buffer ring in a single operation.

## Buffer ring status

Applications can query how many buffers are available using
[io_uring_buf_ring_available], which returns the number of buffers
the kernel has not yet consumed. The current kernel head position can be
retrieved with [io_uring_buf_ring_head].

## Cleaning up

Buffer rings are freed using [io_uring_free_buf_ring], which
unregisters the ring and frees the ring memory (if it was allocated by
[io_uring_setup_buf_ring]). Applications must free the individual
buffers themselves.

# NOTES

- Buffer ring entries must be a power of two, maximum 32768.

- Buffer IDs are 16-bit values (0-65535).

- If no buffer is available when an operation needs one, the operation
  fails with **-ENOBUFS**. Applications should ensure the ring is
  adequately stocked.

- Provided buffers cannot be used with registered (fixed) buffers. These
  are separate mechanisms.

- For multishot receives, ensure buffers are returned to the ring
  promptly to avoid running out.

## Legacy provided buffers

Earlier kernels supported provided buffers via
**IORING_OP_PROVIDE_BUFFERS** and **IORING_OP_REMOVE_BUFFERS**. This
mechanism required submitting SQEs to add or remove buffers, adding
latency and overhead. The ring-based mechanism described above
supersedes this approach and should be used for all new applications.
The legacy interface remains for backwards compatibility.

# SEE ALSO

[io_uring], [io_uring_setup_buf_ring],
[io_uring_free_buf_ring], [io_uring_register_buf_ring],
[io_uring_unregister_buf_ring], [io_uring_buf_ring_add],
[io_uring_buf_ring_advance], [io_uring_buf_ring_cq_advance],
[io_uring_buf_ring_available], [io_uring_prep_recv_multishot]
