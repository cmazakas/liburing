Io_uring registered buffers overview

# DESCRIPTION

Registered buffers are a performance optimization feature of
**io_uring** that allows applications to pre-register a set of buffers
with the kernel. When buffers are registered, the kernel pins the memory
and creates long-term mappings, eliminating the overhead of mapping and
unmapping buffer memory for each I/O operation.

## Why use registered buffers?

For every I/O operation that transfers data between user space and the
kernel, the kernel must perform several operations on the buffer memory:

- Verify the memory is accessible to the process

- Pin the pages in memory to prevent them from being swapped out

- Set up kernel mappings to access the memory

These operations, while individually fast, add up when performing many
small I/O operations. By registering buffers once upfront, these costs
are paid only once, and subsequent I/O operations can use the pre-mapped
buffers directly.

Registered buffers are most beneficial for applications that:

- Perform many small I/O operations

- Reuse the same buffers repeatedly

- Need the lowest possible per-I/O overhead

## Registering buffers

Buffers are registered using [io_uring_register_buffers] or
[io_uring_register_buffers_tags]. The buffers are described using
an array of *struct iovec* structures:

    struct iovec iovecs[2](https://man7.org/linux/man-pages/man2/2.2.html);
    iovecs[0](https://man7.org/linux/man-pages/man2/0.2.html).iov_base = buf1;
    iovecs[0](https://man7.org/linux/man-pages/man2/0.2.html).iov_len = 4096;
    iovecs[1](https://man7.org/linux/man-pages/man2/1.2.html).iov_base = buf2;
    iovecs[1](https://man7.org/linux/man-pages/man2/1.2.html).iov_len = 8192;

    ret = io_uring_register_buffers(ring, iovecs, 2);

The buffers must be anonymous memory (allocated via [malloc](https://man7.org/linux/man-pages/man2/malloc.2.html),
[mmap](https://man7.org/linux/man-pages/man2/mmap.2.html) with **MAP_ANONYMOUS**, or similar). File-backed memory is
not supported.

There is a limit of 1 GiB per individual buffer. Huge pages are
supported and the entire huge page will be pinned even if only part of
it is used.

The buffers are charged against the user's **RLIMIT_MEMLOCK** resource
limit on kernels before 5.12. On kernel 5.12 and later with
**IORING_FEAT_NATIVE_WORKERS** support, cgroup memory accounting is used
instead and no memlock limit applies.

Unless running as root, if buffer registration fails with **ENOMEM**,
the memlock limit may need to be increased. The current limit can be
checked with:

    ulimit -l

The limit can be increased for the current shell session with:

    ulimit -l unlimited

For a permanent change, edit */etc/security/limits.conf* or use
[setrlimit](https://man7.org/linux/man-pages/man2/setrlimit.2.html) programmatically with **RLIMIT_MEMLOCK**.

## Using registered buffers

To use a registered buffer in an I/O operation, use the fixed buffer
variants of the prep functions:

- [io_uring_prep_read_fixed] instead of [io_uring_prep_read]

- [io_uring_prep_write_fixed] instead of [io_uring_prep_write]

- [io_uring_prep_readv_fixed] instead of [io_uring_prep_readv]

- [io_uring_prep_writev_fixed] instead of
  [io_uring_prep_writev]

Zero-copy send operations can also use registered buffers:

- [io_uring_prep_send_zc] with **IORING_RECVSEND_FIXED_BUF**

- [io_uring_prep_sendmsg_zc] with **IORING_RECVSEND_FIXED_BUF**

These functions take a *buf_index* parameter that specifies which
registered buffer to use (0-indexed into the array passed to
[io_uring_register_buffers]).

The memory range used for the I/O operation must fall within the bounds
of the registered buffer. It is valid to use only a portion of a
registered buffer for an operation.

    /* Use first 1024 bytes of registered buffer 0 */
    io_uring_prep_read_fixed(sqe, fd, buf1, 1024, offset, 0);

    /* Use registered buffer 1 */
    io_uring_prep_write_fixed(sqe, fd, buf2, 2048, offset, 1);

## Sparse buffer registration

Applications can register a sparse buffer table using
[io_uring_register_buffers_sparse]. This creates a table with empty
slots that can be filled in later using
[io_uring_register_buffers_update_tag]. This is useful when the
full set of buffers is not known at registration time.

    /* Create sparse table with 10 slots */
    ret = io_uring_register_buffers_sparse(ring, 10);

    /* Later, fill in slot 3 */
    struct iovec iov = { .iov_base = buf, .iov_len = 4096 };
    ret = io_uring_register_buffers_update_tag(ring, 3, &iov, NULL, 1);

## Buffer tagging

When using [io_uring_register_buffers_tags] or
[io_uring_register_buffers_update_tag], each buffer can be
associated with a tag value. When a buffer is unregistered (either
explicitly or by replacing it), and there are no more in-flight
operations using that buffer, a completion queue entry is posted with
*user_data* set to the tag value and all other fields zeroed.

This allows applications to know when it is safe to free or reuse the
buffer memory.

## Updating registered buffers

Registered buffers can be updated in place using
[io_uring_register_buffers_update_tag]. This can:

- Replace an existing buffer with a new one

- Fill in a sparse slot

- Remove a buffer by setting the iovec to zero length

Updating buffers does not immediately free resources. The old buffer
remains valid until all in-flight operations complete.

## Unregistering buffers

Buffers are unregistered using [io_uring_unregister_buffers]. This
releases all registered buffers. Buffers are also automatically
unregistered when the io_uring instance is destroyed.

Applications do not need to explicitly unregister buffers before
shutting down the ring. However, page unpinning may happen
asynchronously, so pages may not be immediately available after ring
destruction.

## Cloning buffers

Registered buffers can be cloned from one ring to another using
[io_uring_clone_buffers] or [io_uring_clone_buffers_offset].
This allows multiple rings to share the same set of registered buffers
without re-registering them.

# NOTES

- Registered buffers provide the most benefit for small, frequent I/O
  operations where the per-operation overhead is significant.

- For large I/O operations, the buffer mapping overhead is small
  relative to the actual I/O time, so registered buffers may not provide
  much benefit.

- The maximum number of registered buffers is limited by available
  kernel memory and the **RLIMIT_MEMLOCK** limit (on older kernels).

- Registered buffers cannot be used with provided buffer rings
  (**IOSQE_BUFFER_SELECT**). These are separate mechanisms for different
  use cases.

# SEE ALSO

[io_uring], [io_uring_registered_files], [setrlimit](https://man7.org/linux/man-pages/man2/setrlimit.2.html),
[io_uring_register_buffers], [io_uring_register_buffers_tags],
[io_uring_register_buffers_sparse],
[io_uring_register_buffers_update_tag],
[io_uring_unregister_buffers], [io_uring_prep_read_fixed],
[io_uring_prep_write_fixed], [io_uring_prep_send_zc],
[io_uring_prep_sendmsg_zc], [io_uring_clone_buffers]
