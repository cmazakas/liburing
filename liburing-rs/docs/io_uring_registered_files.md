Io_uring registered files overview

# DESCRIPTION

Registered files (also known as fixed files) are a performance
optimization feature of **io_uring** that allows applications to
pre-register a set of file descriptors with the kernel. When files are
registered, the kernel takes a reference to each file, avoiding the
overhead of looking up file descriptors and taking references for each
I/O operation.

## Why use registered files?

For every I/O operation that uses a file descriptor, the kernel must:

- Look up the file descriptor in the process's file descriptor table

- Take a reference to the file to ensure it remains valid during the
  operation

- Release the reference when the operation completes

For applications performing many I/O operations, especially on threaded
applications where the file table is shared (making reference counting
more expensive), these overheads accumulate. By registering files once,
the reference is held for the lifetime of the registration, and
operations can use the file directly without per-operation lookups or
reference counting.

Registered files are most beneficial for applications that:

- Perform many I/O operations on the same set of files

- Are multi-threaded (where file table operations are more expensive)

- Need the lowest possible per-I/O overhead

## Registering files

Files are registered using [io_uring_register_files] or
[io_uring_register_files_tags]. The files are described using an
array of file descriptors:

    int fds[3](https://man7.org/linux/man-pages/man2/3.2.html);
    fds[0](https://man7.org/linux/man-pages/man2/0.2.html) = open("file1", O_RDONLY);
    fds[1](https://man7.org/linux/man-pages/man2/1.2.html) = open("file2", O_RDONLY);
    fds[2](https://man7.org/linux/man-pages/man2/2.2.html) = open("file3", O_WRONLY | O_CREAT, 0644);

    ret = io_uring_register_files(ring, fds, 3);

Once registered, the original file descriptors can be closed if desired.
The kernel holds its own references to the underlying files.

## Using registered files

To use a registered file in an I/O operation, set the
**IOSQE_FIXED_FILE** flag in the SQE's *flags* field, and use the index
into the registered file array (not the original file descriptor) in the
*fd* field:

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, 0, buf, len, offset);  /* index 0, not fd */
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);

The index is 0-based into the array passed to
[io_uring_register_files].

## Sparse file registration

The file array can be sparse, meaning some slots can be empty. Empty
slots are indicated by setting the file descriptor to -1. Applications
can create a fully sparse table using
[io_uring_register_files_sparse] and fill in slots later:

    /* Create sparse table with 100 slots */
    ret = io_uring_register_files_sparse(ring, 100);

    /* Later, fill in slot 5 */
    int fd = open("file", O_RDONLY);
    ret = io_uring_register_files_update(ring, 5, &fd, 1);

## Updating registered files

Registered files can be updated using
[io_uring_register_files_update] or
[io_uring_register_files_update_tag]. This can:

- Replace an existing file with a new one

- Fill in an empty slot

- Remove a file by setting the descriptor to -1

To skip updating certain slots while updating others, use the special
value **IORING_REGISTER_FILES_SKIP**.

    int fds[3](https://man7.org/linux/man-pages/man2/3.2.html);
    fds[0](https://man7.org/linux/man-pages/man2/0.2.html) = new_fd;                        /* replace slot 0 */
    fds[1](https://man7.org/linux/man-pages/man2/1.2.html) = IORING_REGISTER_FILES_SKIP;    /* leave slot 1 unchanged */
    fds[2](https://man7.org/linux/man-pages/man2/2.2.html) = -1;                            /* remove slot 2 */

    ret = io_uring_register_files_update(ring, 0, fds, 3);

Updates do not require the ring to be idle on kernels 5.13 and later. On
older kernels, updates would wait for in-flight operations to complete.

## File tagging

When using [io_uring_register_files_tags] or
[io_uring_register_files_update_tag], each file can be associated
with a tag value. When a file is unregistered (either explicitly or by
replacement), and there are no more in-flight operations using that
file, a completion queue entry is posted with *user_data* set to the tag
value and all other fields zeroed.

This notification mechanism allows applications to know when it is safe
to perform cleanup actions associated with the file.

## Direct file descriptors

Some io_uring operations can allocate file descriptors directly into the
registered file table, avoiding the regular file descriptor table
entirely. This is done by setting the *file_index* field in the SQE
(using [io_uring_sqe_set_target_fixed_file]) to the desired slot,
or using **IORING_FILE_INDEX_ALLOC** to have io_uring allocate the next
available slot.

Operations that support direct descriptors include:

- **IORING_OP_OPENAT** / **IORING_OP_OPENAT2**

- **IORING_OP_ACCEPT**

- **IORING_OP_SOCKET**

- **IORING_OP_PIPE**

When using **IORING_FILE_INDEX_ALLOC**, the application should use
[io_uring_register_file_alloc_range] to specify which range of the
file table should be used for allocations.

    /* Reserve slots 50-99 for dynamic allocation */
    io_uring_register_file_alloc_range(ring, 50, 50);

    /* Accept with direct descriptor allocation */
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept_direct(sqe, listen_fd, NULL, NULL, 0,
                                IORING_FILE_INDEX_ALLOC);

The allocated slot index is returned in the CQE *res* field on success.

## Closing direct descriptors

Direct descriptors (files that exist only in the registered file table)
can be closed using **IORING_OP_CLOSE** with the **IOSQE_FIXED_FILE**
flag set, or by updating the slot to -1 using
[io_uring_register_files_update].

## Unregistering files

Files are unregistered using [io_uring_unregister_files]. This
releases all registered files. Files are also automatically unregistered
when the io_uring instance is destroyed.

Applications do not need to explicitly unregister files before shutting
down the ring.

# NOTES

- Registered files provide the most benefit for applications performing
  many operations on the same files, especially multi-threaded
  applications.

- Direct descriptors (files that only exist in the registered table) are
  not visible to operations outside io_uring, such as [read](https://man7.org/linux/man-pages/man2/read.2.html) or
  [write](https://man7.org/linux/man-pages/man2/write.2.html).

- The **IOSQE_FIXED_FILE** flag must be set when using a registered file
  index; without it, the *fd* field is interpreted as a regular file
  descriptor.

- It is an error to use **IOSQE_FIXED_FILE** with an index that does not
  correspond to a registered file.

# SEE ALSO

[io_uring], [io_uring_registered_buffers],
[io_uring_register_files], [io_uring_register_files_tags],
[io_uring_register_files_sparse],
[io_uring_register_files_update],
[io_uring_register_files_update_tag],
[io_uring_unregister_files],
[io_uring_register_file_alloc_range]
