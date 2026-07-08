Register file descriptors

# DESCRIPTION

The [io_uring_register_files] function registers *nr_files* number
of file descriptors defined by the array *files* belonging to the *ring*
for subsequent operations.

The [io_uring_register_files_tags] function behaves the same as
[io_uring_register_files] function but additionally takes *tags*
parameter. See **IORING_REGISTER_BUFFERS2** for the resource tagging
description.

The [io_uring_register_files_sparse] function registers an empty
file table of *nr_files* number of file descriptors. These files must be
updated before use, using eg [io_uring_register_files_update_tag].
Note that if the size of the sparse table exceeds what **RLIMIT_NOFILE**
allows, then [io_uring_register_files_sparse] will attempt to raise
the limit using **setrlimit (2)** and retry the operation. If the
registration fails after doing that, then an error will be returned. The
sparse variant is available in kernels 5.19 and later.

Registering a file table is a prerequisite for using any request that
uses direct descriptors.

Registered files have less overhead per operation than normal files.
This is due to the kernel grabbing a reference count on a file when an
operation begins, and dropping it when it's done. When the process file
table is shared, for example if the process has ever created any
threads, then this cost goes up even more. Using registered files
reduces the overhead of file reference management across requests that
operate on a file.

The [io_uring_register_files_update] function updates existing
registered files. The *off* is offset on which to start the update
*nr_files* number of files defined by the array *files* belonging to the
*ring*.

The [io_uring_register_files_update_tag] function behaves the same
as [io_uring_register_files_update] function but additionally takes
*tags* parameter. See **IORING_REGISTER_BUFFERS2** for the resource
tagging description.

# RETURN VALUE

On success [io_uring_register_files],
[io_uring_register_files_tags] and
[io_uring_register_files_sparse] return 0.
[io_uring_register_files_update] and
[io_uring_register_files_update_tag] return number of files
updated. On failure they return **-errno**.

# SEE ALSO

[io_uring_register], [io_uring_get_sqe],
[io_uring_unregister_files]
