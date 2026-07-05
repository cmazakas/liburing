Set range for fixed file.
allocations

# DESCRIPTION

The [io_uring_register_file_alloc_range] function sets the
allowable range for fixed file index allocations within the kernel. When
requests that can instantiate a new fixed file are used with
**IORING_FILE_INDEX_ALLOC ,** the application is asking the kernel to
allocate a new fixed file descriptor rather than pass in a specific
value for one. By default, the kernel will pick any available fixed file
descriptor within the range available. Calling this function with *off*
set to the starting offset and *len* set to the number of descriptors,
the application can limit the allocated descriptors to that particular
range. This effectively allows the application to set aside a range just
for dynamic allocations, with the remainder being used for specific
values.

The application must have registered a fixed file table upfront, e.g.
through [io_uring_register_files] or
[io_uring_register_files_sparse]**.**

Available since 6.0.

# RETURN VALUE

On success [io_uring_register_file_alloc_range] returns 0. On
failure it returns **-errno**.

# SEE ALSO

[io_uring_register_files] [io_uring_prep_accept_direct]
[io_uring_prep_openat_direct] [io_uring_prep_socket_direct]
