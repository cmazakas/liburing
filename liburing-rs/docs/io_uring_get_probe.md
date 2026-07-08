Get probe instance

# DESCRIPTION

The function [io_uring_get_probe] returns an allocated
io_uring_probe structure to the caller. The caller is responsible for
freeing the structure with the function [io_uring_free_probe].

# NOTES

Earlier versions of the Linux kernel do not support probe. If the kernel
doesn't support probe, this function will return NULL.

# RETURN VALUE

On success it returns an allocated io_uring_probe structure, otherwise
it returns NULL.

# SEE ALSO

[io_uring_free_probe]
