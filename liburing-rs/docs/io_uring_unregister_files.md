Unregister file descriptors

# DESCRIPTION

The [io_uring_unregister_files] function unregisters the file
descriptors previously registered to the *ring*.

# RETURN VALUE

On success [io_uring_unregister_files] returns 0. On failure it
returns **-errno**.

# SEE ALSO

[io_uring_register_files]
