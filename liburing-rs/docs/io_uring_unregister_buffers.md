Unregister buffers for fixed buffer.
operations

# DESCRIPTION

The [io_uring_unregister_buffers] function unregisters the fixed
buffers previously registered to the *ring*.

# RETURN VALUE

On success [io_uring_unregister_buffers] returns 0. On failure it
returns **-errno**.

# SEE ALSO

[io_uring_register_buffers]
