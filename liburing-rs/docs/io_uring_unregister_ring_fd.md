Unregister a ring file descriptor

# DESCRIPTION

[io_uring_unregister_ring_fd] unregisters the file descriptor of
the ring.

Unregisters a ring descriptor previously registered with the task. This
is done automatically when [io_uring_queue_exit] is called, but can
also be done to free up space for new ring registrations. For more
information on ring descriptor registration, see
[io_uring_register_ring_fd]

# RETURN VALUE

Returns 1 on success, indicating that one file descriptor was
unregistered, or **-errno** on error.

# SEE ALSO

[io_uring_register_ring_fd], [io_uring_register_files]
