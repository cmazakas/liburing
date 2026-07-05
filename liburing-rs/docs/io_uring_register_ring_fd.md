Register a ring file descriptor.

# DESCRIPTION

[io_uring_register_ring_fd] registers the file descriptor of the
ring.

Whenever [io_uring_enter] is called to submit request or wait for
completions, the kernel must grab a reference to the file descriptor. If
the application using io_uring is threaded, the file table is marked as
shared, and the reference grab and put of the file descriptor count is
more expensive than it is for a non-threaded application.

Similarly to how io_uring allows registration of files, this allow
registration of the ring file descriptor itself. This reduces the
overhead of the [io_uring_enter] system call.

If an application using liburing is threaded, then an application should
call this function to register the ring descriptor when a ring is set
up. See NOTES for restrictions when a ring is shared.

Available since kernel 5.18.

# NOTES

When the ring descriptor is registered, it is stored internally in the
*struct io_uring* structure. For applications that share a ring between
threads, for example having one thread do submits and another reap
events, then this optimization cannot be used as each thread may have a
different index for the registered ring fd.

# RETURN VALUE

Returns 1 on success, indicating that one file descriptor was
registered, or **-errno** on error.

# SEE ALSO

[io_uring_unregister_ring_fd], [io_uring_register_files]
