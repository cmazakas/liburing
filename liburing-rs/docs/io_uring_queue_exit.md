Tear down io_uring submission and completion
queues

# DESCRIPTION

[io_uring_queue_exit] will release all resources acquired and
initialized by [io_uring_queue_init]. It first unmaps the memory
shared between the application and the kernel and then closes the
io_uring file descriptor.

Some accounting is done asynchronously, so memory locked by
[io_uring_queue_init] may remain locked for a few milliseconds
after this function returns.

# RETURN VALUE

None

# SEE ALSO

[io_uring_setup], [mmap](https://man7.org/linux/man-pages/man2/mmap.2.html), [io_uring_queue_init]
