Setup io_uring submission and completion queues

# DESCRIPTION

The [io_uring_queue_init] function executes the
[io_uring_setup] system call to initialize the submission and
completion queues in the kernel with at least *entries* entries in the
submission queue and then maps the resulting file descriptor to memory
shared between the application and the kernel.

By default, the CQ ring will have twice the number of entries as
specified by *entries* for the SQ ring. This is adequate for regular
file or storage workloads, but may be too small for networked workloads.
The SQ ring entries do not impose a limit on the number of in-flight
requests that the ring can support, it merely limits the number that can
be submitted to the kernel in one go (batch). If the CQ ring overflows,
e.g. more entries are generated than fits in the ring before the
application can reap them, then if the kernel supports
**IORING_FEAT_NODROP** the ring enters a CQ ring overflow state.
Otherwise it drops the CQEs and increments *cq.koverflow* in *struct
io_uring* with the number of CQEs dropped. The overflow state is
indicated by **IORING_SQ_CQ_OVERFLOW** being set in the SQ ring flags.
Unless the kernel runs out of available memory, entries are not dropped,
but it is a much slower completion path and will slow down request
processing. For that reason it should be avoided and the CQ ring sized
appropriately for the workload. Setting *cq_entries* in *struct
io_uring_params* will tell the kernel to allocate this many entries for
the CQ ring, independent of the SQ ring size in given in *entries*. If
the value isn't a power of 2, it will be rounded up to the nearest power
of 2.

On success, [io_uring_queue_init] returns 0 and *ring* will point
to the shared memory containing the io_uring queues. On failure
**-errno** is returned.

*flags* will be passed through to the io_uring_setup syscall (see
[io_uring_setup]).

The [io_uring_queue_init_params] and [io_uring_queue_init_mem]
variants will pass the parameters indicated by *params* straight through
to the [io_uring_setup] system call.

The [io_uring_queue_init_mem] variant uses the provided *buf* with
associated size *buf_size* as the memory for the ring, using the
**IORING_SETUP_NO_MMAP** flag to [io_uring_setup]. The buffer
passed to [io_uring_queue_init_mem] must be page size aligned on
the host, and must already be zeroed. Typically, the caller should
allocate a huge page and pass that in to [io_uring_queue_init_mem].
Pages allocated by mmap are already zeroed.
[io_uring_queue_init_mem] returns the number of bytes used from the
provided buffer, so that the app can reuse the buffer with the returned
offset to put more rings in the same huge page.

On success, the resources held by *ring* should be released via a
corresponding call to [io_uring_queue_exit].

# RETURN VALUE

[io_uring_queue_init] and [io_uring_queue_init_params] return
0 on success and **-errno** on failure. A return value of **-ENOMEM**
indicates there is not enough locked memory available to hold the
specified number of entries. Reduce the number of entries, or call
[setrlimit](https://man7.org/linux/man-pages/man2/setrlimit.2.html) to increase the maximum number of bytes of memory that
may be locked into RAM. Be aware that calling [io_uring_queue_init]
and [io_uring_queue_exit] in a loop will temporarily lock a lot of
memory, because [io_uring_queue_exit] does some of its accounting
asynchronously.

[io_uring_queue_init_mem] returns the number of bytes used from the
provided buffer on success, and **-errno** on failure.

# SEE ALSO

[io_uring_setup], [io_uring_register_ring_fd], [mmap](https://man7.org/linux/man-pages/man2/mmap.2.html),
[io_uring_queue_exit]
