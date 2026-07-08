io_uring ring setup flags overview

# DESCRIPTION

When creating an io_uring instance with
[io_uring_queue_init_params] or [io_uring_setup], various
flags control the ring's behavior. These flags are set in the *flags*
field of *struct io_uring_params*.

Choosing the right flags can significantly impact performance. This page
provides an overview of available flags, their purposes, and common
combinations.

## Polling flags

These flags control how I/O completion and submission polling works.

**IORING_SETUP_IOPOLL**

> Enable I/O polling mode for file descriptors that support it. Instead
> of relying on interrupts, the kernel polls for completions. This
> reduces latency for high-performance storage devices (NVMe, etc.) but
> requires:
>
> - Files opened with **O_DIRECT** (if using the
>   **IORING_OP\_{READ,WRITE}(V)(\_FIXED)** opcodes)
>
> - Hardware and drivers that support polling
>
> - The application to call [io_uring_enter] to reap completions
>   (busy-polling)
>
> - Storage device configuration for polling support
>
> Only the following opcodes are allowed on IOPOLL rings:
>
> - **IORING_OP_NOP(128)**
>
> - **IORING_OP\_{READ,WRITE}(V)(\_FIXED)** (if the file supports
>   busy-polling)
>
> - **IORING_OP_FILES_UPDATE**
>
> - **IORING_OP\_{PROVIDE,REMOVE}\_BUFFERS**
>
> - **IORING_OP_MSG_RING**
>
> - **IORING_OP_URING_CMD(128)**
>
> Since kernel 7.1, an **IORING_OP_URING_CMD(128)** request will use
> busy-polling if the file supports it (i.e., NVMe passthrough I/O
> commands). Previously, **IORING_OP_URING_CMD(128)** was only allowed
> on files that supported busy-polling.
>
> Using IOPOLL generally requires storage device setup. For NVMe
> devices, the kernel parameter **nvme.poll_queues=X** must be set,
> where X is the number of completion queues on the NVMe device to set
> aside for polling operations.

**IORING_SETUP_SQPOLL**

> Create a kernel thread that polls the submission queue. Eliminates the
> need for system calls to submit I/O. See [io_uring_sqpoll] for
> details.

**IORING_SETUP_SQ_AFF**

> Pin the SQPOLL thread to a specific CPU. Requires
> **IORING_SETUP_SQPOLL**. The CPU is specified in *sq_thread_cpu* of
> *struct io_uring_params*.

**IORING_SETUP_HYBRID_IOPOLL**

> Enable hybrid polling mode. Instead of pure busy-polling, the kernel
> uses an adaptive approach that may sleep briefly, reducing CPU usage
> while still providing low latency. This is a middle ground between
> interrupt-driven and pure polling modes.

## Task run flags

These flags control when and how completion processing runs.

**IORING_SETUP_COOP_TASKRUN**

> Disable interrupting the application for completion processing.
> Normally, the kernel signals the application when completions are
> ready, which can interrupt system calls. With this flag, completions
> are only processed when the application returns to userspace from any
> system call, not just io_uring-related ones. This means completions
> may be processed after [read](https://man7.org/linux/man-pages/man2/read.2.html), [write](https://man7.org/linux/man-pages/man2/write.2.html), [poll](https://man7.org/linux/man-pages/man2/poll.2.html), or any
> other syscall returns.
>
> This improves performance by eliminating asynchronous interrupts but
> requires the application to regularly enter the kernel to process
> completions. Recommended for most applications that have an event
> loop.

**IORING_SETUP_TASKRUN_FLAG**

> When completions are pending, set **IORING_SQ_TASKRUN** in the SQ ring
> flags. This allows applications to check if there is completion work
> to process without making a system call. Typically used with
> **IORING_SETUP_COOP_TASKRUN**.

**IORING_SETUP_DEFER_TASKRUN**

> Defer completion task work to when the application explicitly enters
> the kernel via [io_uring_enter]. Unlike
> **IORING_SETUP_COOP_TASKRUN**, completions are only processed during
> io_uring-related syscalls, not on return from arbitrary syscalls. This
> provides the tightest and most predictable control over when
> completion processing occurs, as well as optimal cache behavior since
> work runs in the application's context.
>
> This flag should be considered the default mode for applications
> setting up a ring. It requires **IORING_SETUP_SINGLE_ISSUER** and a
> ring created per-thread. The application must regularly call
> [io_uring_enter] (via [io_uring_submit],
> [io_uring_wait_cqe], or similar) to process deferred work;
> failing to do so will stall completions.
>
> Some features require this flag:
>
> - Ring resizing ([io_uring_resize_rings])
>
> - Zero-copy receive (**IORING_OP_RECV_ZC**)

**IORING_SETUP_SINGLE_ISSUER**

> Hint that only one task will submit requests to this ring. Enables
> internal optimizations including reduced locking overhead. The first
> task to submit a request becomes the designated submitter; others
> attempting to submit will get **-EEXIST**.
>
> Each thread or task having its own ring is the idiomatic use case for
> io_uring. Sharing a ring between multiple threads or tasks is
> discouraged as it requires additional synchronization and prevents
> many optimizations. Applications should create a ring per thread
> rather than sharing rings.

## Ring sizing flags

These flags control the size and layout of the submission and completion
queues.

**IORING_SETUP_CQSIZE**

> Override the default completion queue size. By default, the CQ has
> twice as many entries as the SQ. Set *cq_entries* in *struct
> io_uring_params* to specify a custom CQ size. Must be a power of 2.
>
> Larger CQ sizes are useful when the application may submit many
> requests before processing completions, avoiding CQ overflow.

**IORING_SETUP_CLAMP**

> Clamp the SQ and CQ sizes to the maximum allowed values instead of
> returning **-EINVAL** if the requested sizes are too large. Useful
> when the application wants the largest possible rings without querying
> limits.

**IORING_SETUP_SQE128**

> Use 128-byte SQEs instead of the default 64 bytes. Required for some
> operations that need extra space, such as **IORING_OP_URING_CMD**
> passthrough commands.

**IORING_SETUP_CQE32**

> Use 32-byte CQEs instead of the default 16 bytes. Required for
> operations that return extra data, such as some passthrough commands
> or when using **IORING_OP_MSG_RING**.

**IORING_SETUP_NO_SQARRAY**

> Do not create the SQ array. The SQ array is a level of indirection
> that allows SQEs to be submitted in a different order than they appear
> in the ring. Most applications submit SQEs in order and do not need
> this. This flag saves memory and is required for some modes like
> **IORING_SETUP_REGISTERED_FD_ONLY**.

**IORING_SETUP_SQ_REWIND**

> Use non-circular submission queue mode. The kernel ignores the SQ head
> and tail pointers and instead fetches SQEs starting from index 0 on
> each submit. The application places all SQEs at the beginning of the
> ring before calling [io_uring_enter], and the *sq_entries*
> parameter determines how many SQEs are submitted.
>
> Requires **IORING_SETUP_NO_SQARRAY**. Not compatible with
> **IORING_SETUP_SQPOLL**.
>
> This mode keeps SQEs hot in cache by always accessing the same memory
> locations at the start of the ring, improving performance for
> workloads that submit small batches frequently.

**IORING_SETUP_CQE_MIXED**

> Allow the ring to return a mix of 16-byte and 32-byte CQEs, controlled
> per-request. When a request needs a 32-byte CQE, it sets
> **IOSQE_BIG_CQE** in its flags. Otherwise, a 16-byte CQE is used.
> Requires **IORING_SETUP_CQE32**.
>
> This is useful when certain operations require 32-byte CQEs (such as
> some passthrough commands) but most operations do not. Using mixed
> mode instead of **IORING_SETUP_CQE32** alone provides efficiency
> benefits in terms of memory bandwidth and usage, since the smaller
> 16-byte CQEs are used for operations that do not need the extra space.

**IORING_SETUP_SQE_MIXED**

> Allow the ring to accept a mix of 64-byte and 128-byte SQEs. When a
> request needs a 128-byte SQE, it sets **IOSQE_BIG_SQE** in its flags.
> Requires **IORING_SETUP_SQE128**.
>
> This is useful when certain operations require 128-byte SQEs (such as
> **IORING_OP_URING_CMD**) but most operations do not. Using mixed mode
> instead of **IORING_SETUP_SQE128** alone provides efficiency benefits
> in terms of memory bandwidth and usage, since the smaller 64-byte SQEs
> are used for operations that do not need the extra space.

## Memory and setup flags

These flags control memory allocation and ring initialization.

**IORING_SETUP_NO_MMAP**

> The application provides its own memory for the rings instead of the
> kernel allocating and the application mmap'ing it. The application
> fills in *sq_off.user_addr*, *cq_off.user_addr*, and
> *sq_sqes.user_addr* in *struct io_uring_params* with addresses of
> application-allocated memory.
>
> This is useful for placing rings in specific memory (huge pages,
> shared memory, etc.) or for creating rings without mmap.

**IORING_SETUP_REGISTERED_FD_ONLY**

> The ring file descriptor is not installed in the process's file
> descriptor table. Instead, a "registered ring" index is returned in
> *ring_fd* that can be used with [io_uring_enter] when
> **IORING_ENTER_REGISTERED_RING** is set. This reduces per-operation
> overhead.
>
> Requires **IORING_SETUP_NO_SQARRAY**. The application must use
> [io_uring_register_ring_fd] to use the ring or access it via the
> registered index.

**IORING_SETUP_R_DISABLED**

> Create the ring in a disabled state. The ring will not accept
> submissions until it is enabled via [io_uring_enable_rings]. This
> is useful when setting up restrictions or registered resources before
> allowing I/O. See [io_uring_register_restrictions].

## Submission flags

These flags control submission behavior.

**IORING_SETUP_SUBMIT_ALL**

> Continue processing submissions even if one fails. Normally, if an SQE
> fails during submission (not execution), subsequent SQEs in the same
> submit call are not processed. With this flag, all SQEs are processed
> regardless of earlier failures.
>
> The failed SQE still generates a CQE with the error; this flag only
> affects whether subsequent SQEs are submitted. This is probably the
> behavior most applications expect, since CQEs are generated for failed
> submissions anyway and the application must handle them regardless.

## Workqueue flags

These flags control the async worker threads.

**IORING_SETUP_ATTACH_WQ**

> Share the async worker thread pool with another ring. Set *wq_fd* in
> *struct io_uring_params* to the file descriptor of the ring to share
> with. This reduces resource usage when an application uses multiple
> rings.
>
> When combined with **IORING_SETUP_SQPOLL**, the SQPOLL thread is also
> shared.

## Common flag combinations

**High-performance single-threaded application:**

> ``` c
> .flags = IORING_SETUP_SINGLE_ISSUER |
>          IORING_SETUP_DEFER_TASKRUN |
>          IORING_SETUP_COOP_TASKRUN
> ```
>
> This combination provides the best latency and throughput for
> applications where each thread has its own ring and processes
> completions in a dedicated event loop.

**Low-latency storage with polling:**

> ``` c
> .flags = IORING_SETUP_IOPOLL |
>          IORING_SETUP_SINGLE_ISSUER |
>          IORING_SETUP_DEFER_TASKRUN
> ```
>
> For NVMe or other devices that support polling, this eliminates
> interrupt overhead. Combined with DEFER_TASKRUN for optimal completion
> handling.

**System call-free submission:**

> ``` c
> .flags = IORING_SETUP_SQPOLL |
>          IORING_SETUP_SQ_AFF
> .sq_thread_cpu = preferred_cpu
> .sq_thread_idle = 1000
> ```
>
> For workloads that benefit from eliminating submission syscall
> overhead. See [io_uring_sqpoll].

**Multiple rings sharing resources:**

> ``` c
> /* First ring */
> p1.flags = IORING_SETUP_SQPOLL;
>
> /* Subsequent rings */
> p2.flags = IORING_SETUP_SQPOLL | IORING_SETUP_ATTACH_WQ;
> p2.wq_fd = ring1_fd;
> ```
>
> Reduces kernel thread and workqueue overhead when using multiple
> rings.

# NOTES

- Not all flag combinations are valid. The kernel returns **-EINVAL**
  for incompatible combinations.

- Some flags require specific kernel versions. Check
  [io_uring_setup] for version requirements.

- The [io_uring_queue_init_params] function handles the complexity
  of ring setup. Using the raw [io_uring_setup] syscall requires
  careful mmap setup.

- For most applications with a proper event loop,
  **IORING_SETUP_DEFER_TASKRUN** combined with
  **IORING_SETUP_SINGLE_ISSUER** is the recommended default. This
  provides the best control over when completion work runs and optimal
  cache locality.

# SEE ALSO

[io_uring], [io_uring_sqpoll], [io_uring_setup],
[io_uring_queue_init_params],
[io_uring_register_restrictions], [io_uring_enable_rings]
