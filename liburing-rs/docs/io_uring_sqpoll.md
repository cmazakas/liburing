io_uring submission queue polling overview

# DESCRIPTION

Submission queue polling (SQPOLL) is a mode of operation where an
io_uring created userspace thread that remains in the kernel monitors
the submission queue and submits requests on behalf of the application.
This eliminates the need for the application to make system calls to
submit I/O, reducing latency and CPU overhead for high-throughput
workloads.

## Why use SQPOLL?

In normal io_uring operation, applications must call
[io_uring_enter] (typically via [io_uring_submit]) to notify
the kernel of new submissions. While efficient, this still incurs system
call overhead.

With SQPOLL enabled, the kernel thread continuously polls the submission
queue for new entries. As soon as the application writes an SQE to the
ring, the kernel thread picks it up and submits it. This provides:

- Elimination of submission system call overhead

- Lower and more predictable latency

- Better CPU utilization for high-IOPS workloads

SQPOLL is most beneficial for:

- High-throughput storage workloads (NVMe, etc.)

- Latency-sensitive applications

- Workloads with continuous I/O streams

- Applications already running at high CPU utilization

## When SQPOLL may not help

SQPOLL is not universally beneficial and each use case should be
benchmarked to determine if it provides value. Situations where SQPOLL
may not help or may hurt performance:

- **Low-IOPS workloads:** If the application submits I/O infrequently,
  the system call overhead being saved is negligible, and the polling
  thread wastes CPU cycles.

- **CPU-constrained systems:** The polling thread consumes CPU. If the
  system is already CPU-bound, adding a polling thread may compete with
  the application for CPU resources, reducing overall performance.

- **Bursty workloads:** If I/O comes in bursts with idle periods, the
  polling thread may frequently sleep and wake, adding latency when it
  needs to wake up. Regular submission may be more efficient.

- **Single-threaded applications on single-CPU systems:** The polling
  thread and application will compete for the same CPU, potentially
  causing context switches that negate any benefits.

- **Workloads dominated by completion handling:** SQPOLL only optimizes
  submissions. If the application spends most of its time processing
  completions, SQPOLL provides little benefit.

Always benchmark with and without SQPOLL under realistic conditions. The
performance difference can vary significantly based on hardware, kernel
version, and workload characteristics.

## Enabling SQPOLL

SQPOLL is enabled by setting the **IORING_SETUP_SQPOLL** flag when
creating the ring:

``` c
struct io_uring ring;
struct io_uring_params params = {
    .flags = IORING_SETUP_SQPOLL,
    .sq_thread_idle = 2000,  /* 2 seconds */
};

ret = io_uring_queue_init_params(entries, &ring, &params);
```

The *sq_thread_idle* field specifies how long (in milliseconds) the
kernel thread will poll before going to sleep if no submissions are
pending. A value of 0 means the thread never sleeps (uses more CPU but
provides lowest latency).

## The polling thread lifecycle

When the ring is created with SQPOLL, a kernel thread is spawned to
service it. The thread's behavior is:

1.  Poll the submission queue for new entries

2.  Submit any new requests found

3.  If no new entries are found for *sq_thread_idle* milliseconds, go to
    sleep

4.  Wake up when signaled by the application

The application can check if the thread is sleeping by examining
*sq-\>kflags* for the **IORING_SQ_NEED_WAKEUP** flag using
[io_uring_sq_ready]. If set, the application must call
[io_uring_enter] with **IORING_ENTER_SQ_WAKEUP** to wake the
thread:

``` c
/* After adding SQEs */
io_uring_smp_store_release(ring->sq.ktail, tail);

if (IO_URING_READ_ONCE(*ring->sq.kflags) & IORING_SQ_NEED_WAKEUP)
    io_uring_enter(ring->ring_fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL);
```

The [io_uring_submit] function handles this automatically.

## CPU affinity

By default, the kernel schedules the polling thread on any available
CPU. For better cache locality and reduced latency, the thread can be
pinned to a specific CPU:

``` c
struct io_uring_params params = {
    .flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF,
    .sq_thread_cpu = 3,  /* pin to CPU 3 */
    .sq_thread_idle = 1000,
};
```

The **IORING_SETUP_SQ_AFF** flag enables CPU affinity, and
*sq_thread_cpu* specifies which CPU to use.

## Credential requirements

Creating an SQPOLL ring traditionally required elevated privileges
because the kernel thread runs on behalf of the application. The
requirements have evolved:

- Kernel 5.11 and earlier: requires **CAP_SYS_ADMIN** or
  **CAP_SYS_NICE**

- Kernel 5.12 and later: unprivileged users can create SQPOLL rings, but
  the polling thread runs with reduced capabilities

- The **IORING_SETUP_NO_SQARRAY** flag (kernel 6.6+) can simplify setup
  for SQPOLL-only rings

## Sharing the polling thread

Multiple rings can share a single polling thread using
**IORING_SETUP_ATTACH_WQ**. This reduces resource usage when an
application uses multiple rings:

``` c
/* Create first ring with SQPOLL */
struct io_uring_params p1 = { .flags = IORING_SETUP_SQPOLL };
io_uring_queue_init_params(entries, &ring1, &p1);

/* Create second ring, attach to first ring's thread */
struct io_uring_params p2 = {
    .flags = IORING_SETUP_SQPOLL | IORING_SETUP_ATTACH_WQ,
    .wq_fd = ring1.ring_fd,
};
io_uring_queue_init_params(entries, &ring2, &p2);
```

## Completion handling

SQPOLL only affects submissions. Completions are still handled normally
— the application must either:

- Poll the completion queue directly (busy-wait)

- Use [io_uring_enter] with **IORING_ENTER_GETEVENTS** to wait for
  completions

- Use an eventfd for notification

For full polling on both submission and completion, combine SQPOLL with
completion queue polling using [io_uring_peek_cqe] or similar
functions.

## Performance considerations

- **CPU usage:** The polling thread consumes CPU while active. If I/O is
  sporadic, the thread may waste cycles polling an empty queue. Set
  *sq_thread_idle* appropriately for your workload.

- **Idle timeout tradeoff:** A shorter idle timeout saves CPU but may
  increase latency when the thread needs to wake up. A longer timeout
  (or 0 for never sleeping) uses more CPU but provides consistent low
  latency.

- **Batching:** Even with SQPOLL, batching submissions by adding
  multiple SQEs before updating the tail pointer can improve throughput.

- **CPU affinity:** Pinning the polling thread to a CPU near the
  application's CPU can improve cache behavior and reduce cross-CPU
  communication.

# NOTES

- The polling thread is per-ring (unless shared via
  **IORING_SETUP_ATTACH_WQ**). Creating many SQPOLL rings without
  sharing can consume significant kernel resources.

- SQPOLL rings still require system calls for:

  - Waiting for completions (unless busy-polling the CQ)

  - Waking the thread when it has gone idle

  - Registration operations

- The polling thread inherits resource limits and cgroup membership from
  the creating process.

- If the polling thread encounters an error it cannot recover from,
  **IORING_SQ_CQ_OVERFLOW** may be set in *sq-\>kflags*.

- SQPOLL works well in combination with registered files and buffers,
  which further reduce per-I/O overhead.

# SEE ALSO

[io_uring], [io_uring_setup], [io_uring_enter],
[io_uring_queue_init_params], [io_uring_register_files],
[io_uring_registered_buffers]
