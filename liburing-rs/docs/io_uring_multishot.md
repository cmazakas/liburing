Io_uring multishot requests overview

# DESCRIPTION

Multishot requests are a class of io_uring operations where a single
submission queue entry (SQE) can generate multiple completion queue
entries (CQEs). This is in contrast to normal "oneshot" operations where
each SQE produces exactly one CQE.

## Why use multishot requests?

Traditional I/O operations require submitting a new request for each
operation. For high-frequency operations like accepting connections or
receiving data, this creates overhead:

- CPU cycles spent preparing and submitting SQEs

- Memory bandwidth for SQE/CQE processing

- Potential for gaps between completions and new submissions

Multishot requests eliminate this overhead by keeping the operation
active after each completion. The kernel automatically re-arms the
operation, generating a new CQE when the next event occurs.
Additionally, the internal poll mechanism remains persistent for the
request, avoiding the need to manipulate poll state for each operation.

Multishot operations are most beneficial for:

- Network servers accepting many connections

- Applications receiving data on long-lived connections

- Event monitoring with poll

- Any scenario with repeated identical operations

## How multishot works

When a multishot operation completes, the CQE has the
**IORING_CQE_F_MORE** flag set in *cqe-\>flags*. This indicates that the
operation remains active and more completions will follow. The operation
continues until:

- An error occurs (the final CQE will not have **IORING_CQE_F_MORE**
  set)

- The operation is explicitly canceled

- A termination condition specific to the operation is met (e.g., buffer
  exhaustion for receives)

The final CQE for a multishot operation will not have
**IORING_CQE_F_MORE** set, indicating the operation has terminated.

## Multishot accept

[io_uring_prep_multishot_accept] and
[io_uring_prep_multishot_accept_direct] set up a multishot accept
operation. Each incoming connection generates a CQE with the new file
descriptor in *cqe-\>res*.

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_multishot_accept(sqe, listen_fd, NULL, NULL, 0);

The operation continues accepting connections until an error occurs or
it is canceled. Using the direct variant with
**IORING_FILE_INDEX_ALLOC** allows accepted sockets to be placed
directly into the fixed file table.

## Multishot receive

[io_uring_prep_recv_multishot] sets up a multishot receive
operation. Each time data arrives on the socket, a CQE is generated.
This is typically used with provided buffers (see
[io_uring_provided_buffers]):

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv_multishot(sqe, sockfd, NULL, 0, 0);
    sqe->buf_group = bgid;
    sqe->flags |= IOSQE_BUFFER_SELECT;

Each completion includes:

- **IORING_CQE_F_MORE** if more completions will follow

- **IORING_CQE_F_BUFFER** indicating a buffer was selected

- The buffer ID in the upper bits of *cqe-\>flags*

- The number of bytes received in *cqe-\>res*

The multishot receive terminates when an error occurs, the connection
closes, or the buffer ring is exhausted.

## Multishot recvmsg

[io_uring_prep_recvmsg_multishot] is similar to multishot receive
but uses the *msghdr* structure for scatter/gather I/O and ancillary
data. A provided buffer is used for each message, with the kernel
writing a *struct io_uring_recvmsg_out* header at the start of the
buffer containing the actual message parameters.

## Multishot read

[io_uring_prep_read_multishot] sets up a multishot read operation,
typically used with pipes or other stream-oriented file descriptors.
Like multishot receive, this is used with provided buffers:

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_read_multishot(sqe, fd, 0, 0, bgid);

The operation generates a CQE each time data becomes available to read.

## Multishot poll

[io_uring_prep_poll_multishot] sets up a multishot poll operation,
or it can be done manually by setting the **IORING_POLL_ADD_MULTI**
flag:

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_poll_multishot(sqe, fd, POLLIN);
    /* or equivalently: */
    io_uring_prep_poll_add(sqe, fd, POLLIN);
    sqe->len |= IORING_POLL_ADD_MULTI;

Each time the polled condition becomes true, a CQE is generated with the
triggered events in *cqe-\>res*. Unlike oneshot poll which is
automatically removed after triggering, multishot poll remains active.

For level-triggered events, the application should be careful to handle
the event (e.g., read all available data) before the next poll
completion, or spurious wakeups may occur.

## Multishot waitid

[io_uring_prep_waitid] can operate in multishot mode by setting
**IORING_ACCEPT_MULTISHOT** in the flags. This allows waiting for
multiple child process state changes with a single SQE.

## Handling multishot completions

Applications must check for **IORING_CQE_F_MORE** to determine if the
operation is still active:

    struct io_uring_cqe *cqe;

    while (io_uring_peek_cqe(ring, &cqe) == 0) {
        if (cqe->res < 0) {
            /* Error occurred, operation terminated */
            handle_error(cqe->res);
        } else {
            process_completion(cqe);
        }

        if (!(cqe->flags & IORING_CQE_F_MORE)) {
            /* Operation terminated, may need to resubmit */
            rearm_if_needed();
        }

        io_uring_cqe_seen(ring, cqe);
    }

## Canceling multishot operations

Multishot operations can be canceled using [io_uring_prep_cancel]
or related functions. The cancellation request generates its own CQE,
and the multishot operation generates a final CQE (typically with
**-ECANCELED**) without **IORING_CQE_F_MORE** set.

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_cancel64(sqe, user_data, 0);

## Integration with provided buffers

Multishot receive and read operations are designed to work with provided
buffer rings (see [io_uring_provided_buffers]). Each completion
consumes a buffer from the ring, and the application must return buffers
to the ring to keep the operation running.

If the buffer ring becomes empty, the multishot operation terminates
with **-ENOBUFS**. Applications should ensure adequate buffers are
available and promptly return used buffers to the ring.

# NOTES

- Always check **IORING_CQE_F_MORE** to know if a multishot operation is
  still active.

- Multishot operations may generate many CQEs quickly. Ensure the CQ
  ring is large enough to avoid overflow.

- When using provided buffers with multishot receives, monitor buffer
  availability to prevent premature termination.

- Multishot operations are edge-triggered conceptually — they generate
  completions when events occur, not continuously while conditions are
  true.

- Error completions from multishot operations do not have
  **IORING_CQE_F_MORE** set, indicating termination.

# SEE ALSO

[io_uring], [io_uring_provided_buffers],
[io_uring_prep_multishot_accept],
[io_uring_prep_recv_multishot],
[io_uring_prep_recvmsg_multishot],
[io_uring_prep_read_multishot], [io_uring_prep_poll_add],
[io_uring_prep_poll_multishot], [io_uring_prep_cancel]
