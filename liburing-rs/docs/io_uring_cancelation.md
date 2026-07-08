Io_uring request cancelation overview

# DESCRIPTION

io_uring provides mechanisms to cancel in-flight requests before they
complete naturally. This is useful for implementing timeouts, handling
connection drops, closing connections that go away, or when a request is
no longer needed.

## Why cancel requests?

Common scenarios requiring cancelation:

- **Timeouts:** Cancel a read or accept that has been pending too long

- **Connection management:** Cancel pending operations when a connection
  is closed

- **Resource cleanup:** Cancel operations on a file descriptor being
  closed

- **Multishot termination:** Stop a multishot operation that is no
  longer needed

## Basic cancelation

The primary cancelation mechanism is **IORING_OP_ASYNC_CANCEL** (set up
with [io_uring_prep_cancel] or related functions). By default, it
cancels a request matching a specific *user_data*:

    /* Submit a read with user_data = 1234 */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data64(sqe, 1234);
    io_uring_submit(ring);

    /* Later, cancel it */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_cancel64(sqe, 1234, 0);
    io_uring_submit(ring);

## Cancelation results

When a cancelation is submitted, two CQEs are generated:

**The canceled request's CQE:**

Io_uring request cancelation overview
>   operation was already in progress)
>
Io_uring request cancelation overview

**The cancel request's CQE:**

Io_uring request cancelation overview
>
Io_uring request cancelation overview
>
Io_uring request cancelation overview
>   completing

The order of these CQEs is not guaranteed. The application may receive
the cancel CQE before or after the canceled request's CQE.

## Cancelation flags

Various flags modify cancelation behavior:

**IORING_ASYNC_CANCEL_ALL**

> Cancel all matching requests, not just the first one found. The cancel
> CQE's *res* indicates how many requests were canceled.

**IORING_ASYNC_CANCEL_FD**

> Match requests by file descriptor instead of *user_data*. Cancels
> requests operating on the specified fd:
>
>     io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_FD);

**IORING_ASYNC_CANCEL_ANY**

> Cancel any single request, ignoring *user_data* matching. Useful for
> draining a ring of all pending requests when combined with
> **IORING_ASYNC_CANCEL_ALL**.

**IORING_ASYNC_CANCEL_FD_FIXED**

> The file descriptor is a fixed file (registered file index) rather
> than a regular fd.

Flags can be combined:

    /* Cancel all requests on a specific fd */
    io_uring_prep_cancel_fd(sqe, fd,
        IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ALL);

    /* Cancel all pending requests in the ring */
    io_uring_prep_cancel(sqe, NULL,
        IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_ALL);

## Race conditions

Cancelation is inherently racy. Between submitting the cancel request
and the kernel processing it:

- The target request may complete successfully

- The target request may fail for another reason

- The target request may already be in a non-cancelable state

Applications must handle these cases:

    io_uring_wait_cqe(ring, &cqe);

    if (cqe->user_data == cancel_user_data) {
        /* This is the cancel operation's result */
        if (cqe->res == -ENOENT) {
            /* Request already completed or not found */
        } else if (cqe->res == -EALREADY) {
            /* Request was found but completing */
        } else if (cqe->res >= 0) {
            /* Successfully canceled res requests */
        }
    } else {
        /* This is the original request's result */
        if (cqe->res == -ECANCELED) {
            /* Request was canceled */
        } else {
            /* Request completed normally (or with error) */
        }
    }

## Link timeouts

For timing out a single operation, link timeouts are often simpler than
explicit cancelation. See [io_uring_linked_requests] for details:

    sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd, buf, len, 0);
    sqe->flags |= IOSQE_IO_LINK;

    sqe = io_uring_get_sqe(ring);
    io_uring_prep_link_timeout(sqe, &timeout, 0);

The kernel handles the cancelation automatically if the timeout expires.

## Canceling multishot requests

Multishot requests (see [io_uring_multishot]) continue generating
completions until canceled or an error occurs. To stop a multishot
request:

    /* Cancel a multishot accept */
    io_uring_prep_cancel64(sqe, accept_user_data, 0);

After cancelation:

- The multishot generates a final CQE with **-ECANCELED**

- The **IORING_CQE_F_MORE** flag is not set on this final CQE

- The cancel CQE indicates success

## Canceling by file descriptor

When a file descriptor is closed (either via [close](https://man7.org/linux/man-pages/man2/close.2.html) or
**IORING_OP_CLOSE**), pending requests operating on that fd are **not**
automatically canceled. This differs from synchronous I/O behavior and
is a common source of confusion.

In synchronous I/O, closing a file descriptor is typically the last
reference to the underlying file, so the close completes any pending
operations. However, io_uring holds its own reference to the file for
each pending request. Closing the application's fd does not release
these references — the pending read, recv, or other operation continues
to hold a reference and will not automatically complete or fail.

If an application expects a pending read on an fd to post a completion
when the fd is closed, that will not happen. The request must be
explicitly canceled:

    /* Cancel all operations on fd before closing */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_cancel_fd(sqe, fd,
        IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ALL);
    io_uring_submit(ring);

    /* Wait for cancelations, then close */

## Shutdown cancelation

When an io_uring instance is closed (via [io_uring_queue_exit] or
closing the ring file descriptor), all pending requests are
automatically canceled. Manual cancelation before shutdown is not
required.

However, if the application needs to ensure all requests are completed
before proceeding (e.g., to process their results or free associated
resources), explicit cancelation can be used:

    /* Cancel everything */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_cancel(sqe, NULL,
        IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_ALL);
    io_uring_submit(ring);

    /* Wait for all CQEs */
    while (pending_count > 0) {
        io_uring_wait_cqe(ring, &cqe);
        pending_count--;
        io_uring_cqe_seen(ring, cqe);
    }

## Synchronous cancelation

For cases where the application needs to cancel requests and wait for
the cancelation to complete in a single blocking call,
[io_uring_register_sync_cancel] provides a synchronous interface:

    struct io_uring_sync_cancel_reg reg = {
        .addr = user_data,
        .timeout.tv_sec = 5,
    };

    ret = io_uring_register_sync_cancel(ring, &reg);

This blocks until the matching request is canceled or the timeout
expires. It is useful when the application cannot easily integrate
asynchronous cancelation into its event loop.

# NOTES

- Not all operations are cancelable. Operations that have already been
  submitted to hardware (e.g., disk I/O in progress) typically cannot be
  canceled.

- Cancelation is asynchronous. The cancel request itself may take time
  to complete.

- When using **IORING_ASYNC_CANCEL_ALL**, the cancel CQE's *res* field
  contains the count of canceled requests.

- Fixed files can be canceled using **IORING_ASYNC_CANCEL_FD_FIXED**
  with the file index instead of a regular fd.

- Poll operations and multishot requests are generally good candidates
  for cancelation. Completed disk I/O is not.

# SEE ALSO

[io_uring], [io_uring_linked_requests],
[io_uring_multishot], [io_uring_prep_cancel],
[io_uring_prep_cancel64], [io_uring_prep_cancel_fd],
[io_uring_prep_link_timeout], [io_uring_register_sync_cancel]
