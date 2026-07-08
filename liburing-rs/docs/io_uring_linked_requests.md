Io_uring linked requests overview

# DESCRIPTION

Linked requests allow applications to chain multiple io_uring operations
together, creating dependencies between them. When requests are linked,
they execute sequentially rather than concurrently, with each request
starting only after the previous one in the chain completes.

## Why use linked requests?

Normal io_uring submissions are independent and may execute in any order
or concurrently. However, some operations have natural dependencies:

- Read from one file, then write to another

- Connect to a server, then send a request

- Accept a connection, then receive data

- Perform an operation with a timeout

Without linking, applications would need to wait for completions and
submit follow-up requests manually. Linked requests allow the entire
chain to be submitted at once, reducing round trips between user space
and the kernel.

Linked requests are most beneficial when:

- Operations must execute in a specific order

- Later operations depend on earlier ones succeeding

- You want to attach a timeout to an operation

- Reducing submission latency is important

## Creating linked requests

Requests are linked by setting the **IOSQE_IO_LINK** flag on a request.
This links it to the next request in the submission. The chain continues
until a request without the link flag is encountered.

    struct io_uring_sqe *sqe;

    /* First request in chain */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd_in, buf, len, 0);
    sqe->flags |= IOSQE_IO_LINK;

    /* Second request, linked to first */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_write(sqe, fd_out, buf, len, 0);
    sqe->flags |= IOSQE_IO_LINK;

    /* Third request, end of chain (no link flag) */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_fsync(sqe, fd_out, 0);

    io_uring_submit(ring);

In this example, the read completes first, then the write, then the
fsync. Each operation waits for the previous one to complete before
starting.

## Soft links vs hard links

There are two types of links, which differ in how they handle errors:

**Soft links (IOSQE_IO_LINK)**

> If a request in the chain fails (returns a negative error code), all
> subsequent requests in the chain are canceled with **-ECANCELED**.
> This is useful when later operations depend on earlier ones
> succeeding.

**Hard links (IOSQE_IO_HARDLINK)**

> The chain continues executing even if a request fails. Each request
> runs regardless of the outcome of previous requests. This is useful
> when you want to attempt all operations even if some fail.

    /* Soft link: write is canceled if read fails */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd, buf, len, 0);
    sqe->flags |= IOSQE_IO_LINK;

    sqe = io_uring_get_sqe(ring);
    io_uring_prep_write(sqe, fd2, buf, len, 0);

    /* Hard link: write runs even if read fails */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd, buf, len, 0);
    sqe->flags |= IOSQE_IO_HARDLINK;

    sqe = io_uring_get_sqe(ring);
    io_uring_prep_write(sqe, fd2, buf, len, 0);

## Link timeouts

A common use of linked requests is to add a timeout to an operation. The
**IORING_OP_LINK_TIMEOUT** operation (set up with
[io_uring_prep_link_timeout]) is designed specifically for this:

    struct __kernel_timespec ts = { .tv_sec = 5, .tv_nsec = 0 };

    /* The operation to be timed */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd, buf, len, 0);
    sqe->flags |= IOSQE_IO_LINK;

    /* The timeout, linked to the read */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_link_timeout(sqe, &ts, 0);

    io_uring_submit(ring);

If the read completes before the timeout:

- The read CQE has the actual result

- The timeout CQE has **-ECANCELED**

If the timeout expires first:

- The read CQE has **-ECANCELED** (or **-EINTR** if it was in progress)

- The timeout CQE has **-ETIME**

Link timeouts only apply to the immediately preceding request in the
chain. To timeout an entire chain, the timeout must be linked after the
last operation.

## Completion ordering

Each request in a linked chain generates its own CQE. Completions for
linked requests are ordered — the CQE for an earlier request in the
chain will be posted before the CQE for a later request.

Applications can rely on this ordering when processing completions.
However, if other unlinked requests are in flight, their completions may
be interleaved with the chain's completions.

## Error handling

For soft-linked chains, error handling is straightforward:

- Check each CQE's result

- If a request failed, all subsequent requests will have **-ECANCELED**

- The first non-canceled error indicates where the chain broke

<!-- -->

    /* Processing a linked chain's completions */
    for (int i = 0; i < chain_length; i++) {
        io_uring_wait_cqe(ring, &cqe);

        if (cqe->res == -ECANCELED) {
            /* Previous request in chain failed */
        } else if (cqe->res < 0) {
            /* This request failed, caused chain break */
            handle_error(cqe->res);
        } else {
            /* Success */
            handle_success(cqe->res);
        }

        io_uring_cqe_seen(ring, cqe);
    }

## Common patterns

**Copy with sync:**

> Read data, write it elsewhere, then sync:
>
>     io_uring_prep_read(sqe1, src_fd, buf, len, 0);
>     sqe1->flags |= IOSQE_IO_LINK;
>
>     io_uring_prep_write(sqe2, dst_fd, buf, len, 0);
>     sqe2->flags |= IOSQE_IO_LINK;
>
>     io_uring_prep_fsync(sqe3, dst_fd, 0);

**Connect with timeout:**

> Attempt connection with a time limit:
>
>     io_uring_prep_connect(sqe1, sockfd, addr, addrlen);
>     sqe1->flags |= IOSQE_IO_LINK;
>
>     io_uring_prep_link_timeout(sqe2, &timeout, 0);

**Send after connect:**

> Connect then immediately send data:
>
>     io_uring_prep_connect(sqe1, sockfd, addr, addrlen);
>     sqe1->flags |= IOSQE_IO_LINK;
>
>     io_uring_prep_send(sqe2, sockfd, data, len, 0);

# NOTES

- Linked requests must be submitted together in the same
  [io_uring_submit] call. The chain is defined by the order of SQEs
  in the submission.

- The link flag on the last request in a chain is ignored (it has
  nothing to link to).

- Chains can be arbitrarily long, limited only by SQ ring size.

- Mixing **IOSQE_IO_LINK** and **IOSQE_IO_HARDLINK** in the same chain
  is allowed. Each link's type determines what happens if that specific
  request fails.

- Linked requests share the same *personality* if set, allowing
  credential inheritance through the chain.

- If a request in a chain is canceled (e.g., via
  [io_uring_prep_cancel]), the chain breaks as if that request had
  failed.

- Linked requests have performance implications: they force sequential
  execution, preventing the kernel from optimizing or parallelizing
  operations. Use links only when ordering is required. For independent
  operations, submitting them without links allows the kernel to execute
  them concurrently or reorder them for better performance.

# SEE ALSO

[io_uring], [io_uring_prep_link_timeout],
[io_uring_prep_cancel], [io_uring_sqe_set_flags]
