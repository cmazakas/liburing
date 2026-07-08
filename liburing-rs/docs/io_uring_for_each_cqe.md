Iterate pending completion events

# DESCRIPTION

The [io_uring_for_each_cqe] is a macro helper that iterates
completion events belonging to the *ring* using *head* as a temporary
iterator, and points *cqe* to each pending event when iterating.

This helper provides an efficient way to iterate all pending events in
the ring, and then advancing the CQ ring by calling
[io_uring_cq_advance] with the number of CQEs consumed when done.
As updating the kernel visible CQ ring state involves an ordered write,
doing it once for a number of events is more efficient than handling
each completion separately and calling [io_uring_cqe_seen] for each
of them.

# EXAMPLE

``` c
void handle_cqes(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	unsigned head;
	unsigned i = 0;

	io_uring_for_each_cqe(ring, head, cqe) {
		/* handle completion */
		printf("cqe: %d\n", cqe->res);
		i++;
	}

	io_uring_cq_advance(ring, i);
}
```

# RETURN VALUE

None

# SEE ALSO

[io_uring_wait_cqe_timeout], [io_uring_wait_cqe],
[io_uring_wait_cqes], [io_uring_cqe_seen],
[io_uring_buf_ring_cq_advance]
