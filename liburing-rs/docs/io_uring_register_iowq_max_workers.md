Modify the maximum allowed async
workers

# DESCRIPTION

io_uring async workers are split into two types:

**Bounded**  
These workers have a bounded execution time. Examples of that are
filesystem reads, which normally complete in a relatively short amount
of time. In case of disk failures, they are still bounded by a timeout
operation that will abort them if exceeded.

**Unbounded**  
Work items here may take an indefinite amount of time to complete.
Examples include doing IO to sockets, pipes, or any other non-regular
type of file.

By default, the amount of bounded IO workers is limited to how many SQ
entries the ring was setup with, or 4 times the number of online CPUs in
the system, whichever is smaller. Unbounded workers are only limited by
the process task limit, as indicated by the rlimit **RLIMIT_NPROC**
limit.

This can be modified by calling **io_uring_register_iowq_max_workers**
with *ring* set to the ring in question, and *values* pointing to an
array of two values. The first element should contain the number of
desired bounded workers, and the second element should contain the
number of desired unbounded workers. These are both maximum values,
io_uring will not maintain a high count of idle workers, they are reaped
when they are not necessary anymore.

If called with both values set to 0, the existing values are returned.

# RETURN VALUE

Returns **0** on success, with *values* containing the previous values
for the settings. On error, any of the following may be returned.

**-EFAULT**  
The kernel was unable to copy the memory pointer to by *values* as it
was invalid.

**-EINVAL**  
*values* was **NULL** or the new values exceeded the maximum allowed
value.

# SEE ALSO

[io_uring_queue_init], [io_uring_register]
