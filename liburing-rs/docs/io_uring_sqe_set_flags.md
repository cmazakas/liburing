Set flags for submission queue entry

# DESCRIPTION

The [io_uring_sqe_set_flags] function allows the caller to change
the behavior of the submission queue entry by specifying flags. It
enables the *flags* belonging to the *sqe* submission queue entry param.

*flags* is a bit mask of 0 or more of the following values ORed
together:

**IOSQE_FIXED_FILE**\
The file descriptor in the SQE refers to the index of a previously
registered file or direct file descriptor, not a normal file descriptor.

**IOSQE_ASYNC**\
Normal operation for io_uring is to try and issue an sqe as non-blocking
first, and if that fails, execute it in an async manner. To support more
efficient overlapped operation of requests that the application
knows/assumes will always (or most of the time) block, the application
can ask for an sqe to be issued async from the start. Note that this
flag immediately causes the SQE to be offloaded to an async helper
thread with no initial non-blocking attempt. This may be less efficient
and should not be used liberally or without understanding the
performance and efficiency tradeoffs.

**IOSQE_IO_LINK**\
When this flag is specified, the SQE forms a link with the next SQE in
the submission ring. That next SQE will not be started before the
previous request completes. This, in effect, forms a chain of SQEs,
which can be arbitrarily long. The tail of the chain is denoted by the
first SQE that does not have this flag set. Chains are not supported
across submission boundaries. Even if the last SQE in a submission has
this flag set, it will still terminate the current chain. This flag has
no effect on previous SQE submissions, nor does it impact SQEs that are
outside of the chain tail. This means that multiple chains can be
executing in parallel, or chains and individual SQEs. Only members
inside the chain are serialized. A chain of SQEs will be broken if any
request in that chain ends in error.

**IOSQE_IO_HARDLINK**\
Like **IOSQE_IO_LINK ,** except the links aren't severed if an error or
unexpected result occurs.

**IOSQE_IO_DRAIN**\
When this flag is specified, the SQE will not be started before
previously submitted SQEs have completed, and new SQEs will not be
started before this one completes.

**IOSQE_CQE_SKIP_SUCCESS**\
Request that no CQE be generated for this request, if it completes
successfully. This can be useful in cases where the application doesn't
need to know when a specific request completed, if it completed
successfully.

**IOSQE_BUFFER_SELECT**\
If set, and if the request types supports it, select an IO buffer from
the indicated buffer group. This can be used with requests that read or
receive data from a file or socket, where buffer selection is deferred
until the kernel is ready to transfer data, instead of when the IO is
originally submitted. The application must also set the *buf_group*
field in the SQE, indicating which previously registered buffer group to
select a buffer from.

# RETURN VALUE

None

# SEE ALSO

[io_uring_submit], [io_uring_register]
[io_uring_register_buffers] [io_uring_register_buf_ring]
