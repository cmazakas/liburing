Prepare an accept request

# DESCRIPTION

The [io_uring_prep_accept] function and its three variants prepare
an accept request similar to [accept4](https://man7.org/linux/man-pages/man2/accept4.2.html). The submission queue entry
*sqe* is setup to use the file descriptor *sockfd* to start accepting a
connection request described by the socket address at *addr* and of
structure length *addrlen* and using modifier flags in *flags*.

The three variants allow combining the direct file table and multishot
features.

Direct descriptors are io_uring private file descriptors. They avoid
some of the overhead associated with thread shared file tables and can
be used in any io_uring request that takes a file descriptor. The two
direct variants here create such direct descriptors. Subsequent to their
creation, they can be used by setting **IOSQE_FIXED_FILE** in the SQE
*flags* member, and setting the SQE *fd* field to the direct descriptor
value rather than the regular file descriptor. Direct descriptors are
managed like registered files.

To use an accept direct variant, the application must first have
registered a file table of a desired size using
[io_uring_register_files] or [io_uring_register_files_sparse].
Once registered, [io_uring_prep_accept_direct] allows an entry in
that table to be specifically selected through the *file_index*
argument. If the specified entry already contains a file, the file will
first be removed from the table and closed, consistent with the behavior
of updating an existing file with [io_uring_register_files_update].
*file_index* can also be set to **IORING_FILE_INDEX_ALLOC** for this
variant and an unused table index will be dynamically chosen and
returned. Likewise, **io_uring_prep_multishot_accept_direct** will have
an unused table index dynamically chosen and returned for each
connection accepted. If both forms of direct selection will be employed,
specific and dynamic, see [io_uring_register_file_alloc_range] for
setting up the table so dynamically chosen entries are made against a
different range than that targeted by specific requests.

Note that old kernels don't check the SQE *file_index* field meaning
applications cannot rely on a **-EINVAL** CQE *res* being returned when
the kernel is too old because older kernels may not recognize they are
being asked to use a direct table slot.

When a direct descriptor accept request asks for a table slot to be
dynamically chosen but there are no free entries, **-ENFILE** is
returned as the CQE *res*.

The multishot variants allow an application to issue a single accept
request, which will repeatedly trigger a CQE when a connection request
comes in. Like other multishot type requests, the application should
look at the CQE *flags* and see if **IORING_CQE_F_MORE** is set on
completion as an indication of whether or not the accept request will
generate further CQEs. Note that for the multishot variants, setting
**addr** and **addrlen** may not make a lot of sense, as the same value
would be used for every accepted connection. This means that the data
written to **addr** may be overwritten by a new connection before the
application has had time to process a past connection. If the
application knows that a new connection cannot come in before a previous
one has been processed, it may be used as expected. The multishot
variants are available since 5.19.

See the man page [accept4](https://man7.org/linux/man-pages/man2/accept4.2.html) for details of the accept function
itself.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation.

[io_uring_prep_accept] generates the installed file descriptor as
its result.

[io_uring_prep_accept_direct] and *file_index* set to a specific
direct descriptor generates **0** on success. The caller must remember
which direct descriptor was picked for this request.

[io_uring_prep_accept_direct] and *file_index* set to
**IORING_FILE_INDEX_ALLOC** generates the dynamically chosen direct
descriptor.

[io_uring_prep_multishot_accept] generates the installed file
descriptor in each result.

[io_uring_prep_multishot_accept_direct], generates the dynamically
chosen direct descriptor in each result.

Note that where synchronous system calls will return **-1** on failure
and set *errno* to the actual error value, io_uring never uses *errno*.
Instead it generates the negated *errno* directly in the CQE *res*
field.

# NOTES

As with any request that passes in data in a struct, that data must
remain valid until the request has been successfully submitted. It need
not remain valid until completion. Once a request has been submitted,
the in-kernel state is stable. Very early kernels (5.4 and earlier)
required state to be stable until the completion occurred. Applications
can test for this behavior by inspecting the
**IORING_FEAT_SUBMIT_STABLE** flag passed back from
[io_uring_queue_init_params].

Note that the direct versions of accept do not accept **SOCK_CLOEXEC ,**
and setting that flag will result in an **-EINVAL** error in the CQE.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register_files], [io_uring_register_files_sparse],
[io_uring_register_file_alloc_range], [io_uring_register],
[accept4](https://man7.org/linux/man-pages/man2/accept4.2.html)
