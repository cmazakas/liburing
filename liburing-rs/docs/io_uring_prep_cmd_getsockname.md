Prepare a getsockname or getpeername.
request

# DESCRIPTION

The [io_uring_prep_cmd_getsockname] function prepares a
getsockname/getpeername request. The submission queue entry *sqe* is
setup to fetch the locally bound address or peer address of the socket
file descriptor pointed by *sockfd*. The parameter *sockaddr* points to
a region of size *sockaddr_len* where the output is written.
*sockaddr_len* is modified by the kernel on return to indicate how many
bytes were written. The output address is the locally bound address if
*peer* is set to **0** or the peer address if *peer* is set to **1**.

This function prepares an async [getsockname] or [getpeername]
request. See those man pages for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field. Differently
from the equivalent system calls, if the user attempts to use this
operation on a non-socket file descriptor, the CQE error result is
*ENOTSUP* instead of *ENOSOCK.*

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [getsockname],
[getpeername]
