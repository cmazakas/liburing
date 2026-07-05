Set address details for send requests.

# DESCRIPTION

The [io_uring_prep_send_set_addr] function sets a socket
destination address specified by *dest_addr* and its length using
*addr_len* parameters. It can be used once *sqe* is prepared using any
of the [send] io_uring helpers. See man pages of
[io_uring_prep_send] or [io_uring_prep_send_zc].

# RETURN VALUE

None

# SEE ALSO

[io_uring_get_sqe], [io_uring_prep_send],
[io_uring_prep_send_zc], [send]
