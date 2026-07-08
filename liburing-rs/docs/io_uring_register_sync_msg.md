Send a synchronous message to another ring

# DESCRIPTION

[io_uring_register_sync_msg] issues a synchronous MSG_RING request.
The *sqe* parameter must have been cleared and initialized with
[io_uring_prep_msg_ring]**.**

Normally message requests are sent from one ring to another ring. But
there are also cases where a source ring is not available, yet it would
be convenient to send a message to a destination ring.
[io_uring_register_sync_msg] exists for that purpose. A source ring
is not required to send a message to another ring, instead the *sqe*
parameter can be placed on the stack and filled in using the normal
message helpers, and then [io_uring_register_sync_msg] can be
called. Since a source ring does not exist, the results of the operation
is returned directly rather than via a CQE. On the destination/receiving
end, a CQE is posted, as it would have been with a non-sync request.

Only data request are supported, sending files such as setup by
[io_uring_prep_msg_ring_fd] is not supported. The given SQE should
be initialized by [io_uring_prep_msg_ring] or
[io_uring_prep_msg_ring_cqe_flags]**,** or any other helper that
sets up a non-fd message request.

The targeted ring may be any ring that the user has access to, even the
ring itself. This request can be used for simple message passing to
another ring, allowing 32+64 bits of data to be transferred through the
*len* and *data* fields. The use case may be anything from simply waking
up someone waiting on the targeted ring, or it can be used to pass
messages between the two rings.

[io_uring_prep_msg_ring_cqe_flags] is similar to
[io_uring_prep_msg_ring]**.** But has an addition *cqe_flags*
parameter, which is used to set *flags* field on CQE side. That way, you
can set the CQE flags field *cqe-\>flags* when sending a message. Be
aware that io_uring could potentially set additional bits into this
field.

Available since kernel 6.13.

# RETURN VALUE

Returns 0 on success, or **-errno** on error.

# SEE ALSO

[io_uring_prep_msg_ring_cqe_flags]**,**
[io_uring_prep_msg_ring]
