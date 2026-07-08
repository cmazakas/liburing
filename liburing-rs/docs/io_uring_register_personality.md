Register credentials with io_uring

# DESCRIPTION

The [io_uring_register_personality] function registers the
credentials of the calling application with the io_uring instance
specified by *ring*. This allows a ring to be shared between separate
users or processes while maintaining credential separation.

The returned personality ID can be used in the *personality* field of a
submission queue entry to execute that request with the registered
credentials.

# RETURN VALUE

Returns a positive personality ID on success that can be used in future
operations. On error, a negative errno value is returned.

# SEE ALSO

[io_uring_unregister_personality], [io_uring_register]
