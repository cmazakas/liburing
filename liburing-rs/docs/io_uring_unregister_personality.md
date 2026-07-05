Unregister a personality from io_uring.

# DESCRIPTION

The [io_uring_unregister_personality] function unregisters a
previously registered personality from the io_uring instance specified
by *ring*. The *id* argument is the personality ID returned from a
previous call to [io_uring_register_personality].

After unregistering, the personality ID is no longer valid and must not
be used in future submissions.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# SEE ALSO

[io_uring_register_personality], [io_uring_register]
