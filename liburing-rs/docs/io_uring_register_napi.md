Register NAPI busy poll settings.

# DESCRIPTION

The [io_uring_register_napi] function registers the NAPI settings
for subsequent operations. The NAPI settings are specified in the
structure that is passed in the *napi* parameter. The structure consists
of the napi timeout *busy_poll_to* (napi busy poll timeout in us) and
*prefer_busy_poll*.

Registering a NAPI settings sets the mode when calling the function
napi_busy_loop and corresponds to the SO_PREFER_BUSY_POLL socket option.

NAPI busy poll can reduce the network roundtrip time.

# RETURN VALUE

On success [io_uring_register_napi] return 0. On failure they
return **-errno**. It also updates the napi structure with the current
values.
