Unregister NAPI busy poll settings

# DESCRIPTION

The [io_uring_unregister_napi] function unregisters the NAPI busy
poll settings for subsequent operations.

# RETURN VALUE

On success [io_uring_unregister_napi] return 0. On failure they
return **-errno**. It also updates the napi structure with the current
values.
