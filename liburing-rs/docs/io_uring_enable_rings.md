Enable a disabled ring

# DESCRIPTION

The [io_uring_enable_rings] function enables a ring after having
created it with the **IORING_SETUP_R_DISABLED** flag to
[io_uring_queue_init]

It is not possible to submit work to such a ring until this function has
been successfully called.

# RETURN VALUE

[io_uring_enable_rings] returns 0 on success. It otherwise returns
a negative error code. It does not write to **errno**.

# ERRORS

**EBADFD**  
The ring was not disabled.

# SEE ALSO

[io_uring_queue_init], [io_uring_register],
[io_uring_setup]
