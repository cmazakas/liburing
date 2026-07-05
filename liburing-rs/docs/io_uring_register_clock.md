Set clock source for event waiting.

# DESCRIPTION

The [io_uring_register_clock] function registers which clock source
should be used by io_uring, when an application waits for event
completions. The *ring* argument should point to the ring in question,
and the *arg* argument should be a pointer to a **struct
io_uring_clock_register .**

The *arg* argument must be filled in with the appropriate information.
It looks as follows:

```c
    struct io_uring_clock_register {
        __u32 clockid;
        __u32 __resv[3];
    };
```

The *clockid* field must contain the clock source, with valid sources
being:

**CLOCK_MONOTONIC**\
a nonsettable system-wide clock that represents monotonic time.

**CLOCK_BOOTTIME**\
A nonsettable system-wide clock that is identical to **CLOCK_MONOTONIC
,** except that is also icnludes any time that the system is suspended.

See [clock_gettime] for more details.

The *\_\_resv* fields must be filled with zeroes.

Available since 6.12.

# RETURN VALUE

On success [io_uring_register_clock] returns 0. On failure it
returns **-errno**.

# SEE ALSO

[clock_gettime], [io_uring_register],
[io_uring_wait_cqe], [io_uring_wait_cqe_timeout],
