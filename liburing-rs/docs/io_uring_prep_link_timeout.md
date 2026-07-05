A timeout request for linked sqes.

# DESCRIPTION

The [io_uring_prep_link_timeout] function prepares a timeout
request for linked sqes. The submission queue entry *sqe* is setup for
with timeout specified by *ts*. The flags argument holds modifier
*flags* for the timeout behaviour of the request.

The *ts* argument must be filled in with the appropriate information for
the timeout. It looks as follows:

```c
    struct __kernel_timespec {
        __kernel_time64_t tv_sec;
        long long tv_nsec;
    };
```

The *flags* argument may contain:

**IORING_TIMEOUT_ABS**
The value specified in *ts* is an absolute value rather than a relative
one.

**IORING_TIMEOUT_BOOTTIME**
The boottime clock source should be used.

**IORING_TIMEOUT_REALTIME**
The realtime clock source should be used.

**IORING_TIMEOUT_ETIME_SUCCESS**
Consider an expired timeout a success in terms of the posted completion.

It is invalid to create a chain (linked sqes) consisting only of a link
timeout request. If all the requests in the chain are completed before
timeout, then the link timeout request gets canceled. Upon timeout, all
the uncompleted requests in the chain get canceled.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, **0** is returned.

**-ETIME**
The specified timeout occurred and triggered the completion event.

**-EINVAL**
One of the fields set in the SQE was invalid. For example, two clock
sources where given, or the specified timeout seconds or nanoseconds
where \< 0.

**-EFAULT**
io_uring was unable to access the data specified by ts.

**-ECANCELED**
The timeout was canceled because all submitted requests were completed
successfully or one of the requests resulted in failure.

**-ENOENT**
The request to which the linked timeout was linked already completed and
could not be found when the timer expired.

# SEE ALSO

[io_uring_get_sqe], [io_uring_prep_timeout]
