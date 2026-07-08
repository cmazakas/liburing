Sets up and registers fixed wait regions

# DESCRIPTION

The [io_uring_submit_and_wait_reg] submits previously prepared
requests in the ring *ring* and waits for *wait_nr* completions using
the registered wait index of *reg_index*. Upon successful return, the
completion events are stored in the *cqe_ptr* array.

This function works like [io_uring_submit_and_wait_min_timeout] in
that it supports all the features of that helper, but rather than pass
in all the information in a struct that needs copying, it references a
registered wait index for which previously registered wait region holds
information about how the wait should be performed. That includes
information such as the overall timeout, the minimum timeout to be used,
and so forth. See [io_uring_setup_register_region] for the details
on registered regions, specifically for registered wait regions.

Using registered wait regions has less overhead then other wait methods,
as no copying of data is needed.

It's valid to use this function purely for waiting on events, even if no
new requests should be submitted.

# RETURN VALUE

On success [io_uring_submit_and_wait_reg] returns the number of new
requests submitted. On failure it returns **-errno**. If the kernel
doesn't support this functionality, **-EINVAL** will be returned. If no
events are submitted and the wait operation times out, then **-ETIME**
will be returned.

# SEE ALSO

[io_uring_register_region]**,**
[io_uring_submit_and_wait_min_timeout]**,**
[io_uring_submit_and_wait_timeout]
