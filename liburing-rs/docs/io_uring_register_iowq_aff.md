Register async worker CPU affinities.

# DESCRIPTION

The [io_uring_prep_register_iowq_aff] function registers a set of
CPU affinities to be used by the io_uring async workers. By default,
io_uring async workers are allowed to run on any CPU in the system. If
this function is called with *ring* set to the ring in question and
*mask* set to a pointer to a **cpu_set_t** value and *cpusz* set to the
size of the CPU set, then async workers will only be allowed to run on
the CPUs specified in the mask. Existing workers may need to hit a
schedule point before they are migrated.

For unregistration, [io_uring_unregister_iowq_aff] may be called to
restore CPU affinities to the default.

Applications must define **\_GNU_SOURCE** to obtain the definition of
this helper, as *cpu_set_t* will not be defined without it.

# RETURN VALUE

Returns **0** on success, or any of the following values in case of
error.

**-EFAULT**\
The kernel was unable to copy the memory pointer to by *mask* as it was
invalid.

**-ENOMEM**\
The kernel was unable to allocate memory for the new CPU mask.

**-EINVAL**\
*cpusz* or *mask* was NULL/0, or any other value specified was invalid.

# SEE ALSO

[io_uring_queue_init], [io_uring_register]
