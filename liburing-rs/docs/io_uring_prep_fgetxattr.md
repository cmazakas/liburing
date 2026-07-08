Prepare a request to
get an extended attribute value

# DESCRIPTION

The [io_uring_prep_getxattr] function prepares a request to get an
extended attribute value. The submission queue entry *sqe* is setup to
get the *value* of the extended attribute identified by *name* and
associated with the given *path* in the filesystem. The *len* argument
specifies the size (in bytes) of *value*.

[io_uring_prep_fgetxattr] is identical to
[io_uring_prep_getxattr], only the open file referred to by *fd* is
interrogated in place of *path*.

This function prepares an async [getxattr](https://man7.org/linux/man-pages/man2/getxattr.2.html) request. See that man
page for details.

# RETURN VALUE

None

# SEE ALSO

[io_uring_get_sqe], [getxattr](https://man7.org/linux/man-pages/man2/getxattr.2.html)
