Prepare a request to
set an extended attribute value

# DESCRIPTION

The [io_uring_prep_setxattr] function prepares a request to set an
extended attribute value. The submission queue entry *sqe* is setup to
set the *value* of the extended attribute identified by *name* and
associated with the given *path* in the filesystem with modifier flags
*flags*. The *len* argument specifies the size (in bytes) of *value*.

[io_uring_prep_fsetxattr] is identical to
[io_uring_prep_setxattr], only the extended attribute is set on the
open file referred to by *fd* in place of *path*.

This function prepares an async [setxattr](https://man7.org/linux/man-pages/man2/setxattr.2.html) request. See that man
page for details.

# RETURN VALUE

None

# SEE ALSO

[io_uring_get_sqe], [setxattr](https://man7.org/linux/man-pages/man2/setxattr.2.html)
