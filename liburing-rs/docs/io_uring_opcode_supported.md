Is op code supported?.

# DESCRIPTION

The function [io_uring_opcode_supported] allows the caller to
determine if the passed in *opcode* belonging to the *probe* param is
supported. An instance of the io_uring_probe instance can be obtained by
calling the function [io_uring_get_probe].

# RETURN VALUE

On success it returns 1, otherwise it returns 0.

# SEE ALSO

[io_uring_get_probe]
