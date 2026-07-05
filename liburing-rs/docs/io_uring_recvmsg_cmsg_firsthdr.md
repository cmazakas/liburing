Access data from multishot recvmsg.

# DESCRIPTION

These functions are used to access data in the payload delivered by
[io_uring_prep_recvmsg_multishot].

*msgh* should point to the *struct msghdr* submitted with the request.

[io_uring_recvmsg_validate] will validate a buffer delivered by
[io_uring_prep_recvmsg_multishot] and extract the
*io_uring_recvmsg_out* if it is valid, returning a pointer to it or else
NULL.

The structure is defined as follows:

```c
    struct io_uring_recvmsg_out {
            __u32 namelen;    /* Name byte count as would have been populated
                               * by recvmsg(2) */
            __u32 controllen; /* Control byte count */
            __u32 payloadlen; /* Payload byte count as would have been returned
                               * by recvmsg(2) */
            __u32 flags;      /* Flags result as would have been populated
                               * by recvmsg(2) */
    };
```

* [io_uring_recvmsg_name] - returns a pointer to the name in the buffer.
* [io_uring_recvmsg_cmsg_firsthdr] - returns a pointer to the first cmsg in the buffer, or NULL.
* [io_uring_recvmsg_cmsg_nexthdr] - returns a pointer to the next cmsg in the buffer, or NULL.
* [io_uring_recvmsg_payload] - returns a pointer to the payload in the buffer.
* [io_uring_recvmsg_payload_length] - Calculates the usable payload length in bytes.

# SEE ALSO

[io_uring_prep_recvmsg_multishot]
