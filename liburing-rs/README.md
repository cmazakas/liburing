# liburing-rs

This crate implements an almost pure Rust version of Jens Axboe's [liburing](https://github.com/axboe/liburing).

There are a few existing Rust crates that help users setup and teardown rings for use with io_uring but none
have implemented the complete vocabulary that liburing.h has. This is where liburing-rs comes in.

liburing-rs implements the entire header `liburing.h` in native Rust so that everything is equally inlined as
if you were using the library from C or C++. This means that liburing-rs is the most comprehensive way of
using io_uring in Rust.

Example:
```rust
extern crate liburing_rs;

use std::{mem::zeroed, ptr, time::Duration};

use liburing_rs::*;

#[test]
pub fn queue_init() {
    let mut ring = unsafe { zeroed::<io_uring>() };
    let ring = &raw mut ring;
    let r = unsafe { io_uring_queue_init(64, ring, 0) };
    assert_eq!(r, 0);

    let sqe = unsafe { io_uring_get_sqe(ring) };
    assert!(!sqe.is_null());

    let dur = Duration::from_millis(250);
    let mut ts: timespec = dur.into();
    let ts = (&raw mut ts).cast();

    unsafe { io_uring_prep_timeout(sqe, ts, 0, 0) };
    unsafe { io_uring_sqe_set_data64(sqe, 1234) };

    let n = unsafe { io_uring_submit(ring) };
    assert_eq!(n, 1);

    let mut cqe = ptr::null_mut::<io_uring_cqe>();
    unsafe { io_uring_wait_cqe(ring, &raw mut cqe) };

    assert!(!cqe.is_null());
    assert_eq!(unsafe { (*cqe).user_data }, 1234);

    unsafe { io_uring_cqe_seen(ring, cqe) };
    unsafe { io_uring_queue_exit(ring) };
}
```
