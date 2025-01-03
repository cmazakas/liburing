# axboe-liburing

This crate implements an almost pure Rust version of Jens Axboe's [liburing](https://github.com/axboe/liburing).
All the good names were taken so the package's name is axboe-liburing but the imported crate is `liburing_rs`.

liburing has tremendous value in that it's a low-level unopinionated set of helpers that form a complete vocabulary
for using io_uring. Originally designed as a set of test helpers, liburing is used to setup and teardown rings, register
buffer groups, and create and manage SQEs and CQEs. liburing's API offers users a comprehensive way of using io_uring
in a simple manner.

axboe-liburing implements the entire header `liburing.h` in native Rust so that everything is as equally inlined as
if you were using the library from C or C++. This covers around 117 public functions.

Add the crate with:
```bash
cargo add axboe-liburing
```

axboe-liburing ships with the liburing source and builds `liburing.a`, statically linking it in via the `build.rs`. This means
that axboe-liburing requires a C toolchain be present on the system in order to build. Typical conventions are followed,
the environment variables `CC`, `CXX` are used to set the C and C++ compilers. axboe-liburing also uses `objcopy` in order to weaken
the `io_uring_get_sqe()` symbol present in `liburing.a`. When cross-compiling, it can be important to specify the `objcopy` being used.
The `objcopy` binary can be set via the `OBJCOPY` environment variable. `objcopy` ships with gcc toolchains.

Example:
```bash
export CC=aarch64-linux-gnu-gcc
export CXX=aarch64-linux-gnu-g++
export OBJCOPY=aarch64-linux-gnu-objcopy
cargo build --target aarch64-unknown-linux-gnu
```

For documentation, see the man pages for the liburing package itself. The Arch Linux pages have relatively up-to-date
docs: https://man.archlinux.org/listing/extra/liburing/.

Examples can be found in the main repo: https://github.com/axboe/liburing/tree/master/examples

Example:
```rust
extern crate liburing_rs;

use std::{mem::zeroed, ptr, time::Duration};

use liburing_rs::*;

#[test]
pub fn queue_init() {
    // Setup the ring.
    //
    // We create a stack-local instance of `struct io_uring` and use
    // the `io_uring_queue_init` function to initialize all of its
    // fields, using a submission queue size of 64. liburing sets
    // the size of the CQ to twice the SQ size by default.
    //
    let mut ring = unsafe { zeroed::<io_uring>() };
    let ring = &raw mut ring;
    let r = unsafe { io_uring_queue_init(64, ring, 0) };
    assert_eq!(r, 0);

    // Grab a pointer to an unused SQE from the SQ
    let sqe = unsafe { io_uring_get_sqe(ring) };
    assert!(!sqe.is_null());

    // We're going to create an SQE that completes after a specified
    // amount of time, in this case 250ms. We introduce a cast for `ts`
    // because liburing expects a pointer to `__kernel_timespec` which
    // is layout compatible.
    //
    let dur = Duration::from_millis(250);
    let mut ts: timespec = dur.into();
    let ts = (&raw mut ts).cast();

    unsafe { io_uring_prep_timeout(sqe, ts, 0, 0) };
    unsafe { io_uring_sqe_set_data64(sqe, 1234) };

    // Submit the SQ to the kernel for processing. `io_uring_submit` returns
    // the number of submitted entries that are going to be processed. In this case,
    // we only have 1 work item.
    //
    let n = unsafe { io_uring_submit(ring) };
    assert_eq!(n, 1);

    // Grab the first CQE off the queue and make sure it has the same `user_data`
    // field that we originally set.
    //
    let mut cqe = ptr::null_mut::<io_uring_cqe>();
    unsafe { io_uring_wait_cqe(ring, &raw mut cqe) };

    assert!(!cqe.is_null());
    assert_eq!(unsafe { (*cqe).user_data }, 1234);

    // Mark the CQE as seen so that its spot can be reused as more
    // completions arrive.
    //
    unsafe { io_uring_cqe_seen(ring, cqe) };

    // Teardown the ring.
    //
    unsafe { io_uring_queue_exit(ring) };
}
```
