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
