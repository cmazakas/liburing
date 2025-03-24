use std::mem;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use io_uring::{IoUring, opcode};
use liburing_rs::{
    io_uring_cq_advance, io_uring_for_each_cqe, io_uring_get_sqe, io_uring_prep_nop, io_uring_queue_exit,
    io_uring_queue_init, io_uring_submit_and_wait,
};

struct TaskQueue(usize);

impl TaskQueue {
    pub fn want(&self) -> bool {
        self.0 != 0
    }

    pub fn pop(&mut self) {
        self.0 -= 1;
    }
}

fn bench_normal(c: &mut Criterion) {
    let mut io_uring = IoUring::new(16).unwrap();

    c.bench_function("normal", |b| {
        b.iter(|| {
            let mut queue = TaskQueue(128);

            while queue.want() {
                {
                    let mut sq = io_uring.submission();
                    while queue.want() {
                        unsafe {
                            match sq.push(&black_box(opcode::Nop::new()).build()) {
                                Ok(_) => queue.pop(),
                                Err(_) => break,
                            }
                        }
                    }
                }

                io_uring.submit_and_wait(16).unwrap();

                io_uring.completion().map(black_box).for_each(drop);
            }
        });
    });
}

fn bench_liburing(c: &mut Criterion) {
    let mut ring = unsafe { mem::zeroed::<liburing_rs::io_uring>() };
    let ring = &raw mut ring;
    unsafe { io_uring_queue_init(16, ring, 0) };

    c.bench_function("liburing-rs", |b| {
        b.iter(|| {
            let mut queue = TaskQueue(128);

            while queue.want() {
                {
                    while queue.want() {
                        let sqe = unsafe { io_uring_get_sqe(ring) };
                        if !sqe.is_null() {
                            unsafe { io_uring_prep_nop(sqe) };
                            queue.pop();
                        } else {
                            break;
                        }
                    }
                }

                let ret = unsafe { io_uring_submit_and_wait(ring, 16) };
                assert_eq!(ret, 16);
                unsafe {
                    io_uring_for_each_cqe(ring, |cqe| {
                        let cqe = black_box(cqe);
                        let _ = cqe;
                    })
                };
                unsafe { io_uring_cq_advance(ring, 16) };
            }
        });
    });

    unsafe { io_uring_queue_exit(ring) };
}

criterion_group!(squeue, bench_normal, bench_liburing);
criterion_main!(squeue);
