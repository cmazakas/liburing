extern crate liburing_rs;
extern crate nix;
extern crate rand;

use core::panic;
use std::{
    cell::UnsafeCell,
    collections::HashMap,
    hash::{DefaultHasher, Hasher},
    mem::{self, ManuallyDrop},
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
    ptr::null_mut,
    rc::Rc, time::Instant,
};

use liburing_rs::{
    IORING_CQE_BUFFER_SHIFT, IORING_CQE_F_MORE, IORING_CQE_F_NOTIF, IORING_RECVSEND_BUNDLE,
    IORING_RECVSEND_POLL_FIRST, IORING_SETUP_CQSIZE, IORING_SETUP_DEFER_TASKRUN,
    IORING_SETUP_SINGLE_ISSUER, IOSQE_BUFFER_SELECT, io_uring, io_uring_buf_ring,
    io_uring_buf_ring_add, io_uring_buf_ring_advance, io_uring_buf_ring_mask, io_uring_cq_advance,
    io_uring_cqe, io_uring_cqe_get_data64, io_uring_for_each_cqe, io_uring_get_sqe,
    io_uring_params, io_uring_prep_recv_multishot, io_uring_prep_send_zc, io_uring_queue_exit,
    io_uring_queue_init_params, io_uring_setup_buf_ring, io_uring_sqe, io_uring_sqe_set_data64,
    io_uring_sqe_set_flags, io_uring_submit, io_uring_submit_and_wait,
    io_uring_unregister_buf_ring,
};

use nix::{
    libc::{ENOBUFS, close},
    sys::socket::{
        AddressFamily::Inet, Backlog, SockFlag, SockType::Stream, SockaddrIn, SockaddrStorage,
        accept, bind, connect, listen, setsockopt, socket, sockopt,
    },
};
use rand::Fill;

const NUM_CONNS: u32 = 20000;
const NUM_BUFS: u32 = 32 * 1024;
const BUF_LEN: usize = 4096;
const SERVER_BGID: i32 = 27;
const CLIENT_BGID: i32 = 72;
const MSG_LEN: usize = 256 * 1024;

const PORT: u16 = 10202;

fn fill_bytes(bytes: &mut [u8], seed: u64)
{
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed);
    <[u8] as Fill>::fill(bytes, &mut rng);
}

#[derive(Default)]
struct Conn
{
    fd: i32,
    num_sent: usize,
    num_received: usize,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
    expected_hash: u64,
    hasher: DefaultHasher,
}

pub struct IoContext
{
    pframe: Rc<UnsafeCell<IoContextFrame>>,
}

#[derive(Clone)]
pub struct Executor
{
    pframe: Rc<UnsafeCell<IoContextFrame>>,
}

struct IoContextFrame
{
    ring: io_uring,
    buf_rings: HashMap<u16, BufRing>,
    params: IoContextParams,
}

#[derive(Default, Clone, Copy)]
pub struct IoContextParams
{
    pub cq_entries: u32,
    pub use_defer_taskrun: bool,
}

struct BufRing
{
    num_bufs: u32,
    buf_len: usize,
    bufs: Vec<Vec<u8>>,
    br: *mut io_uring_buf_ring,
}

impl Drop for IoContextFrame
{
    fn drop(&mut self)
    {
        let ring = &raw mut self.ring;

        for bgid in self.buf_rings.keys() {
            unsafe { io_uring_unregister_buf_ring(ring, *bgid as _) };
        }
        unsafe { io_uring_queue_exit(ring) };
    }
}

impl IoContext
{
    fn from_params(params: &IoContextParams) -> IoContext
    {
        let mut pms = io_uring_params { cq_entries: params.cq_entries,
                                        flags: IORING_SETUP_CQSIZE,
                                        ..Default::default() };

        if params.use_defer_taskrun {
            pms.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
        }

        let ring = unsafe { std::mem::zeroed::<io_uring>() };
        let pframe = Rc::new(UnsafeCell::new(IoContextFrame { ring,
                                                              buf_rings: HashMap::new(),
                                                              params: *params }));

        let ring = unsafe { &raw mut (*pframe.get()).ring };

        let ret = unsafe { io_uring_queue_init_params(256, ring, &raw mut pms) };
        assert_eq!(ret, 0);

        IoContext { pframe }
    }

    pub fn get_executor(&self) -> Executor
    {
        Executor { pframe: self.pframe.clone() }
    }
}

impl Executor
{
    fn ring(&self) -> *mut io_uring
    {
        unsafe { &raw mut (*self.pframe.get()).ring }
    }

    pub fn register_buf_ring(&self, num_bufs: u32, buf_len: usize, bgid: i32)
    {
        let mut ret = 0;
        let ring = self.ring();

        let err = &raw mut ret;
        let br = unsafe { io_uring_setup_buf_ring(ring, num_bufs, bgid, 0, err) };
        if br.is_null() {
            panic!("failed to setup buf_ring, errno: {ret}");
        }

        let mut bufs = vec![Vec::<u8>::new(); num_bufs as _];

        for bid in 0..num_bufs {
            bufs[bid as usize] = Vec::with_capacity(buf_len);

            unsafe {
                io_uring_buf_ring_add(br,
                                      bufs[bid as usize].as_mut_ptr().cast(),
                                      buf_len as _,
                                      bid as _,
                                      io_uring_buf_ring_mask(num_bufs),
                                      bid as _)
            };
        }

        unsafe { io_uring_buf_ring_advance(br, num_bufs as _) };

        let buf_ring = BufRing { num_bufs,
                                 buf_len,
                                 bufs,
                                 br };

        let buf_rings = unsafe { &mut (*self.pframe.get()).buf_rings };
        buf_rings.insert(bgid as _, buf_ring);
    }
}

fn get_sqe(ex: Executor) -> *mut io_uring_sqe
{
    let ring = ex.ring();

    let mut sqe = unsafe { io_uring_get_sqe(ring) };
    while sqe.is_null() {
        unsafe { io_uring_submit(ring) };
        sqe = unsafe { io_uring_get_sqe(ring) };
    }

    sqe
}

macro_rules! impl_op_type {
    ($enum:ident { $($variant:ident = $value:expr),* $(,)? }) => {
        #[repr(i16)]
        enum $enum
        {
            $($variant = $value),*
        }

        impl TryFrom<i16> for $enum
        {
            type Error = i16;

            fn try_from(value: i16) -> Result<Self, Self::Error>
            {
                match value
                {
                    $($value => Ok($enum::$variant),)*
                    _ => Err(value),
                }
            }
        }
    };
}

impl_op_type! {

OpType
{
    SendOp = 1,
    RecvOp = 2,
}

}

unsafe fn prep_user_data(sqe: *mut io_uring_sqe, idx: i32, op: OpType)
{
    let user_data: u64 = (idx as u64) | ((op as u64) << 32);
    unsafe { io_uring_sqe_set_data64(sqe, user_data) };
}

fn user_data_to_idx(user_data: u64) -> i32
{
    (user_data & 0xffffffff) as i32
}

fn user_data_to_op(user_data: u64) -> OpType
{
    let op = (user_data >> 32) as i16;
    OpType::try_from(op).unwrap()
}

fn prep_send(conn: &Conn, ex: Executor, idx: u32)
{
    let mut n = MSG_LEN - conn.num_sent;
    if n > 16 * 1024 {
        n = 16 * 1024;
    }

    let sqe = get_sqe(ex);
    unsafe {
        io_uring_prep_send_zc(sqe,
                              conn.fd,
                              conn.send_buf.as_ptr().add(conn.num_sent).cast(),
                              n,
                              0,
                              0)
    };

    unsafe { prep_user_data(sqe, idx as _, OpType::SendOp) };
}

fn prep_recv(conn: &Conn, ex: Executor, idx: u32, bgid: u16)
{
    let sqe = get_sqe(ex);
    unsafe { io_uring_prep_recv_multishot(sqe, conn.fd, null_mut(), 0, 0) };
    unsafe { io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT) };
    unsafe { (*sqe).__liburing_anon_4.buf_group = bgid };
    unsafe { (*sqe).ioprio = (IORING_RECVSEND_POLL_FIRST | IORING_RECVSEND_BUNDLE) as u16 };

    unsafe { prep_user_data(sqe, idx as _, OpType::RecvOp) };
}

#[test]
fn test_tcp_stress_send()
{
    let params = IoContextParams { cq_entries: 64 * 1024,
                                   use_defer_taskrun: true };

    let ioc = IoContext::from_params(&params);
    let ex = ioc.get_executor();

    let bgid = SERVER_BGID;

    ex.register_buf_ring(NUM_BUFS, BUF_LEN, bgid);

    let accept_fd;
    {
        accept_fd = socket(Inet, Stream, SockFlag::empty(), None).unwrap();
        setsockopt(&accept_fd, sockopt::ReuseAddr, &true).unwrap();
        let addr: SockaddrStorage = SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT).into();
        bind(accept_fd.as_raw_fd(), &addr).unwrap();
        listen(&accept_fd, Backlog::new(1024).unwrap()).unwrap();
    }

    let mut send_bufs = Vec::with_capacity(NUM_CONNS as _);
    for idx in 0..NUM_CONNS {
        let mut buf = vec![0_u8; MSG_LEN];
        fill_bytes(&mut buf, idx as _);
        send_bufs.push(buf);
    }

    let expected_hashes = send_bufs.iter()
                                   .map(|buf| {
                                       let mut h = DefaultHasher::new();
                                       h.write(buf);
                                       h.finish()
                                   })
                                   .collect::<Vec<_>>();

    let ring = ex.ring();

    let t = std::thread::spawn(move || client_thread(send_bufs));

    let mut conns = Vec::<Conn>::new();
    for idx in 0..NUM_CONNS {
        let expected_hash = expected_hashes[idx as usize];

        conns.push(Conn { fd: accept(accept_fd.as_raw_fd()).unwrap(),
                          num_sent: 0,
                          send_buf: vec![0_u8; MSG_LEN],
                          recv_buf: vec![0_u8; MSG_LEN],
                          num_received: 0,
                          expected_hash,
                          hasher: DefaultHasher::new() });
    }

    for idx in 0..NUM_CONNS {
        let conn = &conns[idx as usize];
        prep_recv(conn, ex.clone(), idx, bgid as _);
    }

    let mut num_completed = 0;
    while num_completed < NUM_CONNS {
        unsafe { io_uring_submit_and_wait(ring, 1) };

        let mut n = 0;

        let on_cqe = |cqe: *mut io_uring_cqe| {
            n += 1;

            let user_data = unsafe { io_uring_cqe_get_data64(cqe) };
            let idx = user_data_to_idx(user_data);
            let op = user_data_to_op(user_data);

            let conn = &mut conns[idx as usize];
            let cqe_res = unsafe { (*cqe).res };

            match op {
                OpType::RecvOp => {
                    if cqe_res == -ENOBUFS {
                        prep_recv(conn, ex.clone(), idx as _, bgid as _);
                        return;
                    }

                    // println!("cqe is: {:?}", unsafe { &*cqe });
                    assert!(cqe_res >= 0);

                    let flags = unsafe { (*cqe).flags };

                    if flags & IORING_CQE_F_MORE == 0 {
                        prep_recv(conn, ex.clone(), idx as _, bgid as _);
                    }

                    let mut bid = flags >> IORING_CQE_BUFFER_SHIFT;

                    let mut offset = 0;
                    let mut num_received = cqe_res as usize;

                    let buf_rings = unsafe { &mut (*ex.pframe.get()).buf_rings };
                    let buf_ring = buf_rings.get_mut(&(bgid as _)).unwrap();
                    let buf_len = buf_ring.buf_len;

                    while num_received > 0 {
                        let mut n = buf_len;
                        if num_received < buf_len {
                            n = num_received;
                        }

                        let bufs = &mut buf_ring.bufs;
                        unsafe { bufs[bid as usize].set_len(n) };

                        let end = conn.num_received + n;
                        let dst = &mut conn.send_buf[conn.num_received..end];
                        let src = &bufs[bid as usize][0..n];

                        conn.hasher.write(src);
                        dst.copy_from_slice(src);

                        let buf = mem::take(&mut bufs[bid as usize]);
                        drop(buf);

                        let mut new_buf = Vec::<u8>::with_capacity(buf_len);

                        unsafe {
                            io_uring_buf_ring_add(buf_ring.br,
                                                  new_buf.as_mut_ptr().cast(),
                                                  new_buf.capacity() as _,
                                                  bid as _,
                                                  io_uring_buf_ring_mask(buf_ring.num_bufs),
                                                  offset)
                        };

                        bufs[bid as usize] = new_buf;

                        num_received -= n;
                        conn.num_received += n;

                        bid += 1;
                        offset += 1;
                    }

                    unsafe { io_uring_buf_ring_advance(buf_ring.br, offset) };

                    if conn.num_received == MSG_LEN {
                        assert_eq!(conn.hasher.finish(), conn.expected_hash);

                        prep_send(conn, ex.clone(), idx as _);
                    }
                }
                OpType::SendOp => {
                    assert!(cqe_res >= 0);

                    if conn.num_sent < MSG_LEN {
                        conn.num_sent += cqe_res as usize;

                        let flags = unsafe { (*cqe).flags };
                        if flags & IORING_CQE_F_NOTIF != 0 {
                            prep_send(conn, ex.clone(), idx as _);
                            return;
                        }

                        assert!(flags & IORING_CQE_F_MORE != 0);
                    } else {
                        num_completed += 1;
                    }
                }
            }
        };

        unsafe { io_uring_for_each_cqe(ring, on_cqe) };
        unsafe { io_uring_cq_advance(ring, n) };
    }

    t.join().unwrap();

    for conn in &conns {
        unsafe { close(conn.fd) };
    }
}

fn client_thread(mut send_bufs: Vec<Vec<u8>>)
{
    let params = IoContextParams { cq_entries: 64 * 1024,
                                   use_defer_taskrun: true };

    let ioc = IoContext::from_params(&params);
    let ex = ioc.get_executor();

    let bgid = CLIENT_BGID;

    let ring = ex.ring();

    ex.register_buf_ring(NUM_BUFS, BUF_LEN, bgid);

    let start_time = Instant::now();

    let mut conns = Vec::<Conn>::new();
    for idx in 0..NUM_CONNS {
        let fd = socket(Inet, Stream, SockFlag::empty(), None).unwrap();
        connect(fd.as_raw_fd(), &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT))).unwrap();

        let buf = mem::take(&mut send_bufs[idx as usize]);

        let mut h = DefaultHasher::new();
        h.write(&buf);
        let expected_hash = h.finish();

        conns.push(Conn { fd: fd.as_raw_fd(),
                          num_sent: 0,
                          send_buf: buf,
                          recv_buf: vec![0_u8; MSG_LEN],
                          num_received: 0,
                          expected_hash,
                          hasher: DefaultHasher::new() });

        let _ = ManuallyDrop::new(fd);
    }

    for idx in 0..NUM_CONNS {
        prep_send(&conns[idx as usize], ex.clone(), idx);
    }

    let mut num_completed = 0;
    while num_completed < NUM_CONNS {
        unsafe { io_uring_submit_and_wait(ring, 1) };

        let mut n = 0;
        let on_cqe = |cqe: *mut io_uring_cqe| {
            // immediately advance this so we can do things like early-return
            n += 1;

            // println!("cqe => {:?}", unsafe { &*cqe });

            let user_data = unsafe { io_uring_cqe_get_data64(cqe) };
            let idx = user_data_to_idx(user_data);
            let op = user_data_to_op(user_data);

            let cqe_res = unsafe { (*cqe).res };

            let conn = &mut conns[idx as usize];

            match op {
                OpType::SendOp => {
                    assert!(cqe_res >= 0);

                    if conn.num_sent < MSG_LEN {
                        conn.num_sent += cqe_res as usize;

                        let flags = unsafe { (*cqe).flags };
                        if flags & IORING_CQE_F_NOTIF != 0 {
                            prep_send(conn, ex.clone(), idx as _);
                            return;
                        }

                        assert!(flags & IORING_CQE_F_MORE != 0);
                    } else {
                        prep_recv(conn, ex.clone(), idx as _, bgid as _);
                    }
                }
                OpType::RecvOp => {
                    if cqe_res == -ENOBUFS {
                        prep_recv(conn, ex.clone(), idx as _, bgid as _);
                        return;
                    }

                    // println!("cqe is: {:?}", unsafe { &*cqe });
                    assert!(cqe_res >= 0);

                    let flags = unsafe { (*cqe).flags };

                    if flags & IORING_CQE_F_MORE == 0 {
                        prep_recv(conn, ex.clone(), idx as _, bgid as _);
                    }

                    let mut bid = flags >> IORING_CQE_BUFFER_SHIFT;

                    let mut offset = 0;
                    let mut num_received = cqe_res as usize;

                    let buf_rings = unsafe { &mut (*ex.pframe.get()).buf_rings };
                    let buf_ring = buf_rings.get_mut(&(bgid as _)).unwrap();

                    while num_received > 0 {
                        let mut n = BUF_LEN;
                        if num_received < BUF_LEN {
                            n = num_received;
                        }

                        let bufs = &mut buf_ring.bufs;
                        unsafe { bufs[bid as usize].set_len(n) };

                        let end = conn.num_received + n;
                        let dst = &mut conn.recv_buf[conn.num_received..end];
                        let src = &bufs[bid as usize][0..n];

                        conn.hasher.write(src);
                        dst.copy_from_slice(src);

                        let buf = mem::take(&mut bufs[bid as usize]);
                        drop(buf);

                        let mut new_buf = Vec::<u8>::with_capacity(BUF_LEN);

                        unsafe {
                            io_uring_buf_ring_add(buf_ring.br,
                                                  new_buf.as_mut_ptr().cast(),
                                                  new_buf.capacity() as _,
                                                  bid as _,
                                                  io_uring_buf_ring_mask(buf_ring.num_bufs),
                                                  offset)
                        };

                        bufs[bid as usize] = new_buf;

                        num_received -= n;
                        conn.num_received += n;

                        bid += 1;
                        offset += 1;
                    }

                    unsafe { io_uring_buf_ring_advance(buf_ring.br, offset) };

                    if conn.num_received == MSG_LEN {
                        assert!(conn.recv_buf == conn.send_buf);
                        assert_eq!(conn.expected_hash, conn.hasher.finish());
                        num_completed += 1;
                    }
                }
            }
        };

        unsafe { io_uring_for_each_cqe(ring, on_cqe) };
        unsafe { io_uring_cq_advance(ring, n) };
    }

    for conn in &conns {
        unsafe { close(conn.fd) };
    }

    println!("completed client loop in: {:?}", start_time.elapsed());
}
