#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::pedantic)]

include!(concat!(env!("OUT_DIR"), "/liburing_bindings.rs"));

pub const IOSQE_FIXED_FILE: u32 = 1 << IOSQE_FIXED_FILE_BIT;
pub const IOSQE_IO_DRAIN: u32 = 1 << IOSQE_IO_DRAIN_BIT;
pub const IOSQE_IO_LINK: u32 = 1 << IOSQE_IO_LINK_BIT;
pub const IOSQE_IO_HARDLINK: u32 = 1 << IOSQE_IO_HARDLINK_BIT;
pub const IOSQE_ASYNC: u32 = 1 << IOSQE_ASYNC_BIT;
pub const IOSQE_BUFFER_SELECT: u32 = 1 << IOSQE_BUFFER_SELECT_BIT;
pub const IOSQE_CQE_SKIP_SUCCESS: u32 = 1 << IOSQE_CQE_SKIP_SUCCESS_BIT;
