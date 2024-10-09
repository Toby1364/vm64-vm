#![allow(dead_code)]

pub const SUCESS: u16 =                     0x0000;
pub const UNSPECIFIED: u16 =                0x0001;
pub const UNAUTHORIZED_INSTRUCTION: u16 =   0x0002;

pub const MEMORY_READ_VIOLATION: u16 =      0x0010;
pub const MEMORY_WRITE_VIOLATION: u16 =     0x0011;
pub const MEMORY_OUT_OF_BOUNDS: u16 =       0x0012;

pub const DRIVE_ACCESS_VIOLATION: u16 =     0x0020;
