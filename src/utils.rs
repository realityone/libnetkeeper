use std::slice;
use std::mem;

use time;

#[allow(dead_code)]
pub fn current_timestamp() -> u32 {
    let timespec = time::get_time();
    timespec.sec as u32
}

pub fn integer_to_bytes<T>(intger: &T) -> &[u8] {
    let integer_bytes: &[u8];
    unsafe {
        integer_bytes = slice::from_raw_parts::<u8>((intger as *const T) as *const u8,
                                                    mem::size_of::<T>());
    }
    integer_bytes
}
