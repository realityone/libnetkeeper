use std::slice;
use std::mem;
use std::any;

use time;

#[allow(dead_code)]
pub fn current_timestamp() -> u32 {
    let timespec = time::get_time();
    timespec.sec as u32
}

pub fn any_to_bytes<T>(any_type: &T) -> &[u8]
    where T: any::Any
{
    let integer_bytes: &[u8];
    unsafe {
        integer_bytes = slice::from_raw_parts::<u8>((any_type as *const T) as *const u8,
                                                    mem::size_of::<T>());
    }
    integer_bytes
}
