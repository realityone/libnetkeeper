use time;

#[allow(dead_code)]
pub fn current_timestamp() -> i32 {
    let timespec = time::get_time();
    timespec.sec as i32
}
