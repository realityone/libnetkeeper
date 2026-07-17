use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_secs() as u32
}
