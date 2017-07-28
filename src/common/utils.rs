use chrono::offset::Utc;

pub fn current_timestamp() -> u32 {
    let now = Utc::now();
    now.timestamp() as u32
}
