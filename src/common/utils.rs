use std::time::{SystemTime, UNIX_EPOCH};

use crate::common::error::TimeError;

pub fn current_timestamp() -> Result<u32, TimeError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(TimeError::BeforeUnixEpoch)?
        .as_secs();
    u32::try_from(seconds).map_err(|_| TimeError::TimestampOutOfRange { seconds })
}

pub fn resolve_timestamp(timestamp: Option<u32>) -> Result<u32, TimeError> {
    timestamp.map_or_else(current_timestamp, Ok)
}
