use std::time::SystemTimeError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimeError {
    #[error("system clock is before the Unix epoch")]
    BeforeUnixEpoch(#[source] SystemTimeError),

    #[error("Unix timestamp {seconds} does not fit in a 32-bit value")]
    TimestampOutOfRange { seconds: u64 },
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
    #[error("buffer length mismatch: expected {expected} bytes, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}
