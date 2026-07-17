use std::string::FromUtf8Error;

use thiserror::Error;

use crate::common::dialer::Dialer;
use crate::common::error::TimeError;
use crate::common::utils::resolve_timestamp;

#[derive(Debug, Error)]
pub enum SingleNetDialerError {
    #[error("failed to resolve the current timestamp")]
    Time(#[from] TimeError),

    #[error("key table is too short: need at least {required} bytes, got {actual}")]
    KeyTableTooShort { required: usize, actual: usize },

    #[error("generated account prefix is not valid UTF-8")]
    InvalidPrefixEncoding(#[from] FromUtf8Error),
}

pub type SingleNetDialerResult<T> = Result<T, SingleNetDialerError>;

#[derive(Debug)]
pub enum Configuration {
    Hainan,
}

#[derive(Debug)]
pub struct SingleNetDialer {
    share_key: String,
    secret_key: String,
    key_table: String,
}

impl SingleNetDialer {
    pub fn new(share_key: &str, secret_key: &str, key_table: &str) -> Self {
        SingleNetDialer {
            share_key: share_key.to_string(),
            secret_key: secret_key.to_string(),
            key_table: key_table.to_string(),
        }
    }

    pub fn encrypt_account(
        &self,
        username: &str,
        timestamp: Option<u32>,
    ) -> SingleNetDialerResult<String> {
        let username = username.to_uppercase();
        let time_now = resolve_timestamp(timestamp)?;

        let first_hash: u16;
        {
            let mut hash_data: Vec<u8> = Vec::new();
            hash_data.extend_from_slice(&time_now.to_be_bytes());
            hash_data.extend(self.share_key.as_bytes());
            let account_name = username
                .split_once('@')
                .map_or(username.as_str(), |(name, _)| name);
            hash_data.extend(account_name.as_bytes());
            first_hash = Self::calc_hash(&hash_data)
        }

        let second_hash: u16;
        {
            let mut hash_data: Vec<u8> = Vec::new();
            hash_data.extend_from_slice(&first_hash.to_be_bytes());
            hash_data.extend(self.secret_key.as_bytes());
            second_hash = Self::calc_hash(&hash_data);
        }

        let time_now_high = (time_now >> 16) as u16;
        let time_now_low = (time_now & 0xFFFF) as u16;
        let [time_high0, time_high1] = time_now_high.to_be_bytes();
        let [hash10, hash11] = first_hash.to_ne_bytes();
        let [time_low0, time_low1] = time_now_low.to_be_bytes();
        let [hash20, hash21] = second_hash.to_ne_bytes();
        let scheduled_table = [
            time_high0, time_high1, hash10, hash11, time_low0, time_low1, hash20, hash21,
        ];

        let mut vectors: [u8; 12] = [0; 12];
        for (source, destination) in scheduled_table
            .chunks_exact(2)
            .zip(vectors.chunks_exact_mut(3))
        {
            let [first, second] = source else {
                continue;
            };
            let [vector0, vector1, vector2] = destination else {
                continue;
            };
            *vector0 = first >> 0x3 & 0x1F;
            *vector1 = ((first & 0x7) << 0x2) | (second >> 0x6 & 0x3);
            *vector2 = second & 0x3F;
        }

        let key_table_bytes = self.key_table_bytes();
        if key_table_bytes.len() < 64 {
            return Err(SingleNetDialerError::KeyTableTooShort {
                required: 64,
                actual: key_table_bytes.len(),
            });
        }
        let pin = vectors
            .iter()
            .map(|index| {
                key_table_bytes.get(usize::from(*index)).copied().ok_or(
                    SingleNetDialerError::KeyTableTooShort {
                        required: 64,
                        actual: key_table_bytes.len(),
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let pin_str = String::from_utf8(pin)?;
        Ok(format!("~LL_{}_{}", pin_str, username))
    }

    fn calc_hash(data: &[u8]) -> u16 {
        let (paired_data, mut summary) = if data.len() % 2 == 0 {
            (data, 0)
        } else if let Some((last, paired)) = data.split_last() {
            (paired, u32::from(*last))
        } else {
            (data, 0)
        };

        for pair in paired_data.chunks_exact(2) {
            let [first, second] = pair else {
                continue;
            };
            summary = summary.wrapping_add(u32::from(u16::from_ne_bytes([*first, *second])));
        }
        if summary & 0xFFFF_0000 != 0 {
            summary = (summary.wrapping_shr(0x10).wrapping_add(summary)) & 0xFFFF;
        }

        !summary as u16
    }

    fn key_table_bytes(&self) -> &[u8] {
        self.key_table.as_bytes()
    }
}

impl Configuration {
    pub fn share_key(&self) -> &'static str {
        match *self {
            Configuration::Hainan => "hngx01",
        }
    }

    pub fn secret_key(&self) -> &'static str {
        match *self {
            Configuration::Hainan => "000c29270712",
        }
    }

    pub fn key_table(&self) -> &'static str {
        match *self {
            Configuration::Hainan => {
                "abcdefghijklmnopqrstuvwxyz1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA:_"
            }
        }
    }
}

impl Dialer for SingleNetDialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        SingleNetDialer::new(config.share_key(), config.secret_key(), config.key_table())
    }
}

#[test]
fn test_hash_key() {
    let str1 = "123456".to_string();
    let str2 = "1234567".to_string();
    let hash1 = SingleNetDialer::calc_hash(str1.as_bytes());
    let hash2 = SingleNetDialer::calc_hash(str2.as_bytes());
    assert_eq!(hash1, 25446u16);
    assert_eq!(hash2, 25391u16);
}
