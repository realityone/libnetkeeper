use crate::common::dialer::Dialer;
use crate::common::error::TimeError;
use crate::common::utils::resolve_timestamp;
use crate::crypto::hash::{HasherBuilder, HasherType};
use crate::netkeeper::dialer::NetkeeperDialer;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Netkeeper4DialerError {
    #[error("failed to resolve the current timestamp")]
    Time(#[from] TimeError),

    #[error("padded key is too short: need {required} bytes, got {actual}")]
    PaddedKeyTooShort { required: usize, actual: usize },

    #[error("hash output is too short: need byte {index}, got {actual} bytes")]
    HashOutputTooShort { index: usize, actual: usize },
}

pub type Netkeeper4DialerResult<T> = Result<T, Netkeeper4DialerError>;

#[derive(Debug, Copy, Clone)]
pub enum Configuration {
    Zhejiang,
}

#[derive(Debug)]
pub struct Netkeeper4Dialer {
    pub share_key: String,
    pub prefix: String,
    pub padding: String,
}

impl Configuration {
    pub fn share_key(self) -> &'static str {
        match self {
            Configuration::Zhejiang => "zjdxxyfsj2018",
        }
    }

    pub fn prefix(self) -> &'static str {
        match self {
            Configuration::Zhejiang => "\r1",
        }
    }

    pub fn padding(self) -> &'static str {
        match self {
            Configuration::Zhejiang => "GJxDpkZLtSEFarOMuHv",
        }
    }
}

impl Netkeeper4Dialer {
    pub fn new(share_key: &str, prefix: &str, padding: &str) -> Self {
        Netkeeper4Dialer {
            share_key: share_key.to_string(),
            prefix: prefix.to_string(),
            padding: padding.to_string(),
        }
    }

    fn prepare_md5_bytes(
        pin27_bytes: [u8; 6],
        username: &str,
        padded_key: &str,
    ) -> Netkeeper4DialerResult<Vec<u8>> {
        let padded_bytes =
            padded_key
                .as_bytes()
                .get(..32)
                .ok_or(Netkeeper4DialerError::PaddedKeyTooShort {
                    required: 32,
                    actual: padded_key.len(),
                })?;
        let name = username.split_once('@').map_or(username, |(name, _)| name);
        let name_bytes = name.as_bytes();
        let mut md5_bytes = vec![0u8; 64];
        let (mut j, mut k, mut l) = (0usize, 0usize, 0usize);
        for (i, item) in md5_bytes.iter_mut().enumerate().take(64) {
            match i % 3 {
                0 => {
                    if let Some(value) = name_bytes.get(j) {
                        *item = *value;
                        j += 1;
                        continue;
                    }
                }
                1 => {
                    if let Some(value) = pin27_bytes.get(k) {
                        *item = *value;
                        k += 1;
                        continue;
                    }
                }
                2 => {
                    if let Some(value) = padded_bytes.get(l) {
                        *item = *value;
                        l += 1;
                        continue;
                    }
                }
                _ => {}
            }
            if let Some(value) = pin27_bytes.get(k) {
                *item = *value;
                k += 1;
                continue;
            }
            if let Some(value) = padded_bytes.get(l) {
                *item = *value;
                l += 1;
                continue;
            }
            *item = i as u8;
        }
        Ok(md5_bytes)
    }

    pub fn encrypt_account(
        &self,
        username: &str,
        timestamp: Option<u32>,
    ) -> Netkeeper4DialerResult<String> {
        let username = username.to_uppercase();
        let timenow = resolve_timestamp(timestamp)?;
        let time_div_by_five: u32 = timenow / 5;

        let pin27_bytes: [u8; 6] = NetkeeperDialer::pin27_bytes(time_div_by_five);
        let pin27_str: String = pin27_bytes.into_iter().map(char::from).collect();

        let pin89_str = {
            let padded = format!("{}{}", self.share_key, self.padding);
            let mut md5 = HasherBuilder::build(HasherType::MD5);
            md5.update(&Self::prepare_md5_bytes(pin27_bytes, &username, &padded)?);
            let hashed_bytes = md5.finish();
            let byte_at = |index| {
                hashed_bytes
                    .get(index)
                    .copied()
                    .ok_or(Netkeeper4DialerError::HashOutputTooShort {
                        index,
                        actual: hashed_bytes.len(),
                    })
            };
            let x_index = usize::from((byte_at(11)? & 0xF0) >> 4);
            let y_index = usize::from((byte_at(13)? & 0x3C) >> 2);
            let z_index = usize::from(byte_at(6)? & 0x0F);
            let x = byte_at(x_index)?;
            let y = byte_at(y_index)?;
            let z = byte_at(z_index)?;
            let result = ((x & 0xF0) >> 6) + (y & 0x3C) + ((z & 0x0F) << 6);
            format!("{:02x}", result)
        };

        Ok(format!(
            "{}{}{}{}",
            self.prefix, pin27_str, pin89_str, username
        ))
    }
}

impl Dialer for Netkeeper4Dialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        Netkeeper4Dialer::new(config.share_key(), config.prefix(), config.padding())
    }
}

#[test]
fn test_prepare_md5_bytes() {
    let md5_bytes = Netkeeper4Dialer::prepare_md5_bytes(
        [0, 1, 2, 3, 4, 5],
        "05802278989@HYXY.XY",
        "112233445566778899aabbccddeeffgg",
    )
    .unwrap();
    assert_eq!(
        md5_bytes,
        vec![
            48, 0, 49, 53, 1, 49, 56, 2, 50, 48, 3, 50, 50, 4, 51, 50, 5, 51, 55, 52, 52, 56, 53,
            53, 57, 54, 54, 56, 55, 55, 57, 56, 56, 57, 57, 97, 97, 98, 98, 99, 99, 100, 100, 101,
            101, 102, 102, 103, 103, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ]
    );
}
