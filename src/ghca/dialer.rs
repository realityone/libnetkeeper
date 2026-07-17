use crate::common::bytes::BytesAbleNum;
use crate::common::dialer::Dialer;
use crate::common::error::TimeError;
use crate::common::hex::ToHex;
use crate::common::utils::resolve_timestamp;
use crate::crypto::hash::{HasherBuilder, HasherType};
use thiserror::Error;

const MAX_CREDENTIAL_LENGTH: usize = 60;

#[derive(Debug, Error)]
pub enum GhcaDialerError {
    #[error("username is too long: maximum {max} bytes, got {actual}")]
    UsernameTooLong { max: usize, actual: usize },

    #[error("password is too long: maximum {max} bytes, got {actual}")]
    PasswordTooLong { max: usize, actual: usize },

    #[error("password must not be empty")]
    EmptyPassword,

    #[error(
        "username and password suffix require {actual} bytes, exceeding the protocol limit of {max}"
    )]
    CredentialCombinationTooLong { max: usize, actual: usize },

    #[error("share key is too short: need {required} bytes, got {actual}")]
    ShareKeyTooShort { required: usize, actual: usize },

    #[error("cannot split a {length}-byte password at byte {index}")]
    InvalidPasswordSplit { index: usize, length: usize },

    #[error("hash output is too short: need {required} bytes, got {actual}")]
    HashOutputTooShort { required: usize, actual: usize },

    #[error("failed to resolve the current timestamp")]
    Time(#[from] TimeError),
}

#[derive(Debug, Clone, Copy)]
pub enum Configuration {
    SichuanMac,
}

#[derive(Debug)]
pub struct GhcaDialer {
    pub share_key: String,
    pub prefix: String,
    pub version: String,
}

impl GhcaDialer {
    fn new(share_key: &str, prefix: &str, version: &str) -> Self {
        GhcaDialer {
            share_key: share_key.to_string(),
            prefix: prefix.to_string(),
            version: version.to_string(),
        }
    }

    fn validate(username: &str, password: &str) -> Result<(), GhcaDialerError> {
        if username.len() > MAX_CREDENTIAL_LENGTH {
            return Err(GhcaDialerError::UsernameTooLong {
                max: MAX_CREDENTIAL_LENGTH,
                actual: username.len(),
            });
        }
        if password.is_empty() {
            return Err(GhcaDialerError::EmptyPassword);
        }
        if password.len() > MAX_CREDENTIAL_LENGTH {
            return Err(GhcaDialerError::PasswordTooLong {
                max: MAX_CREDENTIAL_LENGTH,
                actual: password.len(),
            });
        }
        Ok(())
    }

    pub fn encrypt_account(
        &self,
        username: &str,
        password: &str,
        fst_timestamp: Option<u32>,
        sec_timestamp: Option<u32>,
    ) -> Result<String, GhcaDialerError> {
        Self::validate(username, password)?;
        let name_len = username.len();
        let pwd_len = password.len();

        let fst_timestamp = resolve_timestamp(fst_timestamp)?;
        let sec_timestamp = resolve_timestamp(sec_timestamp)?;

        let mut cursor = (fst_timestamp % pwd_len as u32) as usize;
        if cursor < 1 {
            cursor += 1;
        }
        let match_flag = if cursor == pwd_len { 1 } else { 0 };

        let delta = cursor - match_flag;
        let md5_hash_prefix;
        {
            let mut md5 = HasherBuilder::build(HasherType::MD5);

            let prefix_len = delta + 1;
            let suffix_len = pwd_len - prefix_len;
            let password_bytes = password.as_bytes();
            let pwd_prefix =
                password_bytes
                    .get(..prefix_len)
                    .ok_or(GhcaDialerError::InvalidPasswordSplit {
                        index: prefix_len,
                        length: password_bytes.len(),
                    })?;
            let pwd_suffix =
                password_bytes
                    .get(prefix_len..)
                    .ok_or(GhcaDialerError::InvalidPasswordSplit {
                        index: prefix_len,
                        length: password_bytes.len(),
                    })?;
            let share_key_bytes = self.share_key.as_bytes();
            let first_key_len = MAX_CREDENTIAL_LENGTH - prefix_len;
            let combined_length = name_len.saturating_add(suffix_len);
            let second_key_len = 64usize.checked_sub(combined_length).ok_or(
                GhcaDialerError::CredentialCombinationTooLong {
                    max: 64,
                    actual: combined_length,
                },
            )?;
            let first_key =
                share_key_bytes
                    .get(..first_key_len)
                    .ok_or(GhcaDialerError::ShareKeyTooShort {
                        required: first_key_len,
                        actual: share_key_bytes.len(),
                    })?;
            let second_key =
                share_key_bytes
                    .get(..second_key_len)
                    .ok_or(GhcaDialerError::ShareKeyTooShort {
                        required: second_key_len,
                        actual: share_key_bytes.len(),
                    })?;

            md5.update(&sec_timestamp.as_bytes_be());
            md5.update(first_key);
            md5.update(pwd_prefix);
            md5.update(username.as_bytes());
            md5.update(second_key);
            md5.update(pwd_suffix);

            let first_hashed_bytes = md5.finish();
            let mut md5 = HasherBuilder::build(HasherType::MD5);
            md5.update(&first_hashed_bytes);
            let second_hash = md5.finish();
            let hash_prefix = second_hash
                .get(..8)
                .ok_or(GhcaDialerError::HashOutputTooShort {
                    required: 8,
                    actual: second_hash.len(),
                })?;
            md5_hash_prefix = hash_prefix.to_hex().to_uppercase();
        }

        let pwd_char_sum = password
            .as_bytes()
            .iter()
            .fold(0, |sum, x| sum + u32::from(*x));
        let pin = format!("{:04X}", (delta as u32) ^ pwd_char_sum);
        Ok(format!(
            "{}{:08X}{}{}{}{}",
            self.prefix, sec_timestamp, self.version, md5_hash_prefix, pin, username
        ))
    }
}

impl Configuration {
    pub fn share_key(self) -> &'static str {
        match self {
            Configuration::SichuanMac => {
                "aI0fC8RslXg6HXaKAUa6kpvcAXszvTcxYP8jmS9sBnVfIqTRdJS1eZNHmBjKN28j"
            }
        }
    }

    pub fn prefix(self) -> &'static str {
        "~ghca"
    }

    pub fn version(self) -> &'static str {
        match self {
            Configuration::SichuanMac => "2023",
        }
    }
}

impl Dialer for GhcaDialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        GhcaDialer::new(config.share_key(), config.prefix(), config.version())
    }
}
