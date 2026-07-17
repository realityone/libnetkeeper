use std::string::FromUtf8Error;

use thiserror::Error;

use crate::common::dialer::Dialer;

#[derive(Debug, Error)]
pub enum Srun3kDialerError {
    #[error("username byte at index {index} cannot be shifted by four: {byte:#04x}")]
    ByteShiftOverflow { index: usize, byte: u8 },

    #[error("encoded username is not valid UTF-8")]
    InvalidUsernameEncoding(#[from] FromUtf8Error),
}

pub type Srun3kDialerResult<T> = Result<T, Srun3kDialerError>;

#[derive(Debug)]
pub enum Configuration {
    TaLiMu,
}

pub struct Srun3kDialer {
    pub configuration: Configuration,
}

impl Srun3kDialer {
    pub fn new(config: Option<Configuration>) -> Self {
        let config = config.unwrap_or(Configuration::TaLiMu);
        Srun3kDialer {
            configuration: config,
        }
    }

    pub fn encrypt_account_v20(&self, username: &str) -> Srun3kDialerResult<String> {
        let encrypted_bytes = username
            .bytes()
            .enumerate()
            .map(|(index, byte)| {
                byte.checked_add(4)
                    .ok_or(Srun3kDialerError::ByteShiftOverflow { index, byte })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let encrypted_username = String::from_utf8(encrypted_bytes)?;
        Ok(format!("{{SRUN3}}\r\n{encrypted_username}"))
    }
}

impl Dialer for Srun3kDialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        Srun3kDialer::new(Some(config))
    }
}
