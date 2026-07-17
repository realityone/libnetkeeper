use std::io;
use std::net::Ipv4Addr;

use thiserror::Error;

use crate::common::error::TimeError;
use crate::common::reader::{ReadBytesError, ReaderHelper};
use crate::common::utils::resolve_timestamp;
use crate::crypto::hash::{HasherBuilder, HasherType};
use crate::drcom::{
    DrCOMCommon, DrCOMFlag, DrCOMResponseCommon, DrCOMValidateError, PACKET_MAGIC_NUMBER,
};

#[derive(Debug, Error)]
pub enum HeartbeatError {
    #[error("packet validation failed")]
    Validate(#[from] DrCOMValidateError),

    #[error("response length mismatch: expected {expected} bytes, got {actual}")]
    ResponseLengthMismatch { expected: u16, actual: u16 },

    #[error("failed to read heartbeat packet")]
    Read(#[from] ReadBytesError),

    #[error("password hash has an unexpected length: expected {expected} bytes, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },

    #[error("failed to resolve the current timestamp")]
    Time(#[from] TimeError),
}

pub type HeartbeatResult<T> = Result<T, HeartbeatError>;

#[derive(Debug)]
pub struct PhaseOneRequest {
    timestamp: u32,
    hash_salt: [u8; 4],
    password: String,
    keep_alive_key: [u8; 4],
}

#[derive(Debug)]
pub struct PhaseTwoRequest<'a> {
    sequence: u8,
    keep_alive_key: [u8; 4],
    flag: &'a (dyn DrCOMFlag + 'a),
    type_id: u8,
    host_ip: Ipv4Addr,
}

pub struct PhaseOneResponse;

#[derive(Debug)]
pub struct PhaseTwoResponse {
    pub sequence: u8,
    pub keep_alive_key: [u8; 4],
}

#[derive(Debug)]
pub enum HeartbeatFlag {
    First,
    NotFirst,
}

impl DrCOMCommon for PhaseOneRequest {
    fn code() -> u8 {
        0xff
    }
}

impl PhaseOneRequest {
    pub fn new(
        hash_salt: [u8; 4],
        password: &str,
        keep_alive_key: [u8; 4],
        timestamp: Option<u32>,
    ) -> HeartbeatResult<Self> {
        Ok(Self {
            timestamp: resolve_timestamp(timestamp)?,
            hash_salt,
            password: password.to_owned(),
            keep_alive_key,
        })
    }

    fn password_hash(&self) -> HeartbeatResult<[u8; 16]> {
        let mut md5 = HasherBuilder::build(HasherType::MD5);
        md5.update(&PACKET_MAGIC_NUMBER.to_le_bytes());
        md5.update(&self.hash_salt);
        md5.update(self.password.as_bytes());
        let hash = md5.finish();
        let hash_length = hash.len();
        hash.try_into()
            .map_err(|_| HeartbeatError::InvalidHashLength {
                expected: 16,
                actual: hash_length,
            })
    }

    pub fn as_bytes(&self) -> HeartbeatResult<Vec<u8>> {
        let mut result = Vec::with_capacity(30);
        result.push(Self::code());
        result.extend_from_slice(&self.password_hash()?);
        result.extend_from_slice(&[0; 3]);
        result.extend_from_slice(&self.keep_alive_key);
        result.extend_from_slice(&((self.timestamp % 0xffff) as u16).to_be_bytes());
        result.extend_from_slice(&[0; 4]);
        Ok(result)
    }
}

impl DrCOMCommon for PhaseOneResponse {
    fn code() -> u8 {
        0x07
    }
}

impl DrCOMResponseCommon for PhaseOneResponse {}

impl PhaseOneResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> HeartbeatResult<Self>
    where
        R: io::Read,
    {
        Self::validate_stream(input, |code| code == Self::code())?;
        Ok(Self)
    }
}

impl DrCOMFlag for HeartbeatFlag {
    fn as_u32(&self) -> u32 {
        match self {
            Self::First => 0x122f_270f,
            Self::NotFirst => 0x122f_02dc,
        }
    }
}

impl DrCOMCommon for PhaseTwoRequest<'_> {
    fn code() -> u8 {
        0x07
    }
}

impl<'a> PhaseTwoRequest<'a> {
    pub fn new<F>(
        sequence: u8,
        keep_alive_key: [u8; 4],
        flag: &'a F,
        host_ip: Ipv4Addr,
        type_id: Option<u8>,
    ) -> Self
    where
        F: DrCOMFlag,
    {
        Self {
            sequence,
            keep_alive_key,
            flag,
            type_id: type_id.unwrap_or(1),
            host_ip,
        }
    }

    const fn packet_length() -> u16 {
        1 + 1 + 2 + 1 + Self::uid_length() + 4 + 4 + Self::footer_length()
    }

    const fn footer_length() -> u16 {
        4 + 4 + 8
    }

    const fn uid_length() -> u16 {
        1 + 4 + 6
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(usize::from(Self::packet_length()));
        result.push(Self::code());
        result.push(self.sequence);
        result.extend_from_slice(&Self::packet_length().to_le_bytes());
        result.push(Self::uid_length() as u8);
        result.push(self.type_id);
        result.extend_from_slice(&self.flag.as_u32().to_le_bytes());
        result.extend_from_slice(&[0; 6]);
        result.extend_from_slice(&self.keep_alive_key);
        result.extend_from_slice(&[0; 4]);
        result.extend_from_slice(&[0; 4]);
        if self.type_id == 3 {
            result.extend_from_slice(&self.host_ip.octets());
        } else {
            result.extend_from_slice(&[0; 4]);
        }
        result.extend_from_slice(&[0; 8]);
        result
    }
}

impl DrCOMCommon for PhaseTwoResponse {}

impl DrCOMResponseCommon for PhaseTwoResponse {}

impl PhaseTwoResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> HeartbeatResult<Self>
    where
        R: io::Read,
    {
        const EXPECTED_LENGTH: u16 = 0x28;

        Self::validate_stream(input, |code| code == Self::code())?;
        let sequence = input.read_byte()?;
        let length = u16::from_le_bytes(input.read_exact_array()?);
        if length != EXPECTED_LENGTH {
            return Err(HeartbeatError::ResponseLengthMismatch {
                expected: EXPECTED_LENGTH,
                actual: length,
            });
        }
        input.read_bytes(12)?;
        let keep_alive_key = input.read_exact_array()?;
        Ok(Self {
            sequence,
            keep_alive_key,
        })
    }
}
