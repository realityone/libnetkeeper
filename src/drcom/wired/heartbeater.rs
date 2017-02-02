use std::{result, io};

use drcom::{DrCOMCommon, DrCOMResponseCommon, DrCOMValidateError, PACKET_MAGIC_NUMBER};
use common::utils::current_timestamp;
// use common::reader::{ReadBytesError, ReaderHelper};
use common::bytes::BytesAbleNum;
use crypto::hash::{HasherType, HasherBuilder};

#[derive(Debug)]
pub enum HeartbeatError {
    ValidateError(DrCOMValidateError),
}

type HeartbeatResult<T> = result::Result<T, HeartbeatError>;

#[derive(Debug)]
pub struct PhaseOneRequest {
    timestamp: u32,
    hash_salt: [u8; 4],
    password: String,
    keep_alive_key: [u8; 4],
}

pub struct PhaseOneResponse;

impl DrCOMCommon for PhaseOneRequest {
    fn code() -> u8 {
        0xffu8
    }
}

impl PhaseOneRequest {
    pub fn new(hash_salt: [u8; 4],
               password: &str,
               keep_alive_key: [u8; 4],
               timestamp: Option<u32>)
               -> Self {
        PhaseOneRequest {
            timestamp: timestamp.unwrap_or_else(current_timestamp),
            hash_salt: hash_salt,
            password: password.to_string(),
            keep_alive_key: keep_alive_key,
        }
    }

    fn packet_length() -> usize {
        1 + // code
        16 + // password hash
        3 + // padding?
        4 + // key bytes
        2 + // timestamp hash
        4 // padding?
    }

    fn password_hash(&self) -> [u8; 16] {
        let mut md5 = HasherBuilder::build(HasherType::MD5);
        md5.update(&PACKET_MAGIC_NUMBER.as_bytes_le());
        md5.update(&self.hash_salt);
        md5.update(self.password.as_bytes());

        let mut md5_digest = [0u8; 16];
        md5_digest.copy_from_slice(&md5.finish());
        md5_digest
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(Self::packet_length());
        result.push(Self::code());
        result.extend_from_slice(&self.password_hash());
        // padding?
        result.extend_from_slice(&[0u8; 3]);
        result.extend_from_slice(&self.keep_alive_key);
        result.extend(((self.timestamp % 0xFFFF) as u16).as_bytes_be());
        // padding?
        result.extend_from_slice(&[0u8; 4]);
        result
    }
}

impl DrCOMCommon for PhaseOneResponse {
    fn code() -> u8 {
        0x07u8
    }
}
impl DrCOMResponseCommon for PhaseOneResponse {}
impl PhaseOneResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> HeartbeatResult<Self>
        where R: io::Read
    {
        // validate packet and consume 1 byte
        try!(Self::validate_stream(input, |c| c == Self::code())
            .map_err(HeartbeatError::ValidateError));
        Ok(PhaseOneResponse {})
    }
}