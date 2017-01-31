use std::{io, result};
use std::net::Ipv4Addr;

use rand;
use rand::Rng;
use byteorder::{NativeEndian, ByteOrder};

use drcom::{DrCOMCommon, DrCOMResponseCommon, DrCOMValidateError};
use common::utils::current_timestamp;
use common::reader::{ReadBytesError, ReaderHelper};

#[derive(Debug)]
pub enum LoginError {
    ValidateError(DrCOMValidateError),
    PacketReadError(ReadBytesError),
    // max_len {}, got {}
    DataOverflow(usize, usize),
}

type LoginResult<T> = result::Result<T, LoginError>;

#[derive(Debug)]
pub struct ChallengeRequest {
    sequence: u16,
}

#[derive(Debug)]
pub struct ChallengeResponse {
    pub hash_salt: [u8; 4],
}

#[derive(Debug)]
pub struct TagOSVersionInfo {
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    service_pack: String,
}

impl DrCOMCommon for ChallengeRequest {
    fn code() -> u8 {
        1u8
    }
}

impl ChallengeRequest {
    pub fn new(sequence: Option<u16>) -> Self {
        ChallengeRequest {
            sequence: sequence.unwrap_or_else(|| {
                current_timestamp() as u16 + rand::thread_rng().gen_range(0xF, 0xFF)
            }),
        }
    }

    fn magic_number() -> u32 {
        9u32
    }

    fn packet_length() -> usize {
        1 + // code 
        1 + // sequence size
        2 + // sequence
        4 + // magic number
        12 // padding?
    }

    fn sequence_length() -> usize {
        2
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = vec![0u8; Self::packet_length()];

        result[0] = Self::code();
        result[1] = Self::sequence_length() as u8;

        NativeEndian::write_u16(&mut result[2..], self.sequence);
        NativeEndian::write_u32(&mut result[4..], Self::magic_number());
        result
    }
}

impl DrCOMResponseCommon for ChallengeResponse {}
impl ChallengeResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> LoginResult<Self>
        where R: io::Read
    {
        // validate packet and consume 1 byte
        try!(Self::validate_stream(input, |c| c == 0x02).map_err(LoginError::ValidateError));

        // drain unknow bytes
        try!(input.read_bytes(3).map_err(LoginError::PacketReadError));

        let salt_bytes = try!(input.read_bytes(4).map_err(LoginError::PacketReadError));
        let mut hash_salt = [0u8; 4];
        hash_salt.clone_from_slice(&salt_bytes);

        Ok(ChallengeResponse { hash_salt: hash_salt })
    }
}

impl TagOSVersionInfo {
    pub fn new(major_version: Option<u32>,
               minor_version: Option<u32>,
               build_number: Option<u32>,
               platform_id: Option<u32>,
               service_pack: Option<&str>)
               -> Self {
        let major_version = major_version.unwrap_or(0x05);
        let minor_version = minor_version.unwrap_or(0x01);
        let build_number = build_number.unwrap_or(0x0a28);
        let platform_id = platform_id.unwrap_or(0x02);
        let service_pack = service_pack.unwrap_or("8089D").to_string();
        TagOSVersionInfo {
            major_version: major_version,
            minor_version: minor_version,
            build_number: build_number,
            platform_id: platform_id,
            service_pack: service_pack,
        }
    }

    fn validate(&self) -> LoginResult<()> {
        const SERVICE_PACK_MAX_LEN: usize = 32;
        if self.service_pack.len() > SERVICE_PACK_MAX_LEN {
            return Err(LoginError::DataOverflow(self.service_pack.len(), SERVICE_PACK_MAX_LEN));
        }
        Ok(())
    }

    fn packet_length() -> usize {
        4 + // packet_length
        4 + // major_version
        4 + // minor_version
        4 + // build_number
        4 + // platform_id
        128 // service_pack
    }

    fn content_length() -> usize {
        4 + // major_version
        4 + // minor_version
        4 + // build_number
        4 + // platform_id
        128 // service_pack
    }

    pub fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut content_bytes = vec![0u8; Self::content_length()];
        {
            NativeEndian::write_u32(&mut content_bytes[0..4], self.major_version);
            NativeEndian::write_u32(&mut content_bytes[4..8], self.minor_version);
            NativeEndian::write_u32(&mut content_bytes[8..12], self.build_number);
            NativeEndian::write_u32(&mut content_bytes[12..16], self.platform_id);
            content_bytes[16..16 + self.service_pack.len()]
                .copy_from_slice(self.service_pack.as_bytes());
        }

        let mut header_bytes = [0u8; 4];
        NativeEndian::write_u32(&mut header_bytes, Self::packet_length() as u32);

        let mut result = Vec::with_capacity(Self::packet_length());
        result.extend_from_slice(&header_bytes);
        result.extend(content_bytes);

        Ok(result)
    }
}

impl Default for TagOSVersionInfo {
    fn default() -> Self {
        TagOSVersionInfo::new(None, None, None, None, None)
    }
}