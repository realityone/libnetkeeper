use std::{result, io};
use std::net::Ipv4Addr;

use byteorder::{NativeEndian, ByteOrder};

use drcom::{DrCOMCommon, DrCOMResponseCommon, DrCOMValidateError, PACKET_MAGIC_NUMBER, DrCOMFlag};
use common::utils::current_timestamp;
use common::reader::{ReadBytesError, ReaderHelper};
use common::bytes::BytesAbleNum;
use crypto::hash::{HasherType, HasherBuilder};

#[derive(Debug)]
pub enum HeartbeatError {
    ValidateError(DrCOMValidateError),
    ResponseLengthMismatch(u16, u16),
    PacketReadError(ReadBytesError),
}

type HeartbeatResult<T> = result::Result<T, HeartbeatError>;

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
    flag: &'a (DrCOMFlag + 'a),
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

impl DrCOMFlag for HeartbeatFlag {
    fn as_u32(&self) -> u32 {
        match *self {
            HeartbeatFlag::First => 0x122f270f,
            HeartbeatFlag::NotFirst => 0x122f02dc,
        }
    }
}

impl<'a> DrCOMCommon for PhaseTwoRequest<'a> {
    fn code() -> u8 {
        0x7u8
    }
}

impl<'a> PhaseTwoRequest<'a> {
    pub fn new<F>(sequence: u8,
                  keep_alive_key: [u8; 4],
                  flag: &'a F,
                  host_ip: Ipv4Addr,
                  type_id: Option<u8>)
                  -> Self
        where F: DrCOMFlag
    {
        PhaseTwoRequest {
            sequence: sequence,
            keep_alive_key: keep_alive_key,
            flag: flag,
            type_id: type_id.unwrap_or(1),
            host_ip: host_ip,
        }
    }

    #[inline]
    fn packet_length() -> usize {
        1 + // code
        1 + // sequence
        2 + // content length
        1 + // uid length
        Self::uid_length() +
        4 + // keep alive key
        4 + // padding?
        Self::footer_length()
    }

    #[inline]
    fn footer_length() -> usize {
        4 + // crc
        4 + // source ip
        8 // padding?
    }

    #[inline]
    fn uid_length() -> usize {
        1 + // type id
        4 + // keep alive flag
        6 // padding?
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(Self::packet_length());
        result.push(Self::code());
        result.push(self.sequence);
        result.extend((Self::packet_length() as u16).as_bytes_le());

        result.push(Self::uid_length() as u8);
        result.push(self.type_id);
        result.extend(self.flag.as_u32().as_bytes_le());
        // padding?
        result.extend_from_slice(&[0u8; 6]);
        result.extend_from_slice(&self.keep_alive_key);
        // padding?
        result.extend_from_slice(&[0u8; 4]);

        let footer_bytes = match self.type_id {
            3 => {
                let mut footer = vec![0u8; Self::footer_length()];
                footer[4..8].copy_from_slice(&self.host_ip.octets());
                footer
            }
            _ => vec![0u8; Self::footer_length()],
        };
        result.extend(footer_bytes);
        result
    }
}

impl DrCOMCommon for PhaseTwoResponse {}
impl DrCOMResponseCommon for PhaseTwoResponse {}
impl PhaseTwoResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> HeartbeatResult<Self>
        where R: io::Read
    {
        const PHASE_TWO_RESPONSE_LENGTH: u16 = 0x28;

        // validate packet and consume 1 byte
        try!(Self::validate_stream(input, |c| c == Self::code())
            .map_err(HeartbeatError::ValidateError));

        let sequence = try!(input.read_bytes(1).map_err(HeartbeatError::PacketReadError))[0];

        // validate length bytes
        {
            let length_bytes = try!(input.read_bytes(2).map_err(HeartbeatError::PacketReadError));
            let length = NativeEndian::read_u16(&length_bytes);
            if length != PHASE_TWO_RESPONSE_LENGTH {
                return Err(HeartbeatError::ResponseLengthMismatch(length,
                                                                  PHASE_TWO_RESPONSE_LENGTH));
            }
        }

        // drain unknow bytes
        try!(input.read_bytes(12).map_err(HeartbeatError::PacketReadError));

        let mut keep_alive_key = [0u8; 4];
        keep_alive_key.copy_from_slice(&try!(input.read_bytes(4).map_err(HeartbeatError::PacketReadError)));
        Ok(PhaseTwoResponse {
            sequence: sequence,
            keep_alive_key: keep_alive_key,
        })
    }
}