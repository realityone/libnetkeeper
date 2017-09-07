use std::{marker, io, result};
use std::net::Ipv4Addr;
use std::num::Wrapping;

use byteorder::{NativeEndian, NetworkEndian, ByteOrder};

use crypto::hash::{HasherBuilder, Hasher, HasherType};
use common::reader::{ReadBytesError, ReaderHelper};
use common::bytes::BytesAbleNum;
use drcom::{DrCOMCommon, DrCOMResponseCommon, DrCOMValidateError, DrCOMFlag};

#[derive(Debug)]
pub enum DrCOMHeartbeatError {
    ValidateError(DrCOMValidateError),
    CRCHashError(CRCHashError),
    PacketReadError(ReadBytesError),
    UnexpectedBytes(Vec<u8>),
}

type PacketResult<T> = result::Result<T, DrCOMHeartbeatError>;

#[derive(Debug)]
pub enum HeartbeatFlag {
    First,
    NotFirst,
}

#[derive(Debug)]
pub enum KeepAliveRequestFlag {
    First,
    NotFirst,
}

#[derive(Debug, PartialEq)]
pub enum KeepAliveResponseType {
    KeepAliveSucceed,
    FileResponse,
    UnrecognizedResponse,
}

#[derive(Debug)]
pub enum CRCHasherType {
    NONE,
    MD5,
    MD4,
    SHA1,
}

#[derive(Debug)]
pub enum CRCHashError {
    ModeNotExist,
    InputLengthInvalid,
}

struct NoneHasher;

#[derive(Debug)]
pub struct ChallengeRequest {
    sequence: u8,
}

#[derive(Debug)]
pub struct ChallengeResponse {
    pub challenge_seed: u32,
    pub source_ip: Ipv4Addr,
}

#[derive(Debug)]
pub struct HeartbeatRequest<'a> {
    sequence: u8,
    type_id: u8,
    uid_length: u8,
    mac_address: [u8; 6],
    source_ip: Ipv4Addr,
    flag: &'a (DrCOMFlag + 'a),
    challenge_seed: u32,
}

#[derive(Debug)]
pub struct KeepAliveRequest<'a> {
    sequence: u8,
    type_id: u8,
    source_ip: Ipv4Addr,
    flag: &'a (DrCOMFlag + 'a),
    keep_alive_seed: u32,
}

#[derive(Debug)]
pub struct KeepAliveResponse {
    pub response_type: KeepAliveResponseType,
}

trait CRCHasher {
    fn hasher(&self) -> Box<Hasher>;
    fn retain_postions(&self) -> [usize; 8];

    fn hash(&self, bytes: &[u8]) -> [u8; 8] {
        let mut hasher = self.hasher();
        let retain_postions = self.retain_postions();

        hasher.update(bytes);
        let hashed_bytes = hasher.finish();

        let mut hashed = Vec::<u8>::with_capacity(retain_postions.len());
        for i in &retain_postions {
            if *i > hashed_bytes.len() {
                continue;
            }
            hashed.push(hashed_bytes[*i]);
        }

        let mut result = [0u8; 8];
        result.clone_from_slice(hashed.as_slice());
        result
    }
}

trait CRCHasherBuilder {
    fn from_mode(mode: u8) -> Result<Self, CRCHashError> where Self: marker::Sized;
}

impl Hasher for NoneHasher {
    #[allow(unused_variables)]
    fn update(&mut self, bytes: &[u8]) {}
    fn finish(&mut self) -> Vec<u8> {
        const DRCOM_DIAL_EXT_PROTO_CRC_INIT: u32 = 20000711;
        const UNKNOW_MAGIC_NUMBER: u32 = 126;

        let mut result = Vec::with_capacity(8);
        result.extend(DRCOM_DIAL_EXT_PROTO_CRC_INIT.as_bytes_le());
        result.extend(UNKNOW_MAGIC_NUMBER.as_bytes_le());

        result
    }
}

impl CRCHasher for CRCHasherType {
    fn hasher(&self) -> Box<Hasher> {
        match *self {
            CRCHasherType::NONE => Box::new(NoneHasher {}) as Box<Hasher>,
            CRCHasherType::MD5 => HasherBuilder::build(HasherType::MD5),
            CRCHasherType::MD4 => HasherBuilder::build(HasherType::MD4),
            CRCHasherType::SHA1 => HasherBuilder::build(HasherType::SHA1),
        }
    }

    fn retain_postions(&self) -> [usize; 8] {
        match *self {
            CRCHasherType::NONE => [0, 1, 2, 3, 4, 5, 6, 7],
            CRCHasherType::MD5 => [2, 3, 8, 9, 5, 6, 13, 14],
            CRCHasherType::MD4 => [1, 2, 8, 9, 4, 5, 11, 12],
            CRCHasherType::SHA1 => [2, 3, 9, 10, 5, 6, 15, 16],
        }
    }
}

impl CRCHasherBuilder for CRCHasherType {
    fn from_mode(mode: u8) -> Result<Self, CRCHashError>
        where Self: marker::Sized
    {
        match mode {
            0 => Ok(CRCHasherType::NONE),
            1 => Ok(CRCHasherType::MD5),
            2 => Ok(CRCHasherType::MD4),
            3 => Ok(CRCHasherType::SHA1),

            _ => Err(CRCHashError::ModeNotExist),
        }
    }
}

impl DrCOMCommon for ChallengeRequest {}

impl DrCOMResponseCommon for ChallengeResponse {}

impl ChallengeRequest {
    pub fn new(sequence: Option<u8>) -> Self {
        ChallengeRequest { sequence: sequence.unwrap_or(1u8) }
    }

    #[inline]
    fn magic_number() -> u32 {
        65544u32
    }

    #[inline]
    fn header_length() -> usize {
        1 + // code
            1 // sequence
    }

    #[inline]
    fn packet_length() -> usize {
        Self::header_length() +
            4 + // magic number
            2 // padding?
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = vec![0u8; Self::packet_length()];

        result[0] = Self::code();
        result[1] = self.sequence;
        Self::magic_number().write_bytes_le(&mut result[2..6]);

        result
    }
}

impl ChallengeResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> PacketResult<Self>
        where R: io::Read
    {
        // validate packet and consume 1 byte
        try!(Self::validate_stream(input, |c| c != 0x4d)
            .map_err(DrCOMHeartbeatError::ValidateError));
        // drain unknow bytes
        try!(input.read_bytes(7).map_err(DrCOMHeartbeatError::PacketReadError));

        let challenge_seed;
        {
            let challenge_seed_bytes = try!(input.read_bytes(4)
                .map_err(DrCOMHeartbeatError::PacketReadError));
            challenge_seed = NativeEndian::read_u32(&challenge_seed_bytes);
        }

        let source_ip;
        {
            let source_ip_bytes = try!(input.read_bytes(4)
                .map_err(DrCOMHeartbeatError::PacketReadError));
            source_ip = Ipv4Addr::from(NetworkEndian::read_u32(&source_ip_bytes));
        }

        Ok(ChallengeResponse {
            challenge_seed: challenge_seed,
            source_ip: source_ip,
        })
    }
}

impl DrCOMFlag for HeartbeatFlag {
    fn as_u32(&self) -> u32 {
        match *self {
            HeartbeatFlag::First => 0x2a006200u32,
            HeartbeatFlag::NotFirst => 0x2a006300u32,
        }
    }
}

impl DrCOMFlag for KeepAliveRequestFlag {
    fn as_u32(&self) -> u32 {
        match *self {
            KeepAliveRequestFlag::First => 0x122f270fu32,
            KeepAliveRequestFlag::NotFirst => 0x122f02dcu32,
        }
    }
}

impl<'a> DrCOMCommon for HeartbeatRequest<'a> {}

impl<'a> HeartbeatRequest<'a> {
    pub fn new<F>(sequence: u8,
                  source_ip: Ipv4Addr,
                  flag: &'a F,
                  challenge_seed: u32,
                  type_id: Option<u8>,
                  uid_length: Option<u8>,
                  mac_address: Option<[u8; 6]>)
                  -> Self
        where F: DrCOMFlag
    {
        HeartbeatRequest {
            sequence: sequence,
            type_id: type_id.unwrap_or(3u8),
            uid_length: uid_length.unwrap_or(0u8),
            mac_address: mac_address.unwrap_or([0u8; 6]),
            source_ip: source_ip,
            flag: flag,
            challenge_seed: challenge_seed,
        }
    }

    #[inline]
    fn header_length() -> usize {
        1 + // code 
            1 + // sequence
            2 // packet_length
    }

    #[inline]
    fn content_length() -> usize {
        1 + // type_id
            1 + // uid_length
            6 + // mac_address
            4 + // source_ip
            4 + // pppoe_flag
            4 // challenge_seed
    }

    #[inline]
    fn footer_length() -> usize {
        8 + // crc_hash
            16 * 4 // padding?
    }

    #[inline]
    fn packet_length() -> usize {
        Self::header_length() + Self::content_length() + Self::footer_length()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut header_bytes = Vec::with_capacity(Self::header_length());
        {
            header_bytes.push(Self::code());
            header_bytes.push(self.sequence);
            header_bytes.extend((Self::packet_length() as u16).as_bytes_le());
        }

        let challenge_seed_bytes = self.challenge_seed.as_bytes_le();
        let mut content_bytes = Vec::with_capacity(Self::content_length());
        {
            content_bytes.push(self.type_id);
            content_bytes.push(self.uid_length);
            content_bytes.extend_from_slice(&self.mac_address);
            content_bytes.extend_from_slice(&self.source_ip.octets());

            let flag_bytes = self.flag.as_u32().as_bytes_le();
            content_bytes.extend_from_slice(&flag_bytes);
            content_bytes.extend(&challenge_seed_bytes);
        }

        let mut footer_bytes = Vec::with_capacity(Self::footer_length());
        {
            let hash_mode = CRCHasherType::from_mode((self.challenge_seed % 3) as u8).unwrap();
            let crc_hash_bytes = hash_mode.hash(&challenge_seed_bytes);
            footer_bytes.extend_from_slice(&crc_hash_bytes);

            if let CRCHasherType::NONE = hash_mode {
                let mut rehash_bytes: Vec<u8> = Vec::with_capacity(Self::packet_length());
                rehash_bytes.extend(&header_bytes);
                rehash_bytes.extend(&content_bytes);
                rehash_bytes.extend(&footer_bytes);
                let rehash = Wrapping(calculate_drcom_crc32(&rehash_bytes, None).unwrap()) *
                    Wrapping(19680126);

                rehash.0.write_bytes_le(&mut footer_bytes[0..4]);
                0u32.write_bytes_le(&mut footer_bytes[4..8]);
            }
            // padding?
            footer_bytes.extend_from_slice(&[0u8; 16 * 4]);
        }

        let mut packet_bytes = Vec::with_capacity(Self::packet_length());
        packet_bytes.extend(header_bytes);
        packet_bytes.extend(content_bytes);
        packet_bytes.extend(footer_bytes);
        packet_bytes
    }
}

impl<'a> DrCOMCommon for KeepAliveRequest<'a> {}

impl<'a> KeepAliveRequest<'a> {
    pub fn new<F>(sequence: u8,
                  flag: &'a F,
                  type_id: Option<u8>,
                  source_ip: Option<Ipv4Addr>,
                  keep_alive_seed: Option<u32>)
                  -> Self
        where F: DrCOMFlag
    {
        let type_id = type_id.unwrap_or(1u8);
        let source_ip = source_ip.unwrap_or_else(|| Ipv4Addr::from(0x0));
        let keep_alive_seed = keep_alive_seed.unwrap_or_default();
        KeepAliveRequest {
            sequence: sequence,
            type_id: type_id,
            source_ip: source_ip,
            flag: flag,
            keep_alive_seed: keep_alive_seed,
        }
    }

    #[inline]
    fn packet_length() -> usize {
        1 + // code
            1 + // sequence
            2 + // packet length
            1 + // uid length
            Self::uid_length() +
            4 + // keep alive seed
            Self::footer_length()
    }

    #[inline]
    fn uid_length() -> usize {
        1 + // type id
            4 + // keep alive flag
            6 // padding?
    }

    #[inline]
    fn footer_length() -> usize {
        8 + // crc
            4 + // source ip
            8 // padding?
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut packet_bytes = Vec::with_capacity(Self::packet_length());

        packet_bytes.push(Self::code());
        packet_bytes.push(self.sequence);
        packet_bytes.extend((Self::packet_length() as u16).as_bytes_le());
        packet_bytes.push(Self::uid_length() as u8);
        packet_bytes.push(self.type_id);
        packet_bytes.extend(self.flag.as_u32().as_bytes_le());

        // padding?
        packet_bytes.extend_from_slice(&[0u8; 6]);

        packet_bytes.extend(self.keep_alive_seed.as_bytes_le());

        let footer_bytes = match self.type_id {
            3 => {
                let mut result = Vec::with_capacity(Self::footer_length());
                let hash_mode = CRCHasherType::from_mode((self.keep_alive_seed & 3) as u8).unwrap();
                let crc_hash_bytes = hash_mode.hash(&packet_bytes);
                result.extend_from_slice(&crc_hash_bytes);

                result.extend_from_slice(&self.source_ip.octets());
                result.extend_from_slice(&[0u8; 8]);
                result
            }
            _ => vec![0u8; Self::footer_length()],
        };
        packet_bytes.extend(footer_bytes);

        packet_bytes
    }
}

impl DrCOMResponseCommon for KeepAliveResponse {}

impl KeepAliveResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> PacketResult<Self>
        where R: io::Read
    {
        // validate packet and consume 1 byte
        try!(Self::validate_stream(input, |c| c != 0x4d)
            .map_err(DrCOMHeartbeatError::ValidateError));
        // drain unknow bytes
        try!(input.read_bytes(1).map_err(DrCOMHeartbeatError::PacketReadError));

        let type_flag_byte;
        {
            type_flag_byte = try!(input.read_bytes(1)
                .map_err(DrCOMHeartbeatError::PacketReadError))[0];
        }

        let response_type = match type_flag_byte {
            0x28 => KeepAliveResponseType::KeepAliveSucceed,
            0x10 => KeepAliveResponseType::FileResponse,
            _ => KeepAliveResponseType::UnrecognizedResponse,
        };

        Ok(KeepAliveResponse { response_type: response_type })
    }
}


fn calculate_drcom_crc32(bytes: &[u8], initial: Option<u32>) -> Result<u32, CRCHashError> {
    if bytes.len() % 4 != 0 {
        return Err(CRCHashError::InputLengthInvalid);
    }

    let mut result = initial.unwrap_or(0u32);
    for c in 0..(bytes.len() / 4usize) {
        result ^= NativeEndian::read_u32(&bytes[c * 4..c * 4 + 4]);
    }
    Ok(result)
}

#[test]
fn test_generate_crc_hash() {
    let crc_hash_none = CRCHasherType::NONE.hash(b"1234567890");
    let crc_hash_md5 = CRCHasherType::MD5.hash(b"1234567890");
    let crc_hash_md4 = CRCHasherType::MD4.hash(b"1234567890");
    let crc_hash_sha1 = CRCHasherType::SHA1.hash(b"1234567890");
    assert_eq!(crc_hash_md5, [241, 252, 155, 176, 45, 19, 56, 161]);
    assert_eq!(crc_hash_sha1, [7, 172, 175, 195, 79, 84, 246, 202]);
    assert_eq!(crc_hash_none, [199, 47, 49, 1, 126, 0, 0, 0]);
    assert_eq!(crc_hash_md4, [177, 150, 28, 171, 227, 148, 144, 95]);
}

#[test]
fn test_calculate_drcom_crc32() {
    let crc32 = calculate_drcom_crc32(b"1234567899999999", None).unwrap();
    assert_eq!(crc32, 201589764);
}
