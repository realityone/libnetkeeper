use std::{marker, io};
use std::net::Ipv4Addr;

use byteorder::{NativeEndian, NetworkEndian, ByteOrder};

use crypto::hash::{HasherBuilder, Hasher, HasherType};
use common::reader::{ReadBytesError, ReaderHelper};
use common::drcom::{DrCOMCommon, DrCOMResponseCommon};

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

trait CRCHasher {
    fn hasher(&self) -> Box<Hasher>;
    fn retain_postions(&self) -> Vec<usize>;

    fn hash(&self, bytes: &[u8]) -> Vec<u8> {
        let mut hasher = self.hasher();
        let retain_postions = self.retain_postions();

        hasher.update(bytes);
        let hashed_bytes = hasher.finish();

        let mut hashed = Vec::<u8>::with_capacity(retain_postions.len());
        for i in retain_postions {
            if i > hashed_bytes.len() {
                continue;
            }
            hashed.push(hashed_bytes[i]);
        }
        hashed
    }
}

trait CRCHasherBuilder {
    fn from_mode(mode: u8) -> Result<Self, CRCHashError> where Self: marker::Sized;
}

struct NoneHasher;
impl Hasher for NoneHasher {
    #[allow(unused_variables)]
    fn update(&mut self, bytes: &[u8]) {}
    fn finish(&mut self) -> Vec<u8> {
        const DRCOM_DIAL_EXT_PROTO_CRC_INIT: u32 = 20000711;
        let mut result = vec![0u8; 8];
        NativeEndian::write_u32(result.as_mut_slice(), DRCOM_DIAL_EXT_PROTO_CRC_INIT);
        NativeEndian::write_u32(&mut result.as_mut_slice()[4..], 126);
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

    fn retain_postions(&self) -> Vec<usize> {
        match *self {
            CRCHasherType::NONE => vec![0, 1, 2, 3, 4, 5, 6, 7],
            CRCHasherType::MD5 => vec![2, 3, 8, 9, 5, 6, 13, 14],
            CRCHasherType::MD4 => vec![1, 2, 8, 9, 4, 5, 11, 12],
            CRCHasherType::SHA1 => vec![2, 3, 9, 10, 5, 6, 15, 16],
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

#[derive(Debug)]
pub struct ChallengeRequest {
    count: u8,
}

#[derive(Debug)]
pub struct ChallengeResponse {
    pub challenge_seed: u32,
    pub source_ip: Ipv4Addr,
}

impl DrCOMCommon for ChallengeRequest {}
impl DrCOMResponseCommon for ChallengeResponse {}

impl ChallengeRequest {
    pub fn new(count: Option<u8>) -> Self {
        let count = match count {
            Some(c) => c,
            None => 1u8,
        };
        ChallengeRequest { count: count }
    }

    fn magic_number() -> u32 {
        65544u32
    }

    pub fn as_bytes(&self) -> [u8; 8] {
        let mut result = [0u8; 8];
        result[0] = Self::code();
        result[1] = self.count;
        NativeEndian::write_u32(&mut result[2..], Self::magic_number());
        result
    }
}

impl ChallengeResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> Result<Self, ReadBytesError>
        where R: io::Read
    {
        // validate packet and consume 1 byte
        try!(Self::validate_packet(input));
        // drain unknow bytes
        try!(input.read_bytes(7));

        let challenge_seed;
        {
            let challenge_seed_bytes = try!(input.read_bytes(4));
            challenge_seed = NativeEndian::read_u32(&challenge_seed_bytes);
        }

        let source_ip;
        {
            let source_ip_bytes = try!(input.read_bytes(4));
            source_ip = Ipv4Addr::from(NetworkEndian::read_u32(&source_ip_bytes));
        }

        Ok(ChallengeResponse {
            challenge_seed: challenge_seed,
            source_ip: source_ip,
        })
    }
}

fn generate_crc_hash(bytes: &[u8], mode: u8) -> Result<Vec<u8>, CRCHashError> {
    let crc_hasher = try!(CRCHasherType::from_mode(mode));
    Ok(crc_hasher.hash(bytes))
}

fn calculate_drcom_crc32(bytes: &[u8], initial: Option<u32>) -> Result<u32, CRCHashError> {
    if bytes.len() % 4 != 0 {
        return Err(CRCHashError::InputLengthInvalid);
    }

    let mut result = match initial {
        Some(initial) => initial,
        None => 0,
    };
    for c in 0..(bytes.len() / 4usize) {
        result ^= NativeEndian::read_u32(&bytes[c * 4..c * 4 + 4]);
    }
    Ok(result)
}

#[test]
fn test_generate_crc_hash() {
    let crc_hash_none = generate_crc_hash(b"1234567890", 0).unwrap();
    let crc_hash_md5 = generate_crc_hash(b"1234567890", 1).unwrap();
    let crc_hash_md4 = generate_crc_hash(b"1234567890", 2).unwrap();
    let crc_hash_sha1 = generate_crc_hash(b"1234567890", 3).unwrap();
    assert_eq!(crc_hash_md5, vec![241, 252, 155, 176, 45, 19, 56, 161]);
    assert_eq!(crc_hash_sha1, vec![7, 172, 175, 195, 79, 84, 246, 202]);
    assert_eq!(crc_hash_none, vec![199, 47, 49, 1, 126, 0, 0, 0]);
    assert_eq!(crc_hash_md4, vec![177, 150, 28, 171, 227, 148, 144, 95]);
}

#[test]
fn test_calculate_drcom_crc32() {
    let crc32 = calculate_drcom_crc32(b"1234567899999999", None).unwrap();
    assert_eq!(crc32, 201589764);
}
