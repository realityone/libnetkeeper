use std::{io, result};

use rand;
use rand::Rng;
use byteorder::{NativeEndian, ByteOrder};

use drcom::{DrCOMCommon, DrCOMResponseCommon, DrCOMValidateError};
use common::utils::current_timestamp;
use common::reader::{ReadBytesError, ReaderHelper};

#[derive(Debug)]
pub enum ChallengeResponseError {
    ValidateError(DrCOMValidateError),
    PacketReadError(ReadBytesError),
}

type PacketResult<T> = result::Result<T, ChallengeResponseError>;

#[derive(Debug)]
pub struct ChallengeRequest {
    sequence: u16,
}

#[derive(Debug)]
pub struct ChallengeResponse {
    pub hash_salt: [u8; 4],
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
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> PacketResult<Self>
        where R: io::Read
    {
        // validate packet and consume 1 byte
        try!(Self::validate_stream(input, |c| c == 0x02)
            .map_err(ChallengeResponseError::ValidateError));

        // drain unknow bytes
        try!(input.read_bytes(3).map_err(ChallengeResponseError::PacketReadError));

        let salt_bytes = try!(input.read_bytes(4).map_err(ChallengeResponseError::PacketReadError));
        let mut hash_salt = [0u8; 4];
        hash_salt.clone_from_slice(&salt_bytes);

        Ok(ChallengeResponse { hash_salt: hash_salt })
    }
}