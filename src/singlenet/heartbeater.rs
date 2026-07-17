use std::io;
use std::net::Ipv4Addr;

use thiserror::Error;

use crate::common::error::TimeError;
use crate::common::reader::{ReadBytesError, ReaderHelper};
use crate::common::utils::resolve_timestamp;
use crate::crypto::hash::{HasherBuilder, HasherType};
use crate::singlenet::attributes::{
    Attribute, AttributeType, AttributeVec, KeepaliveDataCalculator, ParseAttributesError,
};

#[derive(Debug, Error)]
pub enum SinglenetHeartbeatError {
    #[error("failed to read packet data")]
    Read(#[from] ReadBytesError),

    #[error("failed to parse packet attributes")]
    Attributes(#[from] ParseAttributesError),

    #[error("unexpected packet magic: expected {expected:#06x}, got {actual:#06x}")]
    InvalidMagic { expected: u16, actual: u16 },

    #[error("unsupported packet code {code:#04x}")]
    InvalidCode { code: u8 },

    #[error("invalid packet length {actual}: minimum is {minimum}")]
    InvalidPacketLength { minimum: u16, actual: u16 },

    #[error("packet is too long: maximum {max} bytes, got {actual}")]
    PacketTooLong { max: usize, actual: usize },

    #[error("authenticator hash has an unexpected length: expected {expected} bytes, got {actual}")]
    InvalidAuthenticatorLength { expected: usize, actual: usize },

    #[error("failed to resolve the current timestamp")]
    Time(#[from] TimeError),
}

pub type PacketResult<T> = Result<T, SinglenetHeartbeatError>;

#[derive(Debug, Copy, Clone)]
pub enum PacketCode {
    CRegisterRequest = 0x1,
    CRegisterResponse = 0x2,
    CKeepAliveRequest = 0x3,
    CKeepAliveResponse = 0x4,
    CBubbleRequest = 0x5,
    CBubbleResponse = 0x6,
    CChannelRequest = 0x7,
    CChannelResponse = 0x8,
    CPluginRequest = 0x9,
    CPluginResponse = 0xa,
    CRealTimeBubbleRequest = 0xb,
    CRealTimeBubbleResponse = 0xc,
}

#[derive(Debug)]
pub struct Packet {
    magic_number: u16,
    length: u16,
    code: PacketCode,
    seq: u8,
    authorization: [u8; 16],
    attributes: Vec<Attribute>,
}

pub struct PacketAuthenticator {
    salt: String,
}

pub struct PacketFactoryMac;

pub struct PacketFactoryWin;

impl PacketAuthenticator {
    pub fn new(salt: &str) -> Self {
        Self {
            salt: salt.to_owned(),
        }
    }

    pub fn authenticate(&self, bytes: &[u8]) -> PacketResult<[u8; 16]> {
        let mut md5 = HasherBuilder::build(HasherType::MD5);
        md5.update(bytes);
        md5.update(self.salt.as_bytes());
        let hash = md5.finish();
        let hash_length = hash.len();
        hash.try_into()
            .map_err(|_| SinglenetHeartbeatError::InvalidAuthenticatorLength {
                expected: 16,
                actual: hash_length,
            })
    }
}

impl Packet {
    const MAGIC_NUMBER: u16 = 0x534e;
    const HEADER_LENGTH: u16 = 22;

    pub fn new(
        code: PacketCode,
        seq: u8,
        authorization: Option<[u8; 16]>,
        attributes: Vec<Attribute>,
    ) -> PacketResult<Self> {
        let length = Self::calculate_length(&attributes)?;
        Ok(Self {
            magic_number: Self::MAGIC_NUMBER,
            length,
            code,
            seq,
            authorization: authorization.unwrap_or_default(),
            attributes,
        })
    }

    fn calculate_length(attributes: &Vec<Attribute>) -> PacketResult<u16> {
        let attributes_length = usize::from(attributes.length()?);
        let length = usize::from(Self::HEADER_LENGTH)
            .checked_add(attributes_length)
            .ok_or(SinglenetHeartbeatError::PacketTooLong {
                max: usize::from(u16::MAX),
                actual: usize::MAX,
            })?;
        u16::try_from(length).map_err(|_| SinglenetHeartbeatError::PacketTooLong {
            max: usize::from(u16::MAX),
            actual: length,
        })
    }

    pub fn as_bytes(&self, authenticator: Option<&PacketAuthenticator>) -> PacketResult<Vec<u8>> {
        let authorization = match authenticator {
            Some(authenticator) => authenticator.authenticate(&self.as_bytes(None)?)?,
            None => self.authorization,
        };
        let attributes_bytes = self.attributes.as_bytes()?;
        let mut bytes = Vec::with_capacity(usize::from(self.length));
        bytes.extend_from_slice(&self.magic_number.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.push(self.code as u8);
        bytes.push(self.seq);
        bytes.extend_from_slice(&authorization);
        bytes.extend_from_slice(&attributes_bytes);
        Ok(bytes)
    }

    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> PacketResult<Self>
    where
        R: io::Read,
    {
        let magic_number = u16::from_be_bytes(input.read_exact_array()?);
        if magic_number != Self::MAGIC_NUMBER {
            return Err(SinglenetHeartbeatError::InvalidMagic {
                expected: Self::MAGIC_NUMBER,
                actual: magic_number,
            });
        }

        let length = u16::from_be_bytes(input.read_exact_array()?);
        if length < Self::HEADER_LENGTH {
            return Err(SinglenetHeartbeatError::InvalidPacketLength {
                minimum: Self::HEADER_LENGTH,
                actual: length,
            });
        }
        let raw_code = input.read_byte()?;
        let code = PacketCode::from_u8(raw_code)
            .ok_or(SinglenetHeartbeatError::InvalidCode { code: raw_code })?;
        let seq = input.read_byte()?;
        let authorization = input.read_exact_array()?;
        let attributes_length = usize::from(length - Self::HEADER_LENGTH);
        let attributes = Vec::<Attribute>::from_bytes(&input.read_bytes(attributes_length)?)?;

        Self::new(code, seq, Some(authorization), attributes)
    }
}

impl PacketFactoryWin {
    fn calc_seq(timestamp: Option<u32>) -> PacketResult<u8> {
        let timestamp = resolve_timestamp(timestamp)?;
        let tmp_num = (u64::from(timestamp) * 0x3_43fd) + 0x26_9ec3;
        Ok(((tmp_num >> 0x10) & 0xff) as u8)
    }

    pub fn keepalive_request(
        username: &str,
        ipaddress: Ipv4Addr,
        timestamp: Option<u32>,
        last_keepalive_data: Option<&str>,
        version: Option<&str>,
    ) -> PacketResult<Packet> {
        let version = version.unwrap_or("1.2.22.36");
        let timestamp = resolve_timestamp(timestamp)?;
        let keepalive_data =
            KeepaliveDataCalculator::calculate(Some(timestamp), last_keepalive_data)?;

        let attributes = vec![
            Attribute::from_type(AttributeType::TClientIPAddress, &ipaddress),
            Attribute::from_type(AttributeType::TClientVersion, &version.to_owned()),
            Attribute::from_type(AttributeType::TKeepAliveData, &keepalive_data),
            Attribute::from_type(AttributeType::TKeepAliveTime, &timestamp),
            Attribute::from_type(AttributeType::TUserName, &username.to_owned()),
        ];

        Packet::new(
            PacketCode::CKeepAliveRequest,
            Self::calc_seq(Some(timestamp))?,
            None,
            attributes,
        )
    }
}

impl PacketFactoryMac {
    const SEQUENCE: u8 = 1;

    fn client_type() -> String {
        "Mac-SingletNet".to_owned()
    }

    pub fn register_request(
        username: &str,
        ipaddress: Ipv4Addr,
        version: Option<&str>,
        mac_address: Option<&str>,
        explorer: Option<&str>,
    ) -> PacketResult<Packet> {
        let version = version.unwrap_or("1.1.0");
        let mac_address = mac_address.unwrap_or("10:dd:b1:d5:95:ca");
        let explorer = explorer.unwrap_or_default();
        let client_type = Self::client_type();
        let cpu_info = "Intel(R) Core(TM) i5-5287U CPU @ 2.90GHz";
        let memory_size = 0x2000u32;
        let os_version = "Mac OS X Version 10.12 (Build 16A323)";
        let os_language = "zh_CN";

        let attributes = vec![
            Attribute::from_type(AttributeType::TUserName, &username.to_owned()),
            Attribute::from_type(AttributeType::TClientVersion, &version.to_owned()),
            Attribute::from_type(AttributeType::TClientType, &client_type),
            Attribute::from_type(AttributeType::TClientIPAddress, &ipaddress),
            Attribute::from_type(AttributeType::TMACAddress, &mac_address.to_owned()),
            Attribute::from_type(AttributeType::TDefaultExplorer, &explorer.to_owned()),
            Attribute::from_type(AttributeType::TCPUInfo, &cpu_info.to_owned()),
            Attribute::from_type(AttributeType::TMemorySize, &memory_size),
            Attribute::from_type(AttributeType::TOSVersion, &os_version.to_owned()),
            Attribute::from_type(AttributeType::TOSLang, &os_language.to_owned()),
        ];

        Packet::new(
            PacketCode::CRegisterRequest,
            Self::SEQUENCE,
            None,
            attributes,
        )
    }

    pub fn bubble_request(
        username: &str,
        ipaddress: Ipv4Addr,
        version: Option<&str>,
        mac_address: Option<&str>,
    ) -> PacketResult<Packet> {
        Self::simple_request(
            PacketCode::CBubbleRequest,
            username,
            ipaddress,
            version,
            mac_address,
        )
    }

    pub fn real_time_bubble_request(
        username: &str,
        ipaddress: Ipv4Addr,
        version: Option<&str>,
        mac_address: Option<&str>,
    ) -> PacketResult<Packet> {
        Self::simple_request(
            PacketCode::CRealTimeBubbleRequest,
            username,
            ipaddress,
            version,
            mac_address,
        )
    }

    fn simple_request(
        code: PacketCode,
        username: &str,
        ipaddress: Ipv4Addr,
        version: Option<&str>,
        mac_address: Option<&str>,
    ) -> PacketResult<Packet> {
        let version = version.unwrap_or("1.1.0");
        let mac_address = mac_address.unwrap_or("10:dd:b1:d5:95:ca");
        let client_type = Self::client_type();
        let attributes = vec![
            Attribute::from_type(AttributeType::TUserName, &username.to_owned()),
            Attribute::from_type(AttributeType::TClientVersion, &version.to_owned()),
            Attribute::from_type(AttributeType::TClientType, &client_type),
            Attribute::from_type(AttributeType::TClientIPAddress, &ipaddress),
            Attribute::from_type(AttributeType::TMACAddress, &mac_address.to_owned()),
        ];
        Packet::new(code, Self::SEQUENCE, None, attributes)
    }
}

impl PacketCode {
    fn from_u8(code: u8) -> Option<Self> {
        match code {
            0x1 => Some(Self::CRegisterRequest),
            0x2 => Some(Self::CRegisterResponse),
            0x3 => Some(Self::CKeepAliveRequest),
            0x4 => Some(Self::CKeepAliveResponse),
            0x5 => Some(Self::CBubbleRequest),
            0x6 => Some(Self::CBubbleResponse),
            0x7 => Some(Self::CChannelRequest),
            0x8 => Some(Self::CChannelResponse),
            0x9 => Some(Self::CPluginRequest),
            0xa => Some(Self::CPluginResponse),
            0xb => Some(Self::CRealTimeBubbleRequest),
            0xc => Some(Self::CRealTimeBubbleResponse),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_sequence() {
        assert_eq!(PacketFactoryWin::calc_seq(Some(1_472_483_020)).unwrap(), 43);
    }

    #[test]
    fn authenticates_known_packet() {
        let data: &[u8] = &[
            83, 78, 0, 105, 3, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 7, 10, 0,
            0, 1, 3, 0, 12, 49, 46, 50, 46, 50, 50, 46, 51, 54, 20, 0, 35, 100, 48, 100, 99, 101,
            50, 98, 48, 49, 51, 99, 56, 97, 100, 102, 97, 99, 54, 52, 54, 97, 50, 57, 49, 55, 102,
            100, 97, 98, 56, 48, 50, 18, 0, 7, 87, 196, 78, 204, 1, 0, 22, 48, 53, 56, 48, 50, 50,
            55, 56, 57, 56, 57, 64, 72, 89, 88, 89, 46, 88, 89,
        ];
        let authenticator = PacketAuthenticator::new("LLWLXA_TPSHARESECRET");
        let authorization = authenticator.authenticate(data).unwrap();
        assert_eq!(
            authorization,
            [
                240, 67, 87, 201, 164, 134, 179, 142, 110, 163, 208, 119, 121, 90, 173, 75,
            ]
        );
    }

    #[test]
    fn short_packet_length_returns_error() {
        let mut input = io::BufReader::new(&[0x53, 0x4e, 0, 1][..]);
        let error = Packet::from_bytes(&mut input).unwrap_err();
        assert!(matches!(
            error,
            SinglenetHeartbeatError::InvalidPacketLength { .. }
        ));
    }
}
