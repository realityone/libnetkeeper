use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

use linked_hash_map::LinkedHashMap;
use thiserror::Error;

use crate::common::error::TimeError;
use crate::common::reader::{ReadBytesError, ReaderHelper};
use crate::common::utils::resolve_timestamp;
use crate::crypto::cipher::{CipherError, SimpleCipher};
use crate::crypto::hash::{HasherBuilder, HasherType};

#[derive(Debug, Error)]
pub enum NetkeeperHeartbeatError {
    #[error("packet encryption or decryption failed")]
    Cipher(#[from] CipherError),

    #[error("failed to read packet data")]
    Read(#[from] ReadBytesError),

    #[error("unexpected packet magic: expected {expected:#06x}, got {actual:#06x}")]
    InvalidMagic { expected: u16, actual: u16 },

    #[error("packet version is not valid UTF-8")]
    InvalidVersionEncoding(#[source] FromUtf8Error),

    #[error("packet version is not a decimal byte")]
    InvalidVersion(#[source] ParseIntError),

    #[error("packet version {version} cannot be represented by the two-byte wire format")]
    VersionOutOfRange { version: u8 },

    #[error("decrypted frame is not valid UTF-8")]
    InvalidFrameEncoding(#[source] FromUtf8Error),

    #[error("packet content is too long: maximum {max} bytes, got {actual}")]
    ContentTooLong { max: usize, actual: usize },

    #[error("hash output has an unexpected length: expected {expected} bytes, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },

    #[error("timestamp encoding has an unexpected length: expected {expected} bytes, got {actual}")]
    InvalidTimestampEncoding { expected: usize, actual: usize },

    #[error("failed to resolve the current timestamp")]
    Time(#[from] TimeError),
}

pub type PacketResult<T> = Result<T, NetkeeperHeartbeatError>;

#[derive(Debug)]
pub struct Frame {
    type_name: String,
    content: LinkedHashMap<String, String>,
}

#[derive(Debug)]
pub struct Packet {
    magic_number: u16,
    version: u8,
    code: u16,
    frame: Frame,
}

pub struct PacketUtils;

impl Frame {
    pub fn new(type_name: &str, content: Option<LinkedHashMap<String, String>>) -> Self {
        Self {
            type_name: type_name.to_owned(),
            content: content.unwrap_or_default(),
        }
    }

    pub fn add(&mut self, name: &str, value: &str) {
        self.content.insert(name.to_owned(), value.to_owned());
    }

    fn as_bytes(&self, join_with: Option<&str>) -> Vec<u8> {
        let join_with = join_with.unwrap_or("&");
        let mut linked_content = Vec::with_capacity(self.content.len() + 1);
        linked_content.push(format!("TYPE={}", self.type_name));
        for (key, value) in &self.content {
            linked_content.push(format!("{key}={value}"));
        }
        linked_content.join(join_with).into_bytes()
    }

    fn from_bytes(bytes: Vec<u8>, split_with: Option<&str>) -> PacketResult<Self> {
        let byte_content =
            String::from_utf8(bytes).map_err(NetkeeperHeartbeatError::InvalidFrameEncoding)?;
        let split_with = split_with.unwrap_or("&");

        let mut type_name = String::new();
        let mut frame_content = LinkedHashMap::new();
        for param in byte_content.split(split_with) {
            let Some((name, value)) = param.split_once('=') else {
                continue;
            };
            if name.eq_ignore_ascii_case("type") {
                type_name = value.to_owned();
            } else {
                frame_content.insert(name.to_owned(), value.to_owned());
            }
        }

        Ok(Self {
            type_name,
            content: frame_content,
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.as_bytes(None).len()
    }
}

impl Packet {
    const MAGIC_NUMBER: u16 = 0x4852;

    pub fn new(version: u8, code: u16, frame: Frame) -> Self {
        Self {
            magic_number: Self::MAGIC_NUMBER,
            version,
            code,
            frame,
        }
    }

    pub fn as_bytes<E>(&self, encrypter: &E) -> PacketResult<Vec<u8>>
    where
        E: SimpleCipher,
    {
        if self.version > 99 {
            return Err(NetkeeperHeartbeatError::VersionOutOfRange {
                version: self.version,
            });
        }

        let version = format!("{:02}", self.version);
        let encrypted_content = encrypter.encrypt(&self.frame.as_bytes(None))?;
        let content_length = u32::try_from(encrypted_content.len()).map_err(|_| {
            NetkeeperHeartbeatError::ContentTooLong {
                max: u32::MAX as usize,
                actual: encrypted_content.len(),
            }
        })?;

        let mut packet_bytes = Vec::with_capacity(10 + encrypted_content.len());
        packet_bytes.extend_from_slice(&self.magic_number.to_be_bytes());
        packet_bytes.extend_from_slice(version.as_bytes());
        packet_bytes.extend_from_slice(&self.code.to_be_bytes());
        packet_bytes.extend_from_slice(&content_length.to_be_bytes());
        packet_bytes.extend_from_slice(&encrypted_content);
        Ok(packet_bytes)
    }

    pub fn from_bytes<R, E>(
        input: &mut io::BufReader<R>,
        encrypter: &E,
        split_with: Option<&str>,
    ) -> PacketResult<Self>
    where
        E: SimpleCipher,
        R: io::Read,
    {
        let magic_number = u16::from_be_bytes(input.read_exact_array()?);
        if magic_number != Self::MAGIC_NUMBER {
            return Err(NetkeeperHeartbeatError::InvalidMagic {
                expected: Self::MAGIC_NUMBER,
                actual: magic_number,
            });
        }

        let version = String::from_utf8(input.read_bytes(2)?)
            .map_err(NetkeeperHeartbeatError::InvalidVersionEncoding)?
            .parse::<u8>()
            .map_err(NetkeeperHeartbeatError::InvalidVersion)?;
        let code = u16::from_be_bytes(input.read_exact_array()?);
        let content_length = u32::from_be_bytes(input.read_exact_array()?);
        let content_length = usize::try_from(content_length).map_err(|_| {
            NetkeeperHeartbeatError::ContentTooLong {
                max: usize::MAX,
                actual: u32::MAX as usize,
            }
        })?;

        let encrypted_content = input.read_bytes(content_length)?;
        let plain_content = encrypter.decrypt(&encrypted_content)?;
        let frame = Frame::from_bytes(plain_content, split_with)?;
        Ok(Self::new(version, code, frame))
    }
}

impl PacketUtils {
    pub fn calculate_pin(timestamp: Option<u32>) -> PacketResult<String> {
        let timestamp = resolve_timestamp(timestamp)?;
        let timestamp_hex = format!("{timestamp:08x}");
        let [time0, time1, time2, time3, time4, time5, time6, time7] = timestamp_hex.as_bytes()
        else {
            return Err(NetkeeperHeartbeatError::InvalidTimestampEncoding {
                expected: 8,
                actual: timestamp_hex.len(),
            });
        };

        let salt = match timestamp % 3 {
            0 => "wanglei",
            1 => "zhangni",
            _ => "wangtianyou",
        };
        let mut md5 = HasherBuilder::build(HasherType::MD5);
        md5.update(timestamp_hex.as_bytes());
        md5.update(salt.as_bytes());
        let hashed_bytes = md5.finish();
        let [
            hash0,
            hash1,
            hash2,
            hash3,
            hash4,
            hash5,
            hash6,
            hash7,
            hash8,
            hash9,
            hash10,
            hash11,
            hash12,
            hash13,
            hash14,
            hash15,
        ] = hashed_bytes.as_slice()
        else {
            return Err(NetkeeperHeartbeatError::InvalidHashLength {
                expected: 16,
                actual: hashed_bytes.len(),
            });
        };

        Ok(format!(
            "{}{}{:02x}{:02x}{}{}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{}{}{:02x}{:02x}{:02x}{}{}{:02x}{:02x}{:02x}",
            char::from(*time0),
            char::from(*time1),
            hash0,
            hash1,
            char::from(*time2),
            char::from(*time3),
            hash2,
            hash3,
            hash4,
            hash5,
            hash6,
            hash7,
            hash8,
            hash9,
            char::from(*time4),
            char::from(*time5),
            hash10,
            hash11,
            hash12,
            char::from(*time6),
            char::from(*time7),
            hash13,
            hash14,
            hash15,
        ))
    }

    #[deprecated(note = "use calculate_pin")]
    pub fn claculate_pin(timestamp: Option<u32>) -> PacketResult<String> {
        Self::calculate_pin(timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::Aes128Ecb;

    #[test]
    fn frame_round_trip() {
        let mut content = LinkedHashMap::new();
        content.insert("USER_NAME".to_owned(), "05802278989@HYXY.XY".to_owned());
        content.insert("PASSWORD".to_owned(), "000000".to_owned());
        let frame = Frame::new("HEARTBEAT", Some(content));
        let frame_bytes = frame.as_bytes(None);
        assert_eq!(
            std::str::from_utf8(&frame_bytes).unwrap(),
            "TYPE=HEARTBEAT&USER_NAME=05802278989@HYXY.XY&PASSWORD=000000"
        );
        assert_eq!(frame.len(), 60);

        let parsed = Frame::from_bytes(frame_bytes, None).unwrap();
        assert_eq!(parsed.len(), 60);
    }

    #[test]
    fn calculates_heartbeat_pin() {
        let pin = PacketUtils::calculate_pin(Some(1_472_483_020)).unwrap();
        assert_eq!(pin, "57c41bc45b493cfb5f5016074e987ef9cca96334");
    }

    #[test]
    fn encrypts_known_frame() {
        let aes = Aes128Ecb::from_key(b"xlzjhrprotocol3x").unwrap();
        let encrypted = aes
            .encrypt(b"TYPE=HEARTBEAT&USER_NAME=05802278989@HYXY.XY&PASSWORD=000000")
            .unwrap();
        let expected = vec![
            66, 100, 164, 73, 167, 41, 222, 211, 188, 8, 14, 110, 252, 246, 121, 119, 79, 18, 254,
            193, 72, 163, 54, 136, 248, 60, 221, 177, 221, 0, 13, 10, 146, 141, 142, 244, 89, 10,
            176, 106, 162, 242, 204, 38, 73, 34, 55, 137, 180, 223, 253, 142, 43, 158, 209, 80,
            100, 141, 11, 15, 146, 20, 207, 10,
        ];
        assert_eq!(encrypted, expected);
    }

    #[test]
    fn malformed_version_returns_error() {
        let aes = Aes128Ecb::from_key(b"xlzjhrprotocol3x").unwrap();
        let mut input = io::BufReader::new(&b"HRxx"[..]);
        let error = Packet::from_bytes(&mut input, &aes, None).unwrap_err();
        assert!(matches!(error, NetkeeperHeartbeatError::InvalidVersion(_)));
    }
}
