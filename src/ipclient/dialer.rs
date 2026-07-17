use std::net::Ipv4Addr;
use std::num::Wrapping;

use thiserror::Error;

const USERNAME_MAX_LEN: usize = 30;
const MAC_ADDRESS_LEN: usize = 18;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MacOpenError {
    #[error("username is too long: maximum {max} bytes, got {actual}")]
    UsernameTooLong { max: usize, actual: usize },

    #[error("invalid MAC address length: expected {expected} bytes, got {actual}")]
    InvalidMacAddressLength { expected: usize, actual: usize },

    #[error("internal packet buffer is too short for the {field} field")]
    PacketBufferTooShort { field: &'static str },
}

#[deprecated(note = "use MacOpenError")]
pub type MACOpenErr = MacOpenError;

pub type MacOpenResult<T> = Result<T, MacOpenError>;

#[derive(Debug)]
pub struct MACOpenPacket {
    username: String,
    ipaddress: Ipv4Addr,
    mac_address: String,
    isp: ISPCode,
}

#[derive(Debug, Clone, Copy)]
pub enum Configuration {
    GUET,
    GXNU,
}

#[derive(Debug, Clone, Copy)]
pub enum ISPCode {
    CChinaUnicom = 1 << 8,
    CChinaTelecom = 2 << 8,
    CChinaMobile = 3 << 8,
}

impl Configuration {
    pub fn hash_key(self) -> u32 {
        0x4E67_C6A7
    }
}

impl MACOpenPacket {
    pub fn new(username: &str, ipaddress: Ipv4Addr, mac_address: &str, isp: ISPCode) -> Self {
        MACOpenPacket {
            username: username.to_string(),
            ipaddress,
            mac_address: mac_address.to_string(),
            isp,
        }
    }

    pub fn as_bytes(&self, hash_key: u32) -> MacOpenResult<Vec<u8>> {
        let mut macopen_packet = Vec::with_capacity(60);
        {
            self.validate()?;

            let mut username_bytes = [0; USERNAME_MAX_LEN];
            let mut mac_address_bytes = [0; MAC_ADDRESS_LEN];
            username_bytes
                .get_mut(..self.username.len())
                .ok_or(MacOpenError::PacketBufferTooShort { field: "username" })?
                .copy_from_slice(self.username.as_bytes());
            mac_address_bytes
                .get_mut(..self.mac_address.len())
                .ok_or(MacOpenError::PacketBufferTooShort {
                    field: "MAC address",
                })?
                .copy_from_slice(self.mac_address.as_bytes());

            macopen_packet.extend_from_slice(&username_bytes);
            macopen_packet.extend_from_slice(&self.ipaddress.octets());
            macopen_packet.extend_from_slice(&mac_address_bytes);
            macopen_packet.extend_from_slice(&(self.isp as u32).to_be_bytes());

            let hash_bytes = Self::hash_bytes(&macopen_packet, hash_key);
            macopen_packet.extend_from_slice(&hash_bytes);
        }

        Ok(macopen_packet)
    }

    fn validate(&self) -> MacOpenResult<()> {
        if self.username.len() > USERNAME_MAX_LEN - 1 {
            return Err(MacOpenError::UsernameTooLong {
                max: USERNAME_MAX_LEN - 1,
                actual: self.username.len(),
            });
        }
        if self.mac_address.len() != MAC_ADDRESS_LEN - 1 {
            return Err(MacOpenError::InvalidMacAddressLength {
                expected: MAC_ADDRESS_LEN - 1,
                actual: self.mac_address.len(),
            });
        }
        Ok(())
    }

    fn hash_bytes(bytes: &[u8], hash_key: u32) -> [u8; 4] {
        let mut hash = Wrapping(hash_key as i32);
        for c in bytes.iter() {
            hash ^= (hash << 5) + (hash >> 2) + Wrapping(i32::from(*c));
        }
        hash &= Wrapping(0x7fff_ffff);

        (hash.0 as u32).to_le_bytes()
    }
}

#[test]
fn test_mac_opener_hash_bytes() {
    let bytes1 = [1, 2, 3, 4, 5, 6, 7, 0];
    let hash_bytes1 = MACOpenPacket::hash_bytes(&bytes1, Configuration::GUET.hash_key());

    let bytes2 = [
        97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        172, 16, 1, 1, 52, 48, 58, 54, 49, 58, 56, 54, 58, 56, 55, 58, 57, 70, 58, 70, 49, 0, 0, 0,
        1, 0,
    ];
    let hash_bytes2 = MACOpenPacket::hash_bytes(&bytes2, Configuration::GUET.hash_key());

    assert_eq!(hash_bytes1, [0x9c, 0x89, 0xf8, 0x3d]);
    assert_eq!(hash_bytes2, [255, 189, 40, 90]);
}
