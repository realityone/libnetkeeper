use std::net::Ipv4Addr;
use std::num::Wrapping;

use dialer::Dialer;
use utils::integer_to_bytes;

// copy from https://github.com/xuzhipengnt/ipclient_gxnu
const USERNAME_MAX_LEN: usize = 30;
const MAC_ADDRESS_LEN: usize = 18;

#[derive(Debug)]
pub enum MACOpenErr {
    UsernameTooLong,
    MACAddressTooLong,
}

#[derive(Debug)]
pub struct MACOpenDialer {
    hash_key: u32,
}

#[derive(Debug)]
pub enum Configuration {
    GUET,
    GXNU,
}

#[derive(Debug)]
pub enum ISPCode {
    CChinaUnicom = 1 << 8,
    CChinaTelecom = 2 << 8,
    CChinaMobile = 3 << 8,
}

impl Configuration {
    pub fn hash_key(&self) -> u32 {
        match *self {
            _ => 0x4E67C6A7,
        }
    }
}

// [
// 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 172, 16, 1, 1,
// 52, 48, 58, 54, 49, 58, 56, 54, 58, 56, 55, 58, 57, 70, 58, 70, 49, 0,
// 0, 0, 1, 0,
// 255, 189, 40, 90
// ]
impl MACOpenDialer {
    pub fn new(hash_key: u32) -> Self {
        MACOpenDialer { hash_key: hash_key }
    }

    pub fn calculate_packet(&self,
                            username: &str,
                            ipaddress: Ipv4Addr,
                            mac_address: &str,
                            isp: ISPCode)
                            -> Result<Box<Vec<u8>>, MACOpenErr> {
        if username.len() > USERNAME_MAX_LEN - 1 {
            return Err(MACOpenErr::UsernameTooLong);
        }
        if mac_address.len() != MAC_ADDRESS_LEN - 1 {
            return Err(MACOpenErr::MACAddressTooLong);
        }

        let mut macopen_packet: Box<Vec<u8>> = Box::new(Vec::with_capacity(60));
        {
            let mut username_bytes = [0; USERNAME_MAX_LEN];
            let mut mac_address_bytes = [0; MAC_ADDRESS_LEN];
            username_bytes[..username.len()].clone_from_slice(username.as_bytes());
            mac_address_bytes[..mac_address.len()].clone_from_slice(mac_address.as_bytes());

            let isp_be = (isp as u32).to_be();
            let isp_bytes = integer_to_bytes(&isp_be);

            macopen_packet.extend(&username_bytes);
            macopen_packet.extend(&ipaddress.octets());
            macopen_packet.extend(&mac_address_bytes);
            macopen_packet.extend(isp_bytes);

            let hash_bytes = self.hash_bytes(&macopen_packet);
            macopen_packet.extend(&hash_bytes);
        }

        Ok(macopen_packet)
    }

    pub fn hash_bytes(&self, bytes: &[u8]) -> [u8; 4] {
        let mut hash = Wrapping(self.hash_key as i32);
        for c in bytes.iter() {
            hash ^= (hash << 5) + (hash >> 2) + Wrapping(*c as i32);
        }
        hash &= Wrapping(0x7fffffff);

        let mut hash_bytes = [0; 4];
        hash_bytes.clone_from_slice(integer_to_bytes(&hash.0));
        hash_bytes
    }
}

impl Dialer for MACOpenDialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        MACOpenDialer::new(config.hash_key())
    }
}

#[test]
fn test_mac_opener_hash_bytes() {
    let dialer = MACOpenDialer::load_from_config(Configuration::GUET);

    let bytes1 = [1, 2, 3, 4, 5, 6, 7, 0];
    let hash_bytes1 = dialer.hash_bytes(&bytes1);

    let bytes2 = [97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 172, 16, 1, 1, 52, 48, 58, 54, 49, 58, 56, 54, 58, 56, 55, 58, 57,
                  70, 58, 70, 49, 0, 0, 0, 1, 0];
    let hash_bytes2 = dialer.hash_bytes(&bytes2);

    assert_eq!(hash_bytes1, [0x9c, 0x89, 0xf8, 0x3d]);
    assert_eq!(hash_bytes2, [255, 189, 40, 90]);
}