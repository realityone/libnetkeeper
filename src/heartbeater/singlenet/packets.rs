use std::str::FromStr;
use std::net::Ipv4Addr;

use openssl::crypto::hash::{Hasher, Type};

use heartbeater::singlenet::attributes::{Attribute, AttributeVec, AttributeFactory};
use utils::{current_timestamp, integer_to_bytes};

#[derive(Debug)]
struct Packet {
    magic_number: u16,
    length: u16,
    code: u8,
    timeflag: u8,
    signature: [u8; 16],
    attributes: Vec<Attribute>,
}

const HEADER_LENGTH: u16 = 22;

impl Packet {
    pub fn new(code: u8, timeflag: u8, attributes: Vec<Attribute>) -> Self {
        let mut length = HEADER_LENGTH;
        length = attributes.iter().fold(length, |sum, attr| sum + attr.length());

        Packet {
            magic_number: Self::magic_number(),
            length: length,
            code: code,
            timeflag: timeflag,
            signature: [0; 16],
            attributes: attributes,
        }
    }

    pub fn as_bytes(&mut self, with_signature: bool) -> Box<Vec<u8>> {
        let mut bytes: Box<Vec<u8>> = Box::new(Vec::new());
        if with_signature {
            self.signature = Self::calc_signature(&self.as_bytes(false), None);
        }

        {
            let magic_number_be = self.magic_number.to_be();
            let length_be = self.length.to_be();

            let magic_number_bytes = integer_to_bytes(&magic_number_be);
            let length_bytes = integer_to_bytes(&length_be);
            let attributes_bytes = self.attributes.as_bytes();

            bytes.extend(magic_number_bytes);
            bytes.extend(length_bytes);
            bytes.push(self.code);
            bytes.push(self.timeflag);
            bytes.extend(&self.signature);
            bytes.extend(attributes_bytes);
        }
        bytes
    }

    pub fn calc_signature(bytes: &[u8], salt: Option<&str>) -> [u8; 16] {
        let salt = match salt {
            Some(salt) => salt,
            None => "LLWLXA_TPSHARESECRET",
        };

        let mut md5 = Hasher::new(Type::MD5).unwrap();

        md5.update(bytes).unwrap();
        md5.update(salt.as_bytes()).unwrap();

        let mut hashed_bytes = [0; 16];
        hashed_bytes.clone_from_slice(&md5.finish().unwrap());
        hashed_bytes
    }

    pub fn thunder_protocol(username: &str,
                            ipaddress: Ipv4Addr,
                            timestamp: Option<u32>,
                            last_keepalive_data: Option<&str>,
                            version: Option<&str>)
                            -> Self {
        let version = match version {
            Some(version) => version,
            None => "1.2.22.36",
        };
        let timestamp = match timestamp {
            Some(timestamp) => Some(timestamp),
            None => Some(current_timestamp()),
        };
        println!("{:?}", timestamp);
        let keepalive_data = Attribute::calc_keepalive_data(timestamp, last_keepalive_data);
        let attributes = vec![
            Attribute::client_ip_address(ipaddress),
            Attribute::client_version(version),
            Attribute::keepalive_data(&keepalive_data),
            Attribute::keepalive_time(timestamp.unwrap()),
            Attribute::username(username),
            ];

        Packet::new(0x3, Self::calc_timeflag(timestamp), attributes)
    }

    fn calc_timeflag(timestamp: Option<u32>) -> u8 {
        let timestamp = match timestamp {
            Some(timestamp) => timestamp,
            None => current_timestamp(),
        };

        let tmp_num = ((timestamp as u64 * 0x343fd) + 0x269ec3) as u32;
        let timeflag = ((tmp_num >> 0x10) & 0xff) as u8;
        timeflag
    }

    fn magic_number() -> u16 {
        0x534e as u16
    }
}

#[test]
fn test_calc_timeflag() {
    let timeflag = Packet::calc_timeflag(Some(1472483020));
    assert_eq!(timeflag, 43 as u8);
}

#[test]
fn test_calc_signature() {
    let data: &[u8] = &[83, 78, 0, 105, 3, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                        0, 7, 10, 0, 0, 1, 3, 0, 12, 49, 46, 50, 46, 50, 50, 46, 51, 54, 20, 0,
                        35, 100, 48, 100, 99, 101, 50, 98, 48, 49, 51, 99, 56, 97, 100, 102, 97,
                        99, 54, 52, 54, 97, 50, 57, 49, 55, 102, 100, 97, 98, 56, 48, 50, 18, 0,
                        7, 87, 196, 78, 204, 1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57,
                        64, 72, 89, 88, 89, 46, 88, 89];
    let hashed_bytes = Packet::calc_signature(data, None);
    let real_hash_bytes: [u8; 16] = [240, 67, 87, 201, 164, 134, 179, 142, 110, 163, 208, 119,
                                     121, 90, 173, 75];
    assert_eq!(hashed_bytes, real_hash_bytes);
}

#[test]
fn test_thunder_protocol() {
    let mut tp1 = Packet::thunder_protocol("05802278989@HYXY.XY",
                                           Ipv4Addr::from_str("10.0.0.1").unwrap(),
                                           Some(1472483020),
                                           None,
                                           None);
    let mut tp2 = Packet::thunder_protocol("05802278989@HYXY.XY",
                                           Ipv4Addr::from_str("10.0.0.1").unwrap(),
                                           Some(1472483020),
                                           Some("ffb0b2af94693fd1ba4c93e6b9aebd3f"),
                                           None);
    let tp1_bytes = tp1.as_bytes(true);
    let tp2_bytes = tp2.as_bytes(true);
    let real1_bytes: Vec<u8> = vec![83, 78, 0, 105, 3, 43, 220, 250, 219, 227, 84, 6, 40, 77, 138,
                                    217, 220, 230, 189, 142, 123, 179, 2, 0, 7, 10, 0, 0, 1, 3, 0,
                                    12, 49, 46, 50, 46, 50, 50, 46, 51, 54, 20, 0, 35, 102, 102,
                                    98, 48, 98, 50, 97, 102, 57, 52, 54, 57, 51, 102, 100, 49, 98,
                                    97, 52, 99, 57, 51, 101, 54, 98, 57, 97, 101, 98, 100, 51,
                                    102, 18, 0, 7, 87, 196, 78, 204, 1, 0, 22, 48, 53, 56, 48, 50,
                                    50, 55, 56, 57, 56, 57, 64, 72, 89, 88, 89, 46, 88, 89];
    let real2_bytes: Vec<u8> =
        vec![83, 78, 0, 105, 3, 43, 240, 67, 87, 201, 164, 134, 179, 142, 110, 163, 208, 119, 121,
             90, 173, 75, 2, 0, 7, 10, 0, 0, 1, 3, 0, 12, 49, 46, 50, 46, 50, 50, 46, 51, 54, 20,
             0, 35, 100, 48, 100, 99, 101, 50, 98, 48, 49, 51, 99, 56, 97, 100, 102, 97, 99, 54,
             52, 54, 97, 50, 57, 49, 55, 102, 100, 97, 98, 56, 48, 50, 18, 0, 7, 87, 196, 78, 204,
             1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72, 89, 88, 89, 46, 88, 89];
    assert_eq!(*tp1_bytes, real1_bytes);
    assert_eq!(*tp2_bytes, real2_bytes);
}
