use std::net::Ipv4Addr;

use openssl::crypto::hash::{Hasher, Type};

use heartbeater::singlenet::attributes::{Attribute, AttributeVec, AttributeFactory};
use utils::{current_timestamp, integer_to_bytes};

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
    attributes: Vec<Attribute>,
}

pub struct PacketAuthenticator {
    salt: String,
}

// len(magic_number) + len(length) + len(code) + len(seq) + \
// len(authenticator)
// 2 + 2 + 1 + 1 + 16
const HEADER_LENGTH: u16 = 22;
const MAGIC_NUMBE: u16 = 0x534e;

impl PacketAuthenticator {
    pub fn new(salt: &str) -> Self {
        PacketAuthenticator { salt: salt.to_string() }
    }

    pub fn authenticate(&self, bytes: &[u8]) -> [u8; 16] {
        let mut md5 = Hasher::new(Type::MD5).unwrap();

        md5.update(bytes).unwrap();
        md5.update(self.salt.as_bytes()).unwrap();

        let mut authorization = [0; 16];
        authorization.clone_from_slice(&md5.finish().unwrap());
        authorization
    }
}

pub trait PacketFactoryWin {
    fn calc_seq(timestamp: Option<u32>) -> u8 {
        // only be used in windows version,
        let timestamp = match timestamp {
            Some(timestamp) => timestamp,
            None => current_timestamp(),
        };

        let tmp_num = ((timestamp as u64 * 0x343fd) + 0x269ec3) as u32;
        let seq = ((tmp_num >> 0x10) & 0xff) as u8;
        seq
    }

    fn thunder_protocol(username: &str,
                        ipaddress: Ipv4Addr,
                        timestamp: Option<u32>,
                        last_keepalive_data: Option<&str>,
                        version: Option<&str>)
                        -> Packet;
}

pub trait PacketFactoryMac {
    fn calc_seq() -> u8 {
        0x1 as u8
    }
}

impl Packet {
    pub fn new(code: PacketCode, seq: u8, attributes: Vec<Attribute>) -> Self {
        let mut packet = Packet {
            magic_number: MAGIC_NUMBE,
            length: 0,
            code: code,
            seq: seq,
            attributes: attributes,
        };
        packet.length = Self::calc_length(&packet);
        packet
    }

    pub fn calc_length(packet: &Self) -> u16 {
        HEADER_LENGTH + packet.attributes.length()
    }

    pub fn as_bytes(&mut self, authenticator: Option<&PacketAuthenticator>) -> Box<Vec<u8>> {
        let mut bytes: Box<Vec<u8>> = Box::new(Vec::new());
        let authorization = match authenticator {
            Some(authenticator) => authenticator.authenticate(&self.as_bytes(None)),
            None => [0; 16],
        };

        {
            let magic_number_be = self.magic_number.to_be();
            let length_be = self.length.to_be();

            let magic_number_bytes = integer_to_bytes(&magic_number_be);
            let length_bytes = integer_to_bytes(&length_be);
            let attributes_bytes = self.attributes.as_bytes();
            let raw_packet_code = self.code as u8;

            bytes.extend(magic_number_bytes);
            bytes.extend(length_bytes);
            bytes.push(raw_packet_code);
            bytes.push(self.seq);
            bytes.extend(authorization.iter());
            bytes.extend(attributes_bytes);
        }
        bytes
    }
}

impl PacketFactoryWin for Packet {
    // FIXME: this protocol needs update
    fn thunder_protocol(username: &str,
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
        let keepalive_data = Attribute::calc_keepalive_data(timestamp, last_keepalive_data);

        let attributes = vec![
            Attribute::client_ip_address(ipaddress),
            Attribute::client_version(version),
            Attribute::keepalive_data(&keepalive_data),
            Attribute::keepalive_time(timestamp.unwrap()),
            Attribute::username(username),
            ];

        Packet::new(PacketCode::CKeepAliveRequest,
                    Packet::calc_seq(timestamp),
                    attributes)
    }
}

#[test]
fn test_calc_seq() {
    let seq = Packet::calc_seq(Some(1472483020));
    assert_eq!(seq, 43 as u8);
}

#[test]
fn test_authenticator() {
    let data: &[u8] = &[83, 78, 0, 105, 3, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                        0, 7, 10, 0, 0, 1, 3, 0, 12, 49, 46, 50, 46, 50, 50, 46, 51, 54, 20, 0,
                        35, 100, 48, 100, 99, 101, 50, 98, 48, 49, 51, 99, 56, 97, 100, 102, 97,
                        99, 54, 52, 54, 97, 50, 57, 49, 55, 102, 100, 97, 98, 56, 48, 50, 18, 0,
                        7, 87, 196, 78, 204, 1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57,
                        64, 72, 89, 88, 89, 46, 88, 89];
    let authenticator = PacketAuthenticator::new("LLWLXA_TPSHARESECRET");
    let authorization = authenticator.authenticate(data);
    let real_authorization: [u8; 16] = [240, 67, 87, 201, 164, 134, 179, 142, 110, 163, 208, 119,
                                        121, 90, 173, 75];
    assert_eq!(authorization, real_authorization);
}
