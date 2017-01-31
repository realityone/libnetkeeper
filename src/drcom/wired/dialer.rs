use std::{io, result};
use std::net::Ipv4Addr;
use std::str::FromStr;

use rand;
use rand::Rng;

use drcom::{DrCOMCommon, DrCOMResponseCommon, DrCOMValidateError};
use common::utils::current_timestamp;
use common::reader::{ReadBytesError, ReaderHelper};
use common::bytes::{BytesAble, BytesAbleNum};
use crypto::hash::{HasherType, HasherBuilder};

#[derive(Debug)]
pub enum LoginError {
    ValidateError(DrCOMValidateError),
    PacketReadError(ReadBytesError),
    StringFieldOverflow(String, usize),
}

type LoginResult<T> = result::Result<T, LoginError>;

#[derive(Debug)]
pub struct ChallengeRequest {
    sequence: u16,
}

#[derive(Debug)]
pub struct ChallengeResponse {
    pub hash_salt: [u8; 4],
}

#[derive(Debug)]
pub struct TagOSVersionInfo {
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    service_pack: String,
}

#[derive(Debug)]
pub struct TagHostInfo {
    hostname: String,
    dns_server: Ipv4Addr,
    dhcp_server: Ipv4Addr,
    backup_dns_server: Ipv4Addr,
    wins_ips: [Ipv4Addr; 2],
    os_version: TagOSVersionInfo,
}

#[derive(Debug)]
pub struct TagLDAPAuth {
    password: String,
    hash_salt: [u8; 4],
}

const SERVICE_PACK_MAX_LEN: usize = 32;
const HOST_NAME_MAX_LEN: usize = 32;
const PASSWORD_MAX_LEN: usize = 16;

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

        result[2..4].copy_from_slice(&self.sequence.as_bytes_le());
        result[4..8].copy_from_slice(&Self::magic_number().as_bytes_le());
        result
    }
}

impl DrCOMResponseCommon for ChallengeResponse {}
impl ChallengeResponse {
    pub fn from_bytes<R>(input: &mut io::BufReader<R>) -> LoginResult<Self>
        where R: io::Read
    {
        // validate packet and consume 1 byte
        try!(Self::validate_stream(input, |c| c == 0x02).map_err(LoginError::ValidateError));

        // drain unknow bytes
        try!(input.read_bytes(3).map_err(LoginError::PacketReadError));

        let salt_bytes = try!(input.read_bytes(4).map_err(LoginError::PacketReadError));
        let mut hash_salt = [0u8; 4];
        hash_salt.clone_from_slice(&salt_bytes);

        Ok(ChallengeResponse { hash_salt: hash_salt })
    }
}

impl TagOSVersionInfo {
    pub fn new(major_version: Option<u32>,
               minor_version: Option<u32>,
               build_number: Option<u32>,
               platform_id: Option<u32>,
               service_pack: Option<&str>)
               -> Self {
        let major_version = major_version.unwrap_or(0x05);
        let minor_version = minor_version.unwrap_or(0x01);
        let build_number = build_number.unwrap_or(0x0a28);
        let platform_id = platform_id.unwrap_or(0x02);
        let service_pack = service_pack.unwrap_or("8089D").to_string();
        TagOSVersionInfo {
            major_version: major_version,
            minor_version: minor_version,
            build_number: build_number,
            platform_id: platform_id,
            service_pack: service_pack,
        }
    }

    fn validate(&self) -> LoginResult<()> {
        if self.service_pack.len() > SERVICE_PACK_MAX_LEN {
            return Err(LoginError::StringFieldOverflow(self.service_pack.clone(),
                                                       SERVICE_PACK_MAX_LEN));
        }
        Ok(())
    }

    fn packet_length() -> usize {
        4 + // packet_length
        4 + // major_version
        4 + // minor_version
        4 + // build_number
        4 + // platform_id
        128 // service_pack
    }

    fn content_length() -> usize {
        4 + // major_version
        4 + // minor_version
        4 + // build_number
        4 + // platform_id
        128 // service_pack
    }

    pub fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut content_bytes = vec![0u8; Self::content_length()];

        content_bytes[0..4].copy_from_slice(&self.major_version.as_bytes_le());
        content_bytes[4..8].copy_from_slice(&self.minor_version.as_bytes_le());
        content_bytes[8..12].copy_from_slice(&self.build_number.as_bytes_le());
        content_bytes[12..16].copy_from_slice(&self.platform_id.as_bytes_le());
        content_bytes[16..16 + self.service_pack.len()]
            .copy_from_slice(self.service_pack.as_bytes());

        let mut result = Vec::with_capacity(Self::packet_length());
        result.extend((Self::packet_length() as u32).as_bytes_le());
        result.extend(content_bytes);

        Ok(result)
    }
}

impl Default for TagOSVersionInfo {
    fn default() -> Self {
        TagOSVersionInfo::new(None, None, None, None, None)
    }
}

impl TagHostInfo {
    pub fn new(hostname: Option<&str>,
               dns_server: Option<Ipv4Addr>,
               dhcp_server: Option<Ipv4Addr>,
               backup_dns_server: Option<Ipv4Addr>,
               wins_ips: Option<[Ipv4Addr; 2]>,
               os_version: Option<TagOSVersionInfo>)
               -> Self {
        let hostname = hostname.unwrap_or("LIYUANYUAN").to_string();
        let dns_server =
            dns_server.unwrap_or_else(|| Ipv4Addr::from_str("114.114.114.114").unwrap());
        let dhcp_server = dhcp_server.unwrap_or_else(|| Ipv4Addr::from(0x0));
        let backup_dns_server = backup_dns_server.unwrap_or_else(|| Ipv4Addr::from(0x0));
        let wins_ips = wins_ips.unwrap_or([Ipv4Addr::from(0x0); 2]);
        let os_version = os_version.unwrap_or_default();

        TagHostInfo {
            hostname: hostname,
            dns_server: dns_server,
            dhcp_server: dhcp_server,
            backup_dns_server: backup_dns_server,
            wins_ips: wins_ips,
            os_version: os_version,
        }
    }

    fn validate(&self) -> LoginResult<()> {
        if self.hostname.len() > HOST_NAME_MAX_LEN {
            return Err(LoginError::StringFieldOverflow(self.hostname.clone(), HOST_NAME_MAX_LEN));
        }
        Ok(())
    }

    fn packet_length() -> usize {
        32 + // hostname
        4 + // dns_server
        4 + // dhcp_server
        4 + // backup_dns_server
        8 + // wins_ips
        TagOSVersionInfo::packet_length()
    }

    pub fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut result = Vec::with_capacity(Self::packet_length());

        let mut hostname_bytes = [0u8; HOST_NAME_MAX_LEN];
        hostname_bytes[..self.hostname.len()].copy_from_slice(self.hostname.as_bytes());
        result.extend_from_slice(&hostname_bytes);

        result.extend(self.dns_server.as_bytes());
        result.extend(self.dhcp_server.as_bytes());
        result.extend(self.backup_dns_server.as_bytes());
        for ip in &self.wins_ips {
            result.extend(ip.as_bytes());
        }

        let os_version_bytes = try!(self.os_version.as_bytes());
        result.extend(os_version_bytes);

        Ok(result)
    }
}

impl Default for TagHostInfo {
    fn default() -> Self {
        TagHostInfo::new(None, None, None, None, None, None)
    }
}

impl TagLDAPAuth {
    fn validate(&self) -> LoginResult<()> {
        if self.password.len() > PASSWORD_MAX_LEN {
            return Err(LoginError::StringFieldOverflow(self.password.clone(), PASSWORD_MAX_LEN));
        }
        Ok(())
    }

    fn new(password: &str, hash_salt: [u8; 4]) -> Self {
        let password = password.to_string();
        TagLDAPAuth {
            password: password,
            hash_salt: hash_salt,
        }
    }

    fn ror(md5_digest: [u8; 16], password: &str) -> LoginResult<Vec<u8>> {
        if password.len() > PASSWORD_MAX_LEN {
            return Err(LoginError::StringFieldOverflow(password.to_string(), PASSWORD_MAX_LEN));
        }

        let mut result = Vec::with_capacity(PASSWORD_MAX_LEN);
        for (i, c) in password.as_bytes().into_iter().enumerate() {
            let x: u8 = md5_digest[i] ^ c;
            result.push((x << 3) + (x >> 5));
        }
        Ok(result)
    }

    fn packet_length(&self) -> usize {
        1 + // code
        1 + // password length
        self.password.len()
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        const HASH_SALT_MAGIC_NUMBER: u16 = 0x0103u16;

        try!(self.validate());

        let mut result = Vec::with_capacity(self.packet_length());
        result.push(0u8);
        result.push(self.password.len() as u8);

        let password_hash;
        {
            let mut md5 = HasherBuilder::build(HasherType::MD5);
            md5.update(&HASH_SALT_MAGIC_NUMBER.as_bytes_le());
            md5.update(&self.hash_salt);
            md5.update(self.password.as_bytes());

            let mut md5_digest = [0u8; 16];
            md5_digest.copy_from_slice(&md5.finish());
            password_hash = try!(TagLDAPAuth::ror(md5_digest, &self.password));
        }
        result.extend(password_hash);

        Ok(result)
    }
}

#[test]
fn test_login_packet_attributes() {
    let tovi = TagOSVersionInfo::default();
    assert_eq!(tovi.as_bytes().unwrap(),
               vec![148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40, 10, 0, 0, 2, 0, 0, 0, 56, 48, 56,
                    57, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let thi = TagHostInfo::default();
    assert_eq!(thi.as_bytes().unwrap(),
               vec![76, 73, 89, 85, 65, 78, 89, 85, 65, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40, 10, 0, 0, 2,
                    0, 0, 0, 56, 48, 56, 57, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0]);

    let la = TagLDAPAuth::new("admin", [1, 2, 3, 4]);
    assert_eq!(la.as_bytes().unwrap(), vec![0, 5, 146, 26, 36, 122, 150]);
}

#[test]
fn test_ror() {
    assert_eq!(TagLDAPAuth::ror([253u8; 16], "1234567812345678").unwrap(),
               vec![102, 126, 118, 78, 70, 94, 86, 46, 102, 126, 118, 78, 70, 94, 86, 46]);
}