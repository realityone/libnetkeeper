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
    FieldValueOverflow(usize, usize),
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
struct TagLDAPAuth {
    password_ror_hash: Vec<u8>,
}

#[derive(Debug)]
struct TagAccountInfo {
    username: String,
    password_md5_hash: [u8; 16],
}

#[derive(Debug)]
pub struct LoginAccount {
    username: String,
    password: String,
    hash_salt: [u8; 4],
}

const SERVICE_PACK_MAX_LEN: usize = 32;
const HOSTNAME_MAX_LEN: usize = 32;
const PASSWORD_MAX_LEN: usize = 16;
const USERNAME_MAX_LEN: usize = 16;
const LOGIN_PACKET_MAGIC_NUMBER: u16 = 0x0103u16;

macro_rules! validate_field_value_overflow {
    (
        $( $field:expr, $max_size:expr );*
    ) => {
        $(
            if $field.len() > $max_size {
                return Err(LoginError::FieldValueOverflow($field.len(), $max_size));
            }
        )*
    }
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

    #[inline]
    fn magic_number() -> u32 {
        9u32
    }

    #[inline]
    fn packet_length() -> usize {
        1 + // code 
        1 + // sequence size
        Self::sequence_length() +
        4 + // magic number
        12 // padding?
    }

    #[inline]
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
        validate_field_value_overflow!(self.service_pack, SERVICE_PACK_MAX_LEN);
        Ok(())
    }

    #[inline]
    fn packet_length() -> usize {
        4 + // packet_length
        Self::content_length()
    }

    #[inline]
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
        validate_field_value_overflow!(self.hostname, HOSTNAME_MAX_LEN);
        Ok(())
    }

    #[inline]
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

        let mut hostname_bytes = [0u8; HOSTNAME_MAX_LEN];
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
    fn new(password_ror_hash: Vec<u8>) -> Self {
        TagLDAPAuth { password_ror_hash: password_ror_hash }
    }

    fn validate(&self) -> LoginResult<()> {
        validate_field_value_overflow!(self.password_ror_hash, PASSWORD_MAX_LEN);
        Ok(())
    }

    fn packet_length(&self) -> usize {
        1 + // code
        1 + // password_ror_hash length
        self.password_ror_hash.len()
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut result = Vec::with_capacity(self.packet_length());
        result.push(0u8);
        result.push(self.password_ror_hash.len() as u8);
        result.extend(&self.password_ror_hash);

        Ok(result)
    }
}


impl LoginAccount {
    fn validate(&self) -> LoginResult<()> {
        validate_field_value_overflow!(
            self.username, USERNAME_MAX_LEN;
            self.password, PASSWORD_MAX_LEN
        );
        Ok(())
    }

    fn new(username: &str, password: &str, hash_salt: [u8; 4]) -> Self {
        let username = username.to_string();
        let password = password.to_string();

        LoginAccount {
            username: username,
            password: password,
            hash_salt: hash_salt,
        }
    }

    fn ror(md5_digest: [u8; 16], password: &str) -> LoginResult<Vec<u8>> {
        if password.len() > PASSWORD_MAX_LEN {
            return Err(LoginError::FieldValueOverflow(password.len(), PASSWORD_MAX_LEN));
        }

        let mut result = Vec::with_capacity(PASSWORD_MAX_LEN);
        for (i, c) in password.as_bytes().into_iter().enumerate() {
            let x: u8 = md5_digest[i] ^ c;
            result.push((x << 3) + (x >> 5));
        }
        Ok(result)
    }

    fn password_md5_hash(&self) -> [u8; 16] {
        let mut md5 = HasherBuilder::build(HasherType::MD5);
        md5.update(&LOGIN_PACKET_MAGIC_NUMBER.as_bytes_le());
        md5.update(&self.hash_salt);
        md5.update(self.password.as_bytes());

        let mut md5_digest = [0u8; 16];
        md5_digest.copy_from_slice(&md5.finish());
        md5_digest
    }

    fn password_ror_hash(&self) -> LoginResult<Vec<u8>> {
        Self::ror(self.password_md5_hash(), &self.password)
    }

    fn password_md5_hash_validator(&self) -> [u8; 16] {
        let mut md5 = HasherBuilder::build(HasherType::MD5);
        md5.update(&[1u8; 1]);
        md5.update(self.password.as_bytes());
        md5.update(&self.hash_salt);
        md5.update(&[0u8; 4]);

        let mut md5_digest = [0u8; 16];
        md5_digest.copy_from_slice(&md5.finish());
        md5_digest
    }

    fn tag_account_info(&self) -> LoginResult<TagAccountInfo> {
        try!(self.validate());
        Ok(TagAccountInfo::new(&self.username, self.password_md5_hash()))
    }
}

impl TagAccountInfo {
    fn new(username: &str, password_md5_hash: [u8; 16]) -> Self {
        let username = username.to_string();
        TagAccountInfo {
            username: username,
            password_md5_hash: password_md5_hash,
        }
    }

    fn validate(&self) -> LoginResult<()> {
        validate_field_value_overflow!(self.username, USERNAME_MAX_LEN);
        Ok(())
    }

    fn content_length(&self) -> usize {
        self.password_md5_hash.len() + self.username.len() + 4 // pading?
    }

    fn packet_length(&self) -> usize {
        2 + // attribute length
        self.content_length()
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut result = Vec::with_capacity(self.packet_length());
        result.extend((self.content_length() as u16).as_bytes_be());
        result.extend_from_slice(&self.password_md5_hash);
        result.extend_from_slice(self.username.as_bytes());
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

    let la = LoginAccount::new("usernameusername", "password", [1, 2, 3, 4]);
    assert_eq!(la.tag_account_info().unwrap().as_bytes().unwrap(),
               vec![0, 36, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102,
                    177, 222, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114, 110, 97,
                    109, 101]);

    // let la = TagLDAPAuth { password_ror_hash: vec![146, 26, 36, 122, 150] };
    // assert_eq!(la.as_bytes().unwrap(), vec![0, 5, 146, 26, 36, 122, 150]);
}

#[test]
fn test_password_hash() {
    assert_eq!(LoginAccount::ror([253u8; 16], "1234567812345678").unwrap(),
               vec![102, 126, 118, 78, 70, 94, 86, 46, 102, 126, 118, 78, 70, 94, 86, 46]);

    let la = LoginAccount::new("username", "password", [1, 2, 3, 4]);
    assert_eq!(la.password_md5_hash(),
               [174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102, 177, 222]);
    assert_eq!(la.password_md5_hash_validator(),
               [169, 80, 242, 73, 215, 59, 106, 173, 172, 242, 14, 27, 203, 29, 82, 153]);
}