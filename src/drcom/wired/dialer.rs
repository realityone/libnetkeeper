use std::{io, result};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::num::Wrapping;

use rand;
use rand::Rng;
use rustc_serialize::hex::ToHex;
use byteorder::{NetworkEndian, ByteOrder};

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
struct TagLDAPAuthInfo {
    password_ror_hash: Vec<u8>,
}

#[derive(Debug)]
struct TagAccountInfo {
    username: String,
    password_md5_hash: [u8; 16],
}

#[derive(Debug)]
struct TagAdapterInfo {
    counts: u8,
    password_md5_hash: [u8; 16],
    mac_address: [u8; 6],
    password_md5_hash_validator: [u8; 16],
    ipaddresses: [Ipv4Addr; 4],
}

#[derive(Debug)]
struct TagAuthExtraInfo {
    origin_data: Vec<u8>,
    mac_address: [u8; 6],
    option: u16,
}

#[derive(Debug)]
struct TagAuthVersionInfo {
    client_version: u8,
    dog_version: u8,
}

#[derive(Debug)]
pub struct LoginRequest {
    mac_address: [u8; 6],
    account_info: TagAccountInfo,
    control_check_status: u8,
    adapter_info: TagAdapterInfo,
    dog_flag: u8,
    host_info: TagHostInfo,
    auth_version_info: TagAuthVersionInfo,
    auto_logout: bool,
    broadcast_mode: bool,
    random: u16,
    ldap_auth_info: Option<TagLDAPAuthInfo>,
    auth_extra_options: Option<u16>,
}

#[derive(Debug)]
pub struct LoginAccount {
    username: String,
    password: String,
    hash_salt: [u8; 4],
    adapter_count: u8,
    mac_address: [u8; 6],
    ipaddresses: [Ipv4Addr; 4],
    dog_flag: u8,
    client_version: u8,
    dog_version: u8,
    control_check_status: u8,
    auto_logout: Option<bool>,
    broadcast_mode: Option<bool>,
    random: Option<u16>,
    ror_version: bool,
    auth_extra_options: Option<u16>,
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

macro_rules! configable_field {
    (
        $( $field:ident, $ty:ty );*
    ) => {
        $(
            pub fn $field(&mut self, value: $ty) -> &mut Self {
                self.$field = value;
                self
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
    fn attribute_length() -> usize {
        4 + // attribute_length
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

        let mut result = Vec::with_capacity(Self::attribute_length());
        result.extend((Self::attribute_length() as u32).as_bytes_le());
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
    fn attribute_length() -> usize {
        32 + // hostname
        4 + // dns_server
        4 + // dhcp_server
        4 + // backup_dns_server
        8 + // wins_ips
        TagOSVersionInfo::attribute_length()
    }

    pub fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut result = Vec::with_capacity(Self::attribute_length());

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

impl TagLDAPAuthInfo {
    fn new(password_ror_hash: &[u8]) -> Self {
        TagLDAPAuthInfo { password_ror_hash: password_ror_hash.to_vec() }
    }

    fn validate(&self) -> LoginResult<()> {
        validate_field_value_overflow!(self.password_ror_hash, PASSWORD_MAX_LEN);
        Ok(())
    }

    fn attribute_length(&self) -> usize {
        1 + // code
        1 + // password_ror_hash length
        self.password_ror_hash.len()
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut result = Vec::with_capacity(self.attribute_length());
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

    // #[allow(too_many_arguments)]
    // pub fn new(username: &str,
    //            password: &str,
    //            hash_salt: [u8; 4],
    //            ipaddresses: &[Ipv4Addr],
    //            mac_address: [u8; 6],
    //            dog_flag: u8,
    //            client_version: u8,
    //            dog_version: u8,
    //            adapter_count: Option<u8>,
    //            control_check_status: u8,
    //            auto_logout: Option<bool>,
    //            broadcast_mode: Option<bool>,
    //            random: Option<u16>,
    //            ror_version: Option<bool>,
    //            auth_extra_options: Option<u16>)
    //            -> Self {
    //     let username = username.to_string();
    //     let password = password.to_string();
    //     let adapter_count = adapter_count.unwrap_or(1);
    //     let mut fixed_ipaddresses = [Ipv4Addr::from(0x0); 4];
    //     for (i, ip) in ipaddresses.into_iter().take(4).enumerate() {
    //         fixed_ipaddresses[i] = *ip;
    //     }
    //     let ror_version = ror_version.unwrap_or(false);

    //     LoginAccount {
    //         username: username,
    //         password: password,
    //         hash_salt: hash_salt,
    //         adapter_count: adapter_count,
    //         mac_address: mac_address,
    //         ipaddresses: fixed_ipaddresses,
    //         dog_flag: dog_flag,
    //         client_version: client_version,
    //         dog_version: dog_version,
    //         control_check_status: control_check_status,
    //         auto_logout: auto_logout,
    //         broadcast_mode: broadcast_mode,
    //         random: random,
    //         ror_version: ror_version,
    //         auth_extra_options: auth_extra_options,
    //     }
    // }

    fn ror(md5_digest: &[u8; 16], password: &str) -> LoginResult<Vec<u8>> {
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
        Self::ror(&self.password_md5_hash(), &self.password)
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
        Ok(TagAccountInfo::new(&self.username, self.password_md5_hash()))
    }

    fn tag_auth_version(&self) -> LoginResult<TagAuthVersionInfo> {
        Ok(TagAuthVersionInfo::new(self.client_version, self.dog_version))
    }

    fn tag_ldap_auth_info(&self) -> LoginResult<TagLDAPAuthInfo> {
        Ok(TagLDAPAuthInfo::new(&try!(self.password_ror_hash())))
    }

    fn tag_adapter_info(&self) -> LoginResult<TagAdapterInfo> {
        Ok(TagAdapterInfo::new(self.adapter_count,
                               self.password_md5_hash(),
                               self.mac_address,
                               self.password_md5_hash_validator(),
                               self.ipaddresses))
    }

    fn tag_host_info(&self) -> LoginResult<TagHostInfo> {
        Ok(TagHostInfo::default())
    }

    pub fn login_request(&self) -> LoginResult<LoginRequest> {
        Ok(LoginRequest::new(self.mac_address,
                             try!(self.tag_account_info()),
                             try!(self.tag_adapter_info()),
                             self.dog_flag,
                             try!(self.tag_host_info()),
                             try!(self.tag_auth_version()),
                             self.control_check_status,
                             self.auto_logout,
                             self.broadcast_mode,
                             self.random,
                             if self.ror_version {
                                 Some(try!(self.tag_ldap_auth_info()))
                             } else {
                                 None
                             },
                             self.auth_extra_options))
    }

    pub fn create(username: &str, password: &str) -> Self {
        LoginAccount {
            username: username.to_string(),
            password: password.to_string(),
            hash_salt: [0u8; 4],
            adapter_count: 1,
            mac_address: [0, 0, 0, 0, 0, 0],
            ipaddresses: [Ipv4Addr::from(0x0); 4],
            dog_flag: 0x1,
            client_version: 0xa,
            dog_version: 0x0,
            control_check_status: 0x20,
            auto_logout: Some(false),
            broadcast_mode: Some(false),
            random: Some(0x13e9),
            ror_version: false,
            auth_extra_options: Some(0x0),
        }
    }

    pub fn ipaddresses(&mut self, value: &[Ipv4Addr]) -> &mut Self {
        let mut fixed_ipaddresses = [Ipv4Addr::from(0x0); 4];
        for (i, ip) in value.into_iter().take(4).enumerate() {
            fixed_ipaddresses[i] = *ip;
        }
        self.ipaddresses = fixed_ipaddresses;
        self
    }

    configable_field!(
        hash_salt, [u8; 4];
        adapter_count, u8;
        mac_address, [u8; 6];
    // ipaddresses, [Ipv4Addr; 4];
        dog_flag, u8;
        client_version, u8;
        dog_version, u8;
        control_check_status, u8;
        auto_logout, Option<bool>;
        broadcast_mode, Option<bool>;
        random, Option<u16>;
        ror_version, bool;
        auth_extra_options, Option<u16>
        );
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

    fn attribute_length(&self) -> usize {
        2 + // attribute length
        self.content_length()
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        try!(self.validate());

        let mut result = Vec::with_capacity(self.attribute_length());
        result.extend((self.content_length() as u16).as_bytes_be());
        result.extend_from_slice(&self.password_md5_hash);
        result.extend_from_slice(self.username.as_bytes());
        Ok(result)
    }
}

impl TagAdapterInfo {
    fn new(counts: u8,
           password_md5_hash: [u8; 16],
           mac_address: [u8; 6],
           password_md5_hash_validator: [u8; 16],
           ipaddresses: [Ipv4Addr; 4])
           -> Self {
        TagAdapterInfo {
            counts: counts,
            password_md5_hash: password_md5_hash,
            mac_address: mac_address,
            password_md5_hash_validator: password_md5_hash_validator,
            ipaddresses: ipaddresses,
        }
    }

    fn attribute_length() -> usize {
        1 + // adapter counts
        6 + // hashed mac address
        16 + // password_md5_hash_validator
        4 * 4 // ipaddress * 4
    }

    fn hash_mac_address(mac_address: &[u8; 6], password_md5_hash: &[u8; 16]) -> [u8; 6] {
        let prefix = &password_md5_hash[..6];
        let prefix_hex_u64 = u64::from_str_radix(&prefix.to_hex(), 16).unwrap();
        let mac_address_u64 = NetworkEndian::read_uint(mac_address, 6);

        let mut result = [0u8; 6];
        result.clone_from_slice(&((prefix_hex_u64 ^ mac_address_u64) as u64).as_bytes_be()[2..8]);
        result
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        let mut result = Vec::with_capacity(Self::attribute_length());
        result.push(self.counts);
        result.extend_from_slice(&Self::hash_mac_address(&self.mac_address, &self.password_md5_hash));
        result.extend_from_slice(&self.password_md5_hash_validator);

        {
            let mut specified_ip_count = 0u8;
            let mut ipaddress_bytes = vec![0u8; self.ipaddresses.len() * 4];
            for (i, ip) in self.ipaddresses.iter().enumerate() {
                if !ip.is_unspecified() {
                    specified_ip_count += 1;
                    ipaddress_bytes[i * 4..i * 4 + 4].copy_from_slice(&ip.as_bytes());
                }
            }
            result.push(specified_ip_count);
            result.extend(ipaddress_bytes);
        }
        Ok(result)
    }
}

impl TagAuthVersionInfo {
    fn new(client_version: u8, dog_version: u8) -> Self {
        TagAuthVersionInfo {
            client_version: client_version,
            dog_version: dog_version,
        }
    }

    fn attribute_length() -> usize {
        1 + // client version
        1 // dog version
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        let mut result = Vec::with_capacity(Self::attribute_length());
        result.push(self.client_version);
        result.push(self.dog_version);
        Ok(result)
    }
}


impl TagAuthExtraInfo {
    fn caculate_check_sum(data: &[u8], initial: Option<u32>) -> u32 {
        let mut result = Wrapping(initial.unwrap_or(1234u32));
        for chunk in data.chunks(4) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.extend(vec![0u8; 4 - chunk.len()]);
            chunk_vec.reverse();
            result ^= Wrapping(u32::from_str_radix(&chunk_vec.to_hex(), 16).unwrap());
        }
        result *= Wrapping(1968);
        result.0
    }

    fn new(origin_data: &[u8], mac_address: [u8; 6], option: Option<u16>) -> Self {
        let option = option.unwrap_or(0u16);
        TagAuthExtraInfo {
            origin_data: origin_data.to_vec(),
            option: option,
            mac_address: mac_address,
        }
    }

    #[inline]
    fn attribute_length() -> usize {
        1 + // code
        1 + // content length
        Self::content_length()
    }

    #[inline]
    fn content_length() -> usize {
        4 + // checksum bytes
        2 + // option bytes
        6 // mac_address
    }

    #[inline]
    fn code() -> u8 {
        2u8
    }

    fn check_sum(&self) -> u32 {
        const CHECK_SUM_PADDING_BYTES: [u8; 6] = [0x1, 0x26, 0x07, 0x11, 0x00, 0x00];
        let mut to_check_data = self.origin_data.clone();
        to_check_data.push(Self::code());
        to_check_data.push(Self::content_length() as u8);
        to_check_data.extend_from_slice(&CHECK_SUM_PADDING_BYTES);
        to_check_data.extend_from_slice(&self.mac_address);
        Self::caculate_check_sum(&to_check_data, None)
    }

    fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        let mut result = Vec::with_capacity(Self::attribute_length());
        result.push(Self::code());
        result.push(Self::content_length() as u8);
        result.extend(self.check_sum().as_bytes_le());
        // padding?
        result.extend_from_slice(&[0, 0]);
        result.extend_from_slice(&self.mac_address);

        Ok(result)
    }
}

impl LoginRequest {
    #[allow(too_many_arguments)]
    fn new(mac_address: [u8; 6],
           account_info: TagAccountInfo,
           adapter_info: TagAdapterInfo,
           dog_flag: u8,
           host_info: TagHostInfo,
           auth_version_info: TagAuthVersionInfo,
           control_check_status: u8,
           auto_logout: Option<bool>,
           broadcast_mode: Option<bool>,
           random: Option<u16>,
           ldap_auth_info: Option<TagLDAPAuthInfo>,
           auth_extra_options: Option<u16>)
           -> Self {
        let auto_logout = auto_logout.unwrap_or(false);
        let broadcast_mode = broadcast_mode.unwrap_or(false);
        let random = random.unwrap_or(0x13e9u16);
        LoginRequest {
            mac_address: mac_address,
            account_info: account_info,
            control_check_status: control_check_status,
            adapter_info: adapter_info,
            dog_flag: dog_flag,
            host_info: host_info,
            auth_version_info: auth_version_info,
            auto_logout: auto_logout,
            broadcast_mode: broadcast_mode,
            random: random,
            ldap_auth_info: ldap_auth_info,
            auth_extra_options: auth_extra_options,
        }
    }

    fn packet_length(&self) -> usize {
        2 + // magic number
        self.account_info.attribute_length() + 
        20 + // padding?
        1 + // control_check_status
        TagAdapterInfo::attribute_length() + 
        match self.ldap_auth_info {
            Some(ref l) => l.attribute_length(),
            None => 0,
        } +
        TagAuthExtraInfo::attribute_length() + 
        1 + // auto logout
        1 + // broadcast mode
        2 // random number
    }

    pub fn as_bytes(&self) -> LoginResult<Vec<u8>> {
        let mut result = Vec::with_capacity(self.packet_length());

        // Phase 1
        {
            result.extend(LOGIN_PACKET_MAGIC_NUMBER.as_bytes_le());
            result.extend(try!(self.account_info.as_bytes()));
            // padding?
            result.extend_from_slice(&[0u8; 20]);
            result.push(self.control_check_status);
            result.extend(try!(self.adapter_info.as_bytes()));
        }

        // Phase 2
        {
            const PHASE_TWO_HASH_SALT: [u8; 4] = [0x14, 0x00, 0x07, 0x0b];
            let mut md5 = HasherBuilder::build(HasherType::MD5);
            md5.update(&result);
            md5.update(&PHASE_TWO_HASH_SALT);
            let md5_digest = md5.finish();
            result.extend_from_slice(&md5_digest[..8]);
        }

        // Phase 3
        {
            result.push(self.dog_flag);
            // padding?
            result.extend_from_slice(&[0u8; 4]);
            result.extend(try!(self.host_info.as_bytes()));
            result.extend(try!(self.auth_version_info.as_bytes()));
            if let Some(ref l) = self.ldap_auth_info {
                result.extend(try!(l.as_bytes()))
            };
        }

        // Phase 4
        {
            let origin_data = result.clone();
            let auth_extra_info =
                TagAuthExtraInfo::new(&origin_data, self.mac_address, self.auth_extra_options);
            result.extend(try!(auth_extra_info.as_bytes()));
        }

        // Phase 5
        {
            result.push(self.auto_logout as u8);
            result.push(self.broadcast_mode as u8);
            result.extend(self.random.as_bytes_le());
        }

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

    let mut la = LoginAccount::create("usernameusername", "password");
    la.hash_salt([1, 2, 3, 4])
        .ipaddresses(&[Ipv4Addr::from_str("10.30.22.17").unwrap()])
        .mac_address([0xb8, 0x88, 0xe3, 0x05, 0x16, 0x80])
        .dog_flag(0x1)
        .client_version(0xa)
        .dog_version(0x0)
        .adapter_count(0x1)
        .control_check_status(0x20)
        .auto_logout(Some(false))
        .broadcast_mode(Some(false))
        .random(Some(0x13e9))
        .ror_version(false)
        .auth_extra_options(Some(0x0));
    assert_eq!(la.tag_account_info().unwrap().as_bytes().unwrap(),
               vec![0, 36, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102,
                    177, 222, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114, 110, 97,
                    109, 101]);
    assert_eq!(la.tag_ldap_auth_info().unwrap().as_bytes().unwrap(),
               vec![0, 8, 246, 118, 31, 45, 254, 12, 137, 112]);
    assert_eq!(la.tag_adapter_info().unwrap().as_bytes().unwrap(),
               vec![1, 22, 39, 115, 211, 190, 110, 169, 80, 242, 73, 215, 59, 106, 173, 172, 242,
                    14, 27, 203, 29, 82, 153, 1, 10, 30, 22, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0]);
}

#[test]
fn test_password_hash() {
    assert_eq!(LoginAccount::ror(&[253u8; 16], "1234567812345678").unwrap(),
               vec![102, 126, 118, 78, 70, 94, 86, 46, 102, 126, 118, 78, 70, 94, 86, 46]);

    let mut la = LoginAccount::create("usernameusername", "password");
    la.hash_salt([1, 2, 3, 4])
        .ipaddresses(&[Ipv4Addr::from_str("10.30.22.17").unwrap()])
        .mac_address([0xb8, 0x88, 0xe3, 0x05, 0x16, 0x80])
        .dog_flag(0x1)
        .client_version(0xa)
        .dog_version(0x0)
        .adapter_count(0x1)
        .control_check_status(0x20)
        .auto_logout(Some(false))
        .broadcast_mode(Some(false))
        .random(Some(0x13e9))
        .ror_version(false)
        .auth_extra_options(Some(0x0));
    assert_eq!(la.password_md5_hash(),
               [174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102, 177, 222]);
    assert_eq!(la.password_md5_hash_validator(),
               [169, 80, 242, 73, 215, 59, 106, 173, 172, 242, 14, 27, 203, 29, 82, 153]);

    assert_eq!(TagAdapterInfo::hash_mac_address(&[6, 5, 4, 3, 2, 1],
                                                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                                                  15, 16]),
               [7, 7, 7, 7, 7, 7]);
}

#[test]
fn test_data_check_sum() {
    let data: [u8; 326] =
        [3, 1, 0, 36, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102, 177, 222,
         117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114, 110, 97, 109, 101, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 22, 39, 115, 211, 190, 110, 169,
         80, 242, 73, 215, 59, 106, 173, 172, 242, 14, 27, 203, 29, 82, 153, 1, 10, 30, 22, 17, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 84, 80, 240, 75, 157, 179, 232, 1, 0, 0, 0, 0, 76,
         73, 89, 85, 65, 78, 89, 85, 65, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 0,
         0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40, 10, 0, 0, 2, 0, 0, 0, 56, 48, 56, 57, 68, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         10, 0, 2, 12, 1, 38, 7, 17, 0, 0, 184, 136, 227, 5, 22, 128];
    assert_eq!(TagAuthExtraInfo::caculate_check_sum(&data, None),
               3581815520);
}