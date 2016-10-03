use std::net::Ipv4Addr;

use rustc_serialize::hex::ToHex;
use openssl::crypto::hash::{Hasher, Type};

use utils::{current_timestamp, integer_to_bytes};

#[derive(Debug, Copy, Clone)]
pub enum AttributeValueType {
    TInteger = 0x0,
    TIPAddr = 0x1, // or Integer array?
    TString = 0x2,
}

#[derive(Debug, Copy, Clone)]
pub enum AttributeType {
    TAttribute = 0x0, // `TAttribute` is the first type of Attribute
    TUsername = 0x1,
    TClientIPAddr = 0x2,
    TClientVersion = 0x3,
    TClientType = 0x4,
    TOSVersion = 0x5,
    TOSLang = 0x6,
    TAdapterInfo = 0x7,
    TCPUInfo = 0x8,
    TMACAddr = 0x9,
    TMemorySize = 0xa,
    TDefaultExplorer = 0xb,
    TBubble = 0xc,
    TChannel = 0xd,
    TPlugin = 0xe,
    TUpdateVersion = 0xf,
    TUpdateDownloadURL = 0x10,
    TUpdateDescription = 0x11,
    TKeepAliveTime = 0x12,
    TKeepAliveInterval = 0x13,
    TKeepAliveData = 0x14,
}

#[derive(Debug)]
pub struct Attribute {
    typename: String,
    parent_id: AttributeType,
    attribute_id: AttributeType,
    value_type_id: AttributeValueType,
    data: Vec<u8>,
}

// not fully impleted attribute types
// and you can see all attribute types bellow
pub trait AttributeFactory {
    fn username(username: &str) -> Attribute;
    fn client_ip_address(ipaddress: Ipv4Addr) -> Attribute;
    fn client_type(client_type: &str) -> Attribute;
    fn client_version(client_version: &str) -> Attribute;
    fn os_version(version: &str) -> Attribute;
    fn os_language(language: &str) -> Attribute;
    fn cpu_info(cpu_info: &str) -> Attribute;
    fn mac_address(mac_address: &[u8; 4]) -> Attribute;
    fn memory_size(size: u32) -> Attribute;
    fn default_explorer(explorer: &str) -> Attribute;
    fn keepalive_data(data: &str) -> Attribute;
    fn keepalive_time(timestamp: u32) -> Attribute;

    fn calc_keepalive_data(timestamp: Option<u32>, last_data: Option<&str>) -> String;
}

pub trait AttributeVec {
    fn as_bytes(&self) -> Vec<u8>;
    fn length(&self) -> u16;
}

impl Attribute {
    pub fn new(typename: &str,
               parent_id: AttributeType,
               attribute_id: AttributeType,
               value_type_id: AttributeValueType,
               data: Vec<u8>)
               -> Self {
        Attribute {
            typename: typename.to_string(),
            parent_id: parent_id,
            attribute_id: attribute_id,
            value_type_id: value_type_id,
            data: data,
        }
    }

    fn data_length(&self) -> u16 {
        self.data.len() as u16
    }

    pub fn length(&self) -> u16 {
        self.data_length() + 3
    }

    pub fn as_bytes(&self) -> Box<Vec<u8>> {
        let mut attribute_bytes: Box<Vec<u8>> = Box::new(Vec::new());
        {
            let length_be = self.length().to_be();
            let length_bytes = integer_to_bytes(&length_be);
            let raw_attribute_id = self.attribute_id as u8;
            attribute_bytes.push(raw_attribute_id);
            attribute_bytes.extend(length_bytes);
            attribute_bytes.extend(self.data.iter());
        }
        attribute_bytes
    }
}

impl AttributeFactory for Attribute {
    fn username(username: &str) -> Attribute {
        Attribute::new("User-Name",
                       AttributeType::TAttribute,
                       AttributeType::TUsername,
                       AttributeValueType::TString,
                       username.as_bytes().to_vec())
    }

    fn client_ip_address(ipaddress: Ipv4Addr) -> Attribute {
        Attribute::new("Client-IP-Address",
                       AttributeType::TAttribute,
                       AttributeType::TClientIPAddr,
                       AttributeValueType::TIPAddr,
                       ipaddress.octets().to_vec())
    }

    fn client_type(client_type: &str) -> Attribute {
        Attribute::new("Client-Type",
                       AttributeType::TAttribute,
                       AttributeType::TClientType,
                       AttributeValueType::TString,
                       client_type.as_bytes().to_vec())
    }

    fn client_version(client_version: &str) -> Attribute {
        Attribute::new("Client-Version",
                       AttributeType::TAttribute,
                       AttributeType::TClientVersion,
                       AttributeValueType::TString,
                       client_version.as_bytes().to_vec())
    }

    fn os_version(version: &str) -> Attribute {
        Attribute::new("OS-Version",
                       AttributeType::TAttribute,
                       AttributeType::TOSVersion,
                       AttributeValueType::TString,
                       version.as_bytes().to_vec())
    }

    fn os_language(language: &str) -> Attribute {
        Attribute::new("OS-Lang",
                       AttributeType::TAttribute,
                       AttributeType::TOSLang,
                       AttributeValueType::TString,
                       language.as_bytes().to_vec())
    }

    fn cpu_info(cpu_info: &str) -> Attribute {
        Attribute::new("CPU-Info",
                       AttributeType::TAttribute,
                       AttributeType::TCPUInfo,
                       AttributeValueType::TString,
                       cpu_info.as_bytes().to_vec())
    }

    fn mac_address(mac_address: &[u8; 4]) -> Attribute {
        Attribute::new("MAC-Address",
                       AttributeType::TAttribute,
                       AttributeType::TMACAddr,
                       AttributeValueType::TString,
                       mac_address.to_vec())
    }

    fn memory_size(size: u32) -> Attribute {
        let size_be = size.to_be();
        let size_bytes = integer_to_bytes(&size_be);
        Attribute::new("Memory-Size",
                       AttributeType::TAttribute,
                       AttributeType::TMemorySize,
                       AttributeValueType::TInteger,
                       size_bytes.to_vec())
    }

    fn default_explorer(explorer: &str) -> Attribute {
        Attribute::new("Default-Explorer",
                       AttributeType::TAttribute,
                       AttributeType::TDefaultExplorer,
                       AttributeValueType::TString,
                       explorer.as_bytes().to_vec())
    }

    fn keepalive_data(data: &str) -> Attribute {
        Attribute::new("KeepAlive-Data",
                       AttributeType::TAttribute,
                       AttributeType::TKeepAliveData,
                       AttributeValueType::TString,
                       data.as_bytes().to_vec())
    }

    fn keepalive_time(timestamp: u32) -> Attribute {
        let timestamp_be = timestamp.to_be();
        let timestamp_bytes = integer_to_bytes(&timestamp_be);
        Attribute::new("KeepAlive-Time",
                       AttributeType::TAttribute,
                       AttributeType::TKeepAliveTime,
                       AttributeValueType::TInteger,
                       timestamp_bytes.to_vec())
    }

    fn calc_keepalive_data(timestamp: Option<u32>, last_data: Option<&str>) -> String {
        let timenow = match timestamp {
            Some(timestamp) => timestamp,
            None => current_timestamp(),
        };

        let salt = match last_data {
            Some(data) => data,
            None => "llwl",
        };

        let keepalive_data;
        {
            let mut md5 = Hasher::new(Type::MD5).unwrap();
            let timenow_be = timenow.to_be();
            let timenow_bytes = integer_to_bytes(&timenow_be);

            md5.update(timenow_bytes).unwrap();
            md5.update(salt.as_bytes()).unwrap();

            let hashed_bytes = md5.finish().unwrap();
            keepalive_data = hashed_bytes[..].to_hex();
        }
        keepalive_data
    }
}

impl AttributeVec for Vec<Attribute> {
    fn as_bytes(&self) -> Vec<u8> {
        let mut attributes_bytes: Vec<u8> = Vec::new();
        for attr in self {
            attributes_bytes.extend(*attr.as_bytes());
        }
        attributes_bytes
    }

    fn length(&self) -> u16 {
        self.iter().fold(0, |sum, attr| sum + attr.length()) as u16
    }
}

#[test]
fn test_attribute_gen_bytes() {
    let un = Attribute::username("05802278989@HYXY.XY");
    let assert_data: &[u8] = &[1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72, 89,
                               88, 89, 46, 88, 89];
    assert_eq!(&un.as_bytes()[..], assert_data);
}

#[test]
fn test_keepalive_data() {
    let kp_data1 = Attribute::calc_keepalive_data(Some(1472483020), None);
    let kp_data2 = Attribute::calc_keepalive_data(Some(1472483020),
                                                  Some("ffb0b2af94693fd1ba4c93e6b9aebd3f"));
    assert_eq!(kp_data1, "ffb0b2af94693fd1ba4c93e6b9aebd3f");
    assert_eq!(kp_data2, "d0dce2b013c8adfac646a2917fdab802");
}

// [[SNAttributeType alloc] initWithHuman:@"User-Name" :0x0 :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Client-IP-Address" :0x0 :0x2 :0x1];
// [[SNAttributeType alloc] initWithHuman:@"Client-Version" :0x0 :0x3 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Client-Type" :0x0 :0x4 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"OS-Version" :0x0 :0x5 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"OS-Lang" :0x0 :0x6 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Adapter-Info" :0x0 :0x7 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"CPU-Info" :0x0 :0x8 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"MAC-Address" :0x0 :0x9 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Memory-Size" :0x0 :0xa :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Default-Explorer" :0x0 :0xb :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble" :0x0 :0xc :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Id" :0xc :0x1 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Title" :0xc :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Context" :0xc :0x3 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Context-URL" :0xc :0x4 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Keep-Time" :0xc :0x5 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Delay-Time" :0xc :0x6 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Type" :0xc :0x7 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Channel" :0x0 :0xd :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Note" :0xd :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Context-URL" :0xd :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Context-URL" :0xd :0x3 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Order" :0xd :0x4 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Plugin" :0x0 :0xe :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Plugin-Name" :0xe :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Plugin-Configure-Data" :0xe :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Update-Version" :0x0 :0xf :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Update-Download-URL" :0x0 :0x10 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Update-Description" :0x0 :0x11 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"KeepAlive-Time" :0x0 :0x12 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"KeepAlive-Interval" :0x0 :0x13 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"KeepAlive-Data" :0x0 :0x14 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Process-Check-Interval" :0x0 :0x15 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Process-Check-List" :0x0 :0x16 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"RealTime-Bubble-Server" :0x0 :0x17 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"RealTime-Bubble-Interval" :0x0 :0x18 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Transmit-IP-List" :0x0 :0x19 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Number" :0x0 :0x1a :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Code" :0x0 :0x1b :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Error-String" :0x0 :0x1c :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Bind-Required" :0x0 :0x1d :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Plugin" :0x0 :0x1e :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Device-SN" :0x1e :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Device-Type" :0x1e :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Redirect-URL" :0x0 :0x1f :0x2];