use std::slice;
use std::mem;
use std::net::Ipv4Addr;

use rustc_serialize::hex::ToHex;
use openssl::crypto::hash::{Hasher, Type};

use utils::current_timestamp;

#[derive(Debug)]
struct Attribute {
    typename: String,
    parent_id: u8,
    type_id: u8,
    value_type_id: u8,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Username {
    username: String,
}

#[derive(Debug)]
struct ClientIPAddress {
    ipaddress: Ipv4Addr,
}

#[derive(Debug)]
struct ClientVersion {
    version: String,
}

#[derive(Debug)]
struct ClientType {
    client_type: String,
}

#[derive(Debug)]
struct OSVersion {
    version: String,
}

#[derive(Debug)]
struct OSLanguage {
    language: String,
}

#[derive(Debug)]
struct CPUInfo {
    cpu_info: String,
}

#[derive(Debug)]
struct MacAddress {
    mac_address: String,
}

#[derive(Debug)]
struct MemorySize {
    size: u32,
}

#[derive(Debug)]
struct DefaultExplorer {
    explorer: String,
}

#[derive(Debug)]
struct KeepAliveData {
    data: String,
}

#[derive(Debug)]
struct KeepAliveTime {
    timestamp: u32,
}

trait AttributeLoader {
    fn as_attribute(&self) -> Attribute;
}

impl Attribute {
    pub fn new(typename: &str,
               parent_id: u8,
               type_id: u8,
               value_type_id: u8,
               data: Vec<u8>)
               -> Self {
        Attribute {
            typename: typename.to_string(),
            parent_id: parent_id,
            type_id: type_id,
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
            let length_bytes: &[u8];
            unsafe {
                length_bytes =
                    slice::from_raw_parts::<u8>((&self.length().to_be() as *const u16) as *const u8,
                                                mem::size_of::<u16>());
            }
            attribute_bytes.push(self.parent_id);
            attribute_bytes.extend(length_bytes);
            attribute_bytes.extend(&self.data);
        }
        attribute_bytes
    }
}

impl AttributeLoader for Username {
    fn as_attribute(&self) -> Attribute {
        Attribute::new("User-Name",
                       0x1,
                       0x0,
                       0x2,
                       self.username.as_bytes().to_vec())
    }
}

impl KeepAliveData {
    pub fn calc_data(timestamp: Option<i32>, last_data: Option<String>) -> Self {
        let timenow = match timestamp {
            Some(timestamp) => timestamp,
            None => current_timestamp(),
        };

        let salt = match last_data {
            Some(data) => data,
            None => "llwl".to_string(),
        };

        let keepalive_data;
        {
            let mut md5 = Hasher::new(Type::MD5).unwrap();
            let timenow_bytes: &[u8];
            unsafe {
                timenow_bytes =
                    slice::from_raw_parts::<u8>((&timenow.to_be() as *const i32) as *const u8,
                                                mem::size_of::<i32>());
            }

            md5.update(timenow_bytes).unwrap();
            md5.update(salt.as_bytes()).unwrap();

            let hashed_bytes = md5.finish().unwrap();
            keepalive_data = hashed_bytes[..].to_hex();
        }
        KeepAliveData { data: keepalive_data }
    }
}

impl AttributeLoader for KeepAliveData {
    fn as_attribute(&self) -> Attribute {
        Attribute::new("KeepAlive-Data",
                       0x14,
                       0x0,
                       0x2,
                       self.data.as_bytes().to_vec())
    }
}

#[test]
fn test_attribute_gen_bytes() {
    let un = Attribute::new("User-Name",
                            0x1,
                            0x0,
                            0x2,
                            "05802278989@HYXY.XY".as_bytes().to_vec());
    let assert_data: &[u8] = &[1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72, 89,
                               88, 89, 46, 88, 89];
    assert_eq!(&un.as_bytes()[..], assert_data);
}

#[test]
fn test_keepalive_data() {
    let kp_data1 = KeepAliveData::calc_data(Some(1472483020), None);
    let kp_data2 = KeepAliveData::calc_data(Some(1472483020), Some("ffb0b2af94693fd1ba4c93e6b9aebd3f".to_string()));
    assert_eq!(kp_data1.data, "ffb0b2af94693fd1ba4c93e6b9aebd3f");
    assert_eq!(kp_data2.data, "d0dce2b013c8adfac646a2917fdab802");
}
