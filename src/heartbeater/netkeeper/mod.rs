use openssl::crypto::hash::{Hasher, Type};
use linked_hash_map::LinkedHashMap;

use utils::current_timestamp;

#[derive(Debug)]
struct Frame {
    type_name: String,
    content: LinkedHashMap<String, String>,
}

#[derive(Debug)]
struct Packet {
    magic_number: u16,
    version: String,
    code: u16,
    frame: Frame,
}

trait NetkeeperFrame {
    fn as_bytes(&self) -> Vec<u8>;
    fn len(&self) -> u32 {
        self.as_bytes().len() as u32
    }
}

trait HeartbeatFactory {
    // fn heartbeat() -> Packet;
    fn clac_pin(timestamp: Option<u32>) -> String;
}


impl Frame {
    fn new(type_name: &str, content: Option<LinkedHashMap<String, String>>) -> Self {
        let content = match content {
            Some(content) => content,
            None => LinkedHashMap::new(),
        };
        Frame {
            type_name: type_name.to_string(),
            content: content,
        }
    }
}

impl NetkeeperFrame for Frame {
    fn as_bytes(&self) -> Vec<u8> {
        let mut linked_content: Vec<String> = Vec::new();
        linked_content.push(format!("TYPE={}", self.type_name));
        for (key, value) in self.content.iter() {
            linked_content.push(format!("{}={}", key, value));
        }
        linked_content.join("&").as_bytes().to_vec()
    }
}

impl Packet {
    fn magic_number() -> u16 {
        0x4852 as u16
    }

    fn new(version: &str, code: u16, frame: Frame) -> Self {
        Packet {
            magic_number: Self::magic_number(),
            version: version.to_string(),
            code: code,
            frame: frame,
        }
    }
}

impl HeartbeatFactory for Packet {
    fn clac_pin(timestamp: Option<u32>) -> String {
        let timestamp = match timestamp {
            Some(timestamp) => timestamp,
            None => current_timestamp(),
        };
        let salts = ["wanglei", "zhangni", "wangtianyou"];
        let mut hashed_bytes = [0; 16];
        let timestamp_hex = format!("{:08x}", timestamp);
        let timestamp_hex_chars: Vec<char> = timestamp_hex.chars().collect();
        {
            let mut md5 = Hasher::new(Type::MD5).unwrap();
            let salt = salts[(timestamp % 3) as usize];

            md5.update(timestamp_hex.as_bytes()).unwrap();
            md5.update(salt.as_bytes()).unwrap();
            hashed_bytes.clone_from_slice(&md5.finish().unwrap());
        }

        format!("{}{}{:02x}{:02x}{}{}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{}{}{:02x}{:\
                 02x}{:02x}{}{}{:02x}{:02x}{:02x}",
                timestamp_hex_chars[0],
                timestamp_hex_chars[1],
                hashed_bytes[0],
                hashed_bytes[1],
                timestamp_hex_chars[2],
                timestamp_hex_chars[3],
                hashed_bytes[2],
                hashed_bytes[3],
                hashed_bytes[4],
                hashed_bytes[5],
                hashed_bytes[6],
                hashed_bytes[7],
                hashed_bytes[8],
                hashed_bytes[9],
                timestamp_hex_chars[4],
                timestamp_hex_chars[5],
                hashed_bytes[10],
                hashed_bytes[11],
                hashed_bytes[12],
                timestamp_hex_chars[6],
                timestamp_hex_chars[7],
                hashed_bytes[13],
                hashed_bytes[14],
                hashed_bytes[15])
    }
}

#[test]
fn test_frame_concat() {
    let mut content = LinkedHashMap::new();
    content.insert("USER_NAME".to_string(), "05802278989@HYXY.XY".to_string());
    content.insert("PASSWORD".to_string(), "000000".to_string());
    let frame = Frame::new("HEARTBEAT", Some(content));
    let frame_bytes = frame.as_bytes();
    let frame_str = ::std::str::from_utf8(&frame_bytes).unwrap();

    assert_eq!(frame_str,
               "TYPE=HEARTBEAT&USER_NAME=05802278989@HYXY.XY&PASSWORD=000000");
    assert_eq!(frame.len(), 60);
}

#[test]
fn test_calc_heartbeat_pin() {
    let pin = Packet::clac_pin(Some(1472483020));
    assert_eq!(pin, "57c41bc45b493cfb5f5016074e987ef9cca96334");
}