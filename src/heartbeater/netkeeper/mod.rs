use openssl::crypto::{hash, symm};
use linked_hash_map::LinkedHashMap;

use utils::{current_timestamp, integer_to_bytes};

#[derive(Debug)]
pub struct Frame {
    type_name: String,
    content: LinkedHashMap<String, String>,
}

#[derive(Debug)]
pub struct Packet {
    magic_number: u16,
    version: u8,
    code: u16,
    frame: Frame,
}

pub struct PacketUtils;

#[derive(Debug)]
pub struct AES128Encrypter {
    key: String,
}

pub trait ContentEncrypter {
    fn pad(content_bytes: &[u8], length: usize) -> Vec<u8> {
        let pad_size = (length - content_bytes.len() % length) % length;
        let mut result: Vec<u8> = Vec::new();
        result.extend(content_bytes);
        for _ in 0..pad_size {
            result.push(pad_size as u8);
        }
        result
    }

    fn key_bytes(&self) -> &[u8];
    fn encrypt(&self, content_bytes: &[u8]) -> Vec<u8>;
    // fn decrypt(&self, &[u8]) -> Packet;
}

impl Frame {
    pub fn new(type_name: &str, content: Option<LinkedHashMap<String, String>>) -> Self {
        let content = match content {
            Some(content) => content,
            None => LinkedHashMap::new(),
        };
        Frame {
            type_name: type_name.to_string(),
            content: content,
        }
    }

    pub fn add(&mut self, name: &str, value: &str) {
        self.content.insert(name.to_string(), value.to_string());
    }
}

impl Frame {
    fn as_bytes(&self, join_with: Option<&str>) -> Vec<u8> {
        let mut linked_content: Vec<String> = Vec::new();
        let join_with = match join_with {
            Some(join_with) => join_with,
            None => "&",
        };
        linked_content.push(format!("TYPE={}", self.type_name));
        for (key, value) in self.content.iter() {
            linked_content.push(format!("{}={}", key, value));
        }
        linked_content.join(join_with).as_bytes().to_vec()
    }

    fn len(&self) -> u32 {
        self.as_bytes(None).len() as u32
    }
}

impl Packet {
    fn magic_number() -> u16 {
        0x5248 as u16
    }

    pub fn new(version: u8, code: u16, frame: Frame) -> Self {
        Packet {
            magic_number: Self::magic_number(),
            version: version,
            code: code,
            frame: frame,
        }
    }

    pub fn as_bytes<E>(&self, encrypter: &E) -> Vec<u8>
        where E: ContentEncrypter
    {
        let mut packet_bytes = Vec::new();
        {
            let version_str = self.version.to_string();
            let code_be = self.code.to_be();
            let enc_content = encrypter.encrypt(&self.frame.as_bytes(None));
            let enc_content_length_be = (enc_content.len() as u32).to_be();

            let magic_number_bytes = integer_to_bytes(&self.magic_number);
            let code_be_bytes = integer_to_bytes(&code_be);
            let enc_length_bytes = integer_to_bytes(&enc_content_length_be);

            packet_bytes.extend(magic_number_bytes);
            packet_bytes.extend(version_str.as_bytes());
            packet_bytes.extend(code_be_bytes);
            packet_bytes.extend(enc_length_bytes);
            packet_bytes.extend(enc_content);
        }
        packet_bytes
    }
}

impl PacketUtils {
    pub fn claculate_pin(timestamp: Option<u32>) -> String {
        let timestamp = match timestamp {
            Some(timestamp) => timestamp,
            None => current_timestamp(),
        };
        let salts = ["wanglei", "zhangni", "wangtianyou"];
        let mut hashed_bytes = [0; 16];
        let timestamp_hex = format!("{:08x}", timestamp);
        let timestamp_hex_chars: Vec<char> = timestamp_hex.chars().collect();
        {
            let mut md5 = hash::Hasher::new(hash::Type::MD5).unwrap();
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

impl AES128Encrypter {
    pub fn new(key: &str) -> Result<AES128Encrypter, &'static str> {
        if key.len() != 16 {
            return Err("In AES 128 mode, key must be 16 characters.");
        }
        Ok(AES128Encrypter { key: key.to_string() })
    }
}

impl ContentEncrypter for AES128Encrypter {
    fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }

    fn encrypt(&self, content_bytes: &[u8]) -> Vec<u8> {
        symm::encrypt(symm::Type::AES_128_ECB,
                      self.key_bytes(),
                      None,
                      content_bytes)
            .unwrap()
    }
}

#[test]
fn test_frame_concat() {
    let mut content = LinkedHashMap::new();
    content.insert("USER_NAME".to_string(), "05802278989@HYXY.XY".to_string());
    content.insert("PASSWORD".to_string(), "000000".to_string());
    let frame = Frame::new("HEARTBEAT", Some(content));
    let frame_bytes = frame.as_bytes(None);
    let frame_str = ::std::str::from_utf8(&frame_bytes).unwrap();

    assert_eq!(frame_str,
               "TYPE=HEARTBEAT&USER_NAME=05802278989@HYXY.XY&PASSWORD=000000");
    assert_eq!(frame.len(), 60);
}

#[test]
fn test_calc_heartbeat_pin() {
    let pin = PacketUtils::claculate_pin(Some(1472483020));
    assert_eq!(pin, "57c41bc45b493cfb5f5016074e987ef9cca96334");
}

#[test]
fn test_aes_128_ecb_encrypt() {
    let aes = AES128Encrypter::new("xlzjhrprotocol3x").unwrap();
    let plain_text = "TYPE=HEARTBEAT&USER_NAME=05802278989@HYXY.XY&PASSWORD=000000";
    let encrypted = aes.encrypt(&plain_text.as_bytes());
    let real_data = vec![66, 100, 164, 73, 167, 41, 222, 211, 188, 8, 14, 110, 252, 246, 121, 119,
                         79, 18, 254, 193, 72, 163, 54, 136, 248, 60, 221, 177, 221, 0, 13, 10,
                         146, 141, 142, 244, 89, 10, 176, 106, 162, 242, 204, 38, 73, 34, 55, 137,
                         180, 223, 253, 142, 43, 158, 209, 80, 100, 141, 11, 15, 146, 20, 207, 10];
    assert_eq!(encrypted, real_data);
}