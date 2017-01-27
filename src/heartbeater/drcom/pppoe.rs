use openssl::crypto::hash::{Hasher, Type};
use byteorder::{NativeEndian, ByteOrder};

#[derive(Debug)]
pub struct Heartbeater {
    count: u64,
}

#[derive(Debug)]
pub enum CRCHasherType {
    NONE,
    MD5,
    MD4,
    SHA1,
}

trait CRCHasher {
    fn from_mode(mode: u8) -> Self;
    fn hasher(&self) -> Hasher;
    fn retain_postions(&self) -> Vec<usize>;

    fn hash(&self, bytes: &[u8]) -> Vec<u8> {
        let mut hasher = self.hasher();
        let retain_postions = self.retain_postions();

        hasher.update(bytes).unwrap();
        let hashed_bytes = hasher.finish().unwrap();

        let mut hashed = Vec::<u8>::with_capacity(retain_postions.len());
        for i in retain_postions {
            if i > hashed_bytes.len() {
                continue;
            }
            hashed.push(hashed_bytes[i]);
        }
        hashed
    }
}

impl CRCHasher for CRCHasherType {
    fn from_mode(mode: u8) -> Self {
        match mode {
            3 => CRCHasherType::SHA1,

            _ => CRCHasherType::MD5,
        }
    }

    fn hasher(&self) -> Hasher {
        match *self {
            CRCHasherType::SHA1 => Hasher::new(Type::SHA1).unwrap(),

            // default md5 for now
            _ => Hasher::new(Type::MD5).unwrap(),
        }
    }

    fn retain_postions(&self) -> Vec<usize> {
        match *self {
            CRCHasherType::SHA1 => vec![2, 3, 9, 10, 5, 6, 15, 16],

            _ => vec![2, 3, 8, 9, 5, 6, 13, 14],
        }
    }
}

fn generate_crc_hash(bytes: &[u8], mode: u8) -> Vec<u8> {
    let crc_hasher = CRCHasherType::from_mode(mode);
    crc_hasher.hash(bytes)
}

fn calculate_drcom_crc32(bytes: &[u8], initial: Option<u32>) -> Result<u32, &'static str> {
    if bytes.len() % 4 != 0 {
        return Err("bytes length is invalid");
    }

    let mut result = match initial {
        Some(initial) => initial,
        None => 0,
    };
    for c in 0..(bytes.len() / 4usize) {
        result ^= NativeEndian::read_u32(&bytes[c * 4..c * 4 + 4]);
    }
    Ok(result)
}

#[test]
fn test_generate_crc_hash() {
    let crc_hash_md5 = generate_crc_hash(b"1234567890", 1);
    let crc_hash_sha1 = generate_crc_hash(b"1234567890", 3);
    assert_eq!(crc_hash_md5, vec![241, 252, 155, 176, 45, 19, 56, 161]);
    assert_eq!(crc_hash_sha1, vec![7, 172, 175, 195, 79, 84, 246, 202]);
}

#[test]
fn test_calculate_drcom_crc32() {
    let crc32 = calculate_drcom_crc32(b"1234567899999999", None).unwrap();
    assert_eq!(crc32, 201589764);
}