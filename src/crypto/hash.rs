use md4;
use md4::Digest as Md4Digest;
use md5;
use sha1;

#[derive(Debug, Clone, Copy)]
pub enum HasherType {
    MD4,
    MD5,
    SHA1,
}

pub struct HasherBuilder;

pub trait Hasher {
    fn update(&mut self, bytes: &[u8]);
    fn finish(&mut self) -> Vec<u8>;
}

struct MD4(md4::Md4);

struct MD5(md5::Context);

struct SHA1(sha1::Sha1);

impl MD4 {
    fn new() -> Self {
        MD4(md4::Md4::new())
    }
}

impl Hasher for MD4 {
    fn update(&mut self, bytes: &[u8]) {
        self.0.input(bytes)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.0.result().to_vec()
    }
}

impl MD5 {
    fn new() -> Self {
        MD5(md5::Context::new())
    }
}

impl Hasher for MD5 {
    fn update(&mut self, bytes: &[u8]) {
        self.0.consume(bytes)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.0.compute().to_vec()
    }
}

impl SHA1 {
    fn new() -> Self {
        SHA1(sha1::Sha1::new())
    }
}

impl Hasher for SHA1 {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.0.digest().bytes().to_vec()
    }
}

impl HasherBuilder {
    pub fn build(type_: HasherType) -> Box<Hasher> {
        match type_ {
            HasherType::MD4 => Box::new(MD4::new()) as Box<Hasher>,
            HasherType::MD5 => Box::new(MD5::new()) as Box<Hasher>,
            HasherType::SHA1 => Box::new(SHA1::new()) as Box<Hasher>,
        }
    }
}

fn hash_bytes(bytes: &[u8], type_: HasherType) -> Vec<u8> {
    let mut hasher = HasherBuilder::build(type_);
    hasher.update(bytes);
    hasher.finish()
}

#[test]
fn test_hash_bytes() {
    assert_eq!(
        vec![249, 212, 4, 157, 214, 164, 220, 53, 212, 14, 82, 101, 149, 75, 42, 70,],
        hash_bytes(b"admin", HasherType::MD4)
    );
    assert_eq!(
        vec![33, 35, 47, 41, 122, 87, 165, 167, 67, 137, 74, 14, 74, 128, 31, 195,],
        hash_bytes(b"admin", HasherType::MD5)
    );
    assert_eq!(
        vec![
            208, 51, 226, 42, 227, 72, 174, 181, 102, 15, 194, 20, 10, 236, 53, 133, 12, 77, 169,
            151,
        ],
        hash_bytes(b"admin", HasherType::SHA1)
    );
}
