use rust_crypto::{md5, sha1};
use rust_crypto::digest::Digest;

#[derive(Debug)]
pub enum HasherTypes {
    MD5,
    SHA1,
}

pub struct HasherBuilder;

pub trait Hasher {
    fn update(&mut self, bytes: &[u8]);
    fn finish(&mut self) -> Vec<u8>;
}

struct MD5(md5::Md5);
struct SHA1(sha1::Sha1);

macro_rules! impl_for_rust_crypto_digest{
    ($digest:path, $hasher:ident) => {
        impl $hasher {
            fn new() -> Self {
                $hasher(<$digest>::new())
            }
        }

        impl Hasher for $hasher {
            fn update(&mut self, bytes: &[u8]) {
                self.0.input(bytes)
            }

            fn finish(&mut self) -> Vec<u8> {
                let mut result = vec![0u8; self.0.output_bytes()];
                self.0.result(result.as_mut_slice());
                result
            }
        }
    };
}

impl_for_rust_crypto_digest!(md5::Md5, MD5);
impl_for_rust_crypto_digest!(sha1::Sha1, SHA1);

impl HasherBuilder {
    pub fn build(type_: HasherTypes) -> Box<Hasher> {
        match type_ {
            HasherTypes::MD5 => Box::new(MD5::new()) as Box<Hasher>,
            HasherTypes::SHA1 => Box::new(SHA1::new()) as Box<Hasher>,
        }
    }
}

fn hash_bytes(bytes: &[u8], type_: HasherTypes) -> Vec<u8> {
    let mut hasher = HasherBuilder::build(type_);
    hasher.update(bytes);
    hasher.finish()
}