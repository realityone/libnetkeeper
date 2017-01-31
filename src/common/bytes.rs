use std::net::Ipv4Addr;

use byteorder::{NetworkEndian, NativeEndian, ByteOrder};

pub trait BytesAble {
    fn as_bytes(&self) -> Vec<u8>;
}

pub trait BytesAbleNum {
    fn as_bytes_be(&self) -> Vec<u8>;
    fn as_bytes_le(&self) -> Vec<u8>;
}

impl BytesAble for Ipv4Addr {
    fn as_bytes(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

impl BytesAble for String {
    fn as_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl BytesAble for u32 {
    fn as_bytes(&self) -> Vec<u8> {
        self.as_bytes_be().to_vec()
    }
}

impl BytesAble for u16 {
    fn as_bytes(&self) -> Vec<u8> {
        self.as_bytes_be().to_vec()
    }
}

impl BytesAbleNum for u32 {
    fn as_bytes_be(&self) -> Vec<u8> {
        let mut bytes = [0u8; 4];
        NetworkEndian::write_u32(&mut bytes, *self);
        bytes.to_vec()
    }

    fn as_bytes_le(&self) -> Vec<u8> {
        let mut bytes = [0u8; 4];
        NativeEndian::write_u32(&mut bytes, *self);
        bytes.to_vec()
    }
}

impl BytesAbleNum for u16 {
    fn as_bytes_be(&self) -> Vec<u8> {
        let mut bytes = [0u8; 2];
        NetworkEndian::write_u16(&mut bytes, *self);
        bytes.to_vec()
    }

    fn as_bytes_le(&self) -> Vec<u8> {
        let mut bytes = [0u8; 2];
        NativeEndian::write_u16(&mut bytes, *self);
        bytes.to_vec()
    }
}