use std::str;
use std::slice;

use dialer::Dialer;
use utils::{current_timestamp, any_to_bytes};

#[derive(Debug)]
pub enum Configuration {
    Hainan,
}

#[derive(Debug)]
pub struct SingleNetDialer {
    share_key: String,
    secret_key: String,
    key_table: String,
}

impl SingleNetDialer {
    pub fn new(share_key: &str, secret_key: &str, key_table: &str) -> Self {
        SingleNetDialer {
            share_key: share_key.to_string(),
            secret_key: secret_key.to_string(),
            key_table: key_table.to_string(),
        }
    }

    pub fn encrypt_account(&self, username: &str, timestamp: Option<u32>) -> String {
        let username = username.to_uppercase();
        let timenow = timestamp.unwrap_or_else(current_timestamp);

        let first_hash: u16;
        {
            let timenow_be = timenow.to_be();
            let timenow_bytes = any_to_bytes(&timenow_be);

            let mut hash_data: Vec<u8> = Vec::new();
            hash_data.extend_from_slice(timenow_bytes);
            hash_data.extend(self.share_key.as_bytes());
            hash_data.extend(username.split('@').nth(0).unwrap().as_bytes());
            first_hash = Self::calc_hash(&hash_data)
        }

        let second_hash: u16;
        {
            let first_hash_be = first_hash.to_be();
            let first_hash_bytes = any_to_bytes(&first_hash_be);

            let mut hash_data: Vec<u8> = Vec::new();
            hash_data.extend_from_slice(first_hash_bytes);
            hash_data.extend(self.secret_key.as_bytes());
            second_hash = Self::calc_hash(&hash_data);
        }

        let mut scheduled_table: Vec<u8> = Vec::with_capacity(8);
        {
            let timenow_high = (timenow >> 16) as u16;
            let timenow_low = (timenow & 0xFFFF) as u16;
            let timenow_high_be = timenow_high.to_be();
            let timenow_low_be = timenow_low.to_be();

            let timenow_high_bytes = any_to_bytes(&timenow_high_be);
            let timenow_low_bytes = any_to_bytes(&timenow_low_be);
            let first_hash_bytes = any_to_bytes(&first_hash);
            let second_hash_bytes = any_to_bytes(&second_hash);

            scheduled_table.extend_from_slice(timenow_high_bytes);
            scheduled_table.extend_from_slice(first_hash_bytes);
            scheduled_table.extend_from_slice(timenow_low_bytes);
            scheduled_table.extend_from_slice(second_hash_bytes);
        }

        let mut vectors: [u8; 12] = [0; 12];
        for i in 0..4 {
            let j = 2 * i + 1;
            let k = 3 * i + 1;
            vectors[k - 1] = scheduled_table[j - 1] >> 0x3 & 0x1F;
            vectors[k] = ((scheduled_table[j - 1] & 0x7) << 0x2) |
                         (scheduled_table[j] >> 0x6 & 0x3);
            vectors[k + 1] = scheduled_table[j] & 0x3F;
        }

        let key_table_bytes = self.key_table_bytes();
        let pin: Vec<u8> = vectors.iter().map(|c| key_table_bytes[*c as usize]).collect();

        let pin_str = str::from_utf8(&pin).unwrap();
        format!("~LL_{}_{}", pin_str, username)
    }

    fn calc_hash(data: &[u8]) -> u16 {
        let length = data.len();
        let mut summary: u32 = 0;
        let mut data = data;

        if length % 2 != 0 {
            summary = data[length - 1] as u32;
            data = &data[0..length - 2];
        }

        let data_shorts: &[u16];
        unsafe {
            data_shorts = slice::from_raw_parts::<u16>((data as *const [u8]) as *const u16,
                                                       length / 2);
        }

        summary = data_shorts.iter().fold(summary, |sum, x| sum + *x as u32);
        if summary & 0xFFFF0000 != 0 {
            summary = ((summary >> 0x10) + summary) & 0xFFFF;
        }

        !summary as u16
    }

    fn key_table_bytes(&self) -> &[u8] {
        self.key_table.as_bytes()
    }
}

impl Configuration {
    pub fn share_key(&self) -> &'static str {
        match *self {
            Configuration::Hainan => "hngx01",
        }
    }

    pub fn secret_key(&self) -> &'static str {
        match *self {
            Configuration::Hainan => "000c29270712",
        }
    }

    pub fn key_table(&self) -> &'static str {
        match *self {
            Configuration::Hainan => {
                "abcdefghijklmnopqrstuvwxyz1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA:_"
            }
        }
    }
}

impl Dialer for SingleNetDialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        SingleNetDialer::new(config.share_key(), config.secret_key(), config.key_table())
    }
}

#[test]
fn test_hash_key() {
    let str1 = "123456".to_string();
    let str2 = "1234567".to_string();
    let hash1 = SingleNetDialer::calc_hash(str1.as_bytes());
    let hash2 = SingleNetDialer::calc_hash(str2.as_bytes());
    assert_eq!(hash1, 25446u16);
    assert_eq!(hash2, 25391u16);
}
