use std::slice;
use std::mem;
use std::str;

use utils::current_timestamp;

#[derive(Debug)]
#[allow(dead_code)]
pub struct SingleNetDialer {
    share_key: String,
    secret_key: String,
    key_table: String,
}

#[allow(dead_code)]
impl SingleNetDialer {
    pub fn new(share_key: &str, secret_key: &str, key_table: &str) -> Self {
        SingleNetDialer {
            share_key: share_key.to_string(),
            secret_key: secret_key.to_string(),
            key_table: key_table.to_string(),
        }
    }

    pub fn encrypt_account(&self, username: &str, timestamp: Option<i32>) -> String {
        let username = username.to_uppercase();
        let timenow = match timestamp {
            Some(timestamp) => timestamp,
            None => current_timestamp(),
        };

        let first_hash: u16;
        {
            let timenow_bytes: &[u8];
            unsafe {
                timenow_bytes =
                    slice::from_raw_parts::<u8>((&timenow.to_be() as *const i32) as *const u8,
                                                mem::size_of::<i32>());
            }

            let mut hash_data: Vec<u8> = Vec::new();
            hash_data.extend(timenow_bytes);
            hash_data.extend(self.share_key.as_bytes());
            hash_data.extend(username.split("@").nth(0).unwrap().as_bytes());
            first_hash = Self::calc_hash(&hash_data)
        }

        let second_hash: u16;
        {
            let first_hash_bytes: &[u8];
            unsafe {
                first_hash_bytes =
                    slice::from_raw_parts::<u8>((&first_hash.to_be() as *const u16) as *const u8,
                                                mem::size_of::<u16>());
            }

            let mut hash_data: Vec<u8> = Vec::new();
            hash_data.extend(first_hash_bytes);
            hash_data.extend(self.secret_key.as_bytes());
            second_hash = Self::calc_hash(&hash_data);
        }

        let mut scheduled_table: Vec<u8> = Vec::with_capacity(8);
        {
            let timenow_high_bytes: &[u8];
            let timenow_low_bytes: &[u8];
            let first_hash_bytes: &[u8];
            let second_hash_bytes: &[u8];
            let timenow_high = (timenow >> 16) as u16;
            let timenow_low = (timenow & 0xFFFF) as u16;
            unsafe {
                timenow_high_bytes =
                    slice::from_raw_parts::<u8>((&timenow_high.to_be() as *const u16) as *const u8,
                                                mem::size_of::<u16>());
                timenow_low_bytes =
                    slice::from_raw_parts::<u8>((&timenow_low.to_be() as *const u16) as *const u8,
                                                mem::size_of::<u16>());

                first_hash_bytes =
                    slice::from_raw_parts::<u8>((&first_hash.to_le() as *const u16) as *const u8,
                                                mem::size_of::<u16>());
                second_hash_bytes =
                    slice::from_raw_parts::<u8>((&second_hash.to_le() as *const u16) as *const u8,
                                                mem::size_of::<u16>());
            }

            scheduled_table.extend(timenow_high_bytes);
            scheduled_table.extend(first_hash_bytes);
            scheduled_table.extend(timenow_low_bytes);
            scheduled_table.extend(second_hash_bytes);
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

#[allow(dead_code)]
pub fn load_default_dialer() -> SingleNetDialer {
    SingleNetDialer::new("hngx01",
                         "000c29270712",
                         "abcdefghijklmnopqrstuvwxyz1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA:_")
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
