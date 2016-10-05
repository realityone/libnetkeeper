use std::str;

use rustc_serialize::hex::ToHex;
use openssl::crypto::hash::{Hasher, Type};

use utils::{current_timestamp, integer_to_bytes};

#[derive(Debug)]
pub struct GhcaDialer {
    pub share_key: String,
    pub prefix: String,
    pub version: String,
}

impl GhcaDialer {
    fn new(share_key: &str, prefix: &str, version: &str) -> Self {
        GhcaDialer {
            share_key: share_key.to_string(),
            prefix: prefix.to_string(),
            version: version.to_string(),
        }
    }

    pub fn encrypt_account(&self,
                           username: &str,
                           password: &str,
                           fst_timestamp: Option<u32>,
                           sec_timestamp: Option<u32>)
                           -> String {
        let fst_timestamp = match fst_timestamp {
            Some(fst_timestamp) => fst_timestamp,
            None => current_timestamp(),
        };
        let sec_timestamp = match sec_timestamp {
            Some(sec_timestamp) => sec_timestamp,
            None => current_timestamp(),
        };
        let name_len = username.len() as u32;
        let pwd_len = password.len() as u32;

        let mut cursor = fst_timestamp % pwd_len;
        if cursor < 1 {
            cursor += 1;
        }
        let match_flag = match cursor == pwd_len {
            true => 1,
            false => 0,
        };

        let delta = cursor - match_flag;
        let prefix_len = cursor + match_flag + 1;
        let suffix_len = pwd_len - 1 - delta;
        let pwd_prefix = &password[..prefix_len as usize];
        let pwd_suffix = &password[(delta + 1) as usize..(delta + 1 + suffix_len) as usize];

        let md5_hash_prefix;
        {
            let mut md5 = Hasher::new(Type::MD5).unwrap();
            let sec_timestamp_be = sec_timestamp.to_be();
            let sec_timestamp_bytes = integer_to_bytes(&sec_timestamp_be);

            md5.update(sec_timestamp_bytes).unwrap();
            md5.update(&self.share_key[..(60 - prefix_len) as usize].as_bytes()).unwrap();
            md5.update(pwd_prefix.as_bytes()).unwrap();
            md5.update(username.as_bytes()).unwrap();
            md5.update(&self.share_key[..(64 - name_len - suffix_len) as usize].as_bytes())
                .unwrap();
            md5.update(pwd_suffix.as_bytes()).unwrap();

            let first_hashed_bytes = md5.finish().unwrap();
            let mut md5 = Hasher::new(Type::MD5).unwrap();
            md5.update(&first_hashed_bytes).unwrap();
            md5_hash_prefix = md5.finish().unwrap()[..8].to_hex().to_uppercase();
        }

        let pwd_char_sum = password.as_bytes().iter().fold(0, |sum, x| sum + *x as u32);
        let pin = format!("{:04X}", delta ^ pwd_char_sum);

        format!("{}{:08X}{}{}{}{}",
                self.prefix,
                sec_timestamp,
                self.version,
                md5_hash_prefix,
                pin,
                username)
    }
}

pub fn load_default_dialer() -> GhcaDialer {
    GhcaDialer::new("aI0fC8RslXg6HXaKAUa6kpvcAXszvTcxYP8jmS9sBnVfIqTRdJS1eZNHmBjKN28j",
                    "~ghca",
                    "2023")
}