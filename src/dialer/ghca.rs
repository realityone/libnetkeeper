use rustc_serialize::hex::ToHex;
use crypto::hash::{HasherBuilder, HasherType};

use dialer::Dialer;
use utils::{current_timestamp, any_to_bytes};

#[derive(Debug)]
pub enum Configuration {
    SichuanMac,
}

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
                           -> Result<String, &'static str> {
        let name_len = username.len() as u32;
        let pwd_len = password.len() as u32;
        if name_len >= 60 || pwd_len >= 60 {
            return Err("username and password must be shorter than 60 characters.");
        }
        let fst_timestamp = fst_timestamp.unwrap_or_else(current_timestamp);
        let sec_timestamp = sec_timestamp.unwrap_or_else(current_timestamp);

        let mut cursor = fst_timestamp % pwd_len;
        if cursor < 1 {
            cursor += 1;
        }
        let match_flag = if cursor == pwd_len {
            1
        } else {
            0
        };

        let delta = cursor - match_flag;
        let md5_hash_prefix;
        {
            let mut md5 = HasherBuilder::build(HasherType::MD5);

            let prefix_len = delta + 1;
            let suffix_len = pwd_len - prefix_len;
            let pwd_prefix = &password[..prefix_len as usize];
            let pwd_suffix = &password[prefix_len as usize..pwd_len as usize];
            let sec_timestamp_be = sec_timestamp.to_be();
            let sec_timestamp_bytes = any_to_bytes(&sec_timestamp_be);

            md5.update(sec_timestamp_bytes);
            md5.update(self.share_key[..(60 - prefix_len) as usize].as_bytes());
            md5.update(pwd_prefix.as_bytes());
            md5.update(username.as_bytes());
            md5.update(self.share_key[..(64 - name_len - suffix_len) as usize].as_bytes());
            md5.update(pwd_suffix.as_bytes());

            let first_hashed_bytes = md5.finish();
            let mut md5 = HasherBuilder::build(HasherType::MD5);
            md5.update(&first_hashed_bytes);
            md5_hash_prefix = md5.finish()[..8].to_hex().to_uppercase();
        }

        let pwd_char_sum = password.as_bytes().iter().fold(0, |sum, x| sum + *x as u32);
        let pin = format!("{:04X}", delta ^ pwd_char_sum);
        Ok(format!("{}{:08X}{}{}{}{}",
                   self.prefix,
                   sec_timestamp,
                   self.version,
                   md5_hash_prefix,
                   pin,
                   username))
    }
}

impl Configuration {
    pub fn share_key(&self) -> &'static str {
        match *self {
            Configuration::SichuanMac => "aI0fC8RslXg6HXaKAUa6kpvcAXszvTcxYP8jmS9sBnVfIqTRdJS1eZNHmBjKN28j",
        }
    }

    pub fn prefix(&self) -> &'static str {
        match *self {
            _ => "~ghca",
        }
    }

    pub fn version(&self) -> &'static str {
        match *self {
            Configuration::SichuanMac => "2023",
        }
    }
}

impl Dialer for GhcaDialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        GhcaDialer::new(config.share_key(), config.prefix(), config.version())
    }
}
