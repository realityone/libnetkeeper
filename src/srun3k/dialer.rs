use common::dialer::Dialer;

#[derive(Debug)]
pub enum Configuration {
    TaLiMu,
}

pub struct Srun3kDialer {
    pub configuration: Configuration,
}

impl Srun3kDialer {
    pub fn new(config: Option<Configuration>) -> Self {
        let config = config.unwrap_or(Configuration::TaLiMu);
        Srun3kDialer { configuration: config }
    }

    pub fn encrypt_account_v20(&self, username: &str) -> String {
        let encrypted_bytes: Vec<u8> = username.bytes().map(|c| c + 4).collect();
        let encrypted_username;
        unsafe {
            encrypted_username = String::from_utf8_unchecked(encrypted_bytes);
        };
        format!("{{SRUN3}}\r\n{}", encrypted_username)
    }
}

impl Dialer for Srun3kDialer {
    type C = Configuration;

    fn load_from_config(config: Self::C) -> Self {
        Srun3kDialer::new(Some(config))
    }
}