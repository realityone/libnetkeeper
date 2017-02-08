use common::dialer::Dialer;
use srun3k::dialer::{Srun3kDialer, Configuration};

#[test]
fn test_srun3k_v20_username_encrypt() {
    let username = "admin";
    let dialer = Srun3kDialer::load_from_config(Configuration::TaLiMu);
    let encrypted_result = dialer.encrypt_account_v20(username);
    assert_eq!(encrypted_result, "{SRUN3}\r\nehqmr");
}
