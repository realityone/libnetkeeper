use common::dialer::Dialer;
use netkeeper4::dialer::{Configuration, Netkeeper4Dialer};

#[test]
fn test_netkeeper4_username_encrypt() {
    let dialer = Netkeeper4Dialer::load_from_config(Configuration::Zhejiang);
    let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1535814909));
    assert_eq!(encrypted, "\r1I7L]. 1905802278989@HYXY.XY");
}
