use common::dialer::Dialer;
use ghca::dialer::{GhcaDialer, Configuration};

#[test]
fn test_ghca_username_encrypt() {
    let dialer = GhcaDialer::load_from_config(Configuration::SichuanMac);
    let encrypted = dialer.encrypt_account("05802278989@HYXY.XY",
                                           "123456",
                                           Some(0x57F486F7),
                                           Some(0x57F48719))
        .unwrap();
    let encrypted2 = dialer.encrypt_account("05802278989@HYXY.XY",
                                            "1",
                                            Some(0x57F4B79E),
                                            Some(0x57F4B7B0))
        .unwrap();
    let err_result = dialer.encrypt_account("05802278989@HYXY.XY",
                                            "123456123456123456123456123456123456123456123456123456123456123456123456",
                                            Some(0x57F4B79E),
                                            Some(0x57F4B7B0));
    assert_eq!(encrypted,
               "~ghca57F487192023484F1BD1D9AB5DC5013405802278989@HYXY.XY");
    assert_eq!(encrypted2,
               "~ghca57F4B7B020234370C48B10C2AF5E003105802278989@HYXY.XY");
    assert!(err_result.is_err());
}
