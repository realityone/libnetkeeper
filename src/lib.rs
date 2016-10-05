#![allow(dead_code)]

extern crate rustc_serialize;
extern crate linked_hash_map;
extern crate openssl;
extern crate time;
extern crate num;

mod dialer;
mod heartbeater;
mod utils;

#[cfg(test)]
mod tests {
    #[test]
    fn test_netkeeper_username_encrypt() {
        use dialer::netkeeper::load_default_dialer;
        let dialer = load_default_dialer();
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "\r\n:R#(P 5005802278989@HYXY.XY");
    }

    #[test]
    fn test_singlenet_username_encrypt() {
        use dialer::singlenet::load_default_dialer;
        let dialer = load_default_dialer();
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "~LL_k6ecvpj2mrjA_05802278989@HYXY.XY");
    }

    #[test]
    fn test_ghca_username_encrypt() {
        use dialer::ghca::load_default_dialer;
        let dialer = load_default_dialer();
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY",
                                               "123456",
                                               Some(0x57F486F7),
                                               Some(0x57F48719));
        let encrypted2 = dialer.encrypt_account("05802278989@HYXY.XY",
                                                "1",
                                                Some(0x57F4B79E),
                                                Some(0x57F4B7B0));
        assert_eq!(encrypted,
                   "~ghca57F487192023484F1BD1D9AB5DC5013405802278989@HYXY.XY");
        assert_eq!(encrypted2,
                   "~ghca57F4B7B020234370C48B10C2AF5E003105802278989@HYXY.XY");
    }

    #[test]
    fn test_keepalive_request() {
        use std::str::FromStr;
        use std::net::Ipv4Addr;
        use heartbeater::singlenet::packets::{PacketFactoryWin, PacketAuthenticator};

        let ka1 = PacketFactoryWin::keepalive_request("05802278989@HYXY.XY",
                                                      Ipv4Addr::from_str("10.0.0.1").unwrap(),
                                                      Some(1472483020),
                                                      None,
                                                      None);
        let ka2 = PacketFactoryWin::keepalive_request("05802278989@HYXY.XY",
                                                      Ipv4Addr::from_str("10.0.0.1").unwrap(),
                                                      Some(1472483020),
                                                      Some("ffb0b2af94693fd1ba4c93e6b9aebd3f"),
                                                      None);

        let authenticator = PacketAuthenticator::new("LLWLXA_TPSHARESECRET");
        let ka1_bytes = ka1.as_bytes(Some(&authenticator));
        let ka2_bytes = ka2.as_bytes(Some(&authenticator));
        let real1_bytes: Vec<u8> =
            vec![83, 78, 0, 105, 3, 43, 220, 250, 219, 227, 84, 6, 40, 77, 138, 217, 220, 230,
                 189, 142, 123, 179, 2, 0, 7, 10, 0, 0, 1, 3, 0, 12, 49, 46, 50, 46, 50, 50, 46,
                 51, 54, 20, 0, 35, 102, 102, 98, 48, 98, 50, 97, 102, 57, 52, 54, 57, 51, 102,
                 100, 49, 98, 97, 52, 99, 57, 51, 101, 54, 98, 57, 97, 101, 98, 100, 51, 102, 18,
                 0, 7, 87, 196, 78, 204, 1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64,
                 72, 89, 88, 89, 46, 88, 89];
        let real2_bytes: Vec<u8> =
            vec![83, 78, 0, 105, 3, 43, 240, 67, 87, 201, 164, 134, 179, 142, 110, 163, 208, 119,
                 121, 90, 173, 75, 2, 0, 7, 10, 0, 0, 1, 3, 0, 12, 49, 46, 50, 46, 50, 50, 46, 51,
                 54, 20, 0, 35, 100, 48, 100, 99, 101, 50, 98, 48, 49, 51, 99, 56, 97, 100, 102,
                 97, 99, 54, 52, 54, 97, 50, 57, 49, 55, 102, 100, 97, 98, 56, 48, 50, 18, 0, 7,
                 87, 196, 78, 204, 1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72,
                 89, 88, 89, 46, 88, 89];
        assert_eq!(*ka1_bytes, real1_bytes);
        assert_eq!(*ka2_bytes, real2_bytes);
    }

    #[test]
    fn test_register_request() {
        use std::str::FromStr;
        use std::net::Ipv4Addr;
        use heartbeater::singlenet::packets::{PacketFactoryMac, PacketAuthenticator};

        let authenticator = PacketAuthenticator::new("LLWLXA");
        let reg = PacketFactoryMac::register_request("05802278989@HYXY.XY",
                                                     Ipv4Addr::from_str("10.8.0.4").unwrap(),
                                                     None,
                                                     None,
                                                     None);
        let reg_bytes = reg.as_bytes(Some(&authenticator));
        let real_bytes: Vec<u8> =
            vec![83, 78, 0, 197, 1, 1, 111, 131, 14, 200, 48, 216, 23, 80, 223, 56, 164, 152, 147,
                 120, 164, 191, 1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72, 89,
                 88, 89, 46, 88, 89, 3, 0, 8, 49, 46, 49, 46, 48, 4, 0, 17, 77, 97, 99, 45, 83,
                 105, 110, 103, 108, 101, 116, 78, 101, 116, 2, 0, 7, 10, 8, 0, 4, 9, 0, 20, 49,
                 48, 58, 100, 100, 58, 98, 49, 58, 100, 53, 58, 57, 53, 58, 99, 97, 11, 0, 3, 8,
                 0, 43, 73, 110, 116, 101, 108, 40, 82, 41, 32, 67, 111, 114, 101, 40, 84, 77, 41,
                 32, 105, 53, 45, 53, 50, 56, 55, 85, 32, 67, 80, 85, 32, 64, 32, 50, 46, 57, 48,
                 71, 72, 122, 10, 0, 7, 0, 0, 32, 0, 5, 0, 40, 77, 97, 99, 32, 79, 83, 32, 88, 32,
                 86, 101, 114, 115, 105, 111, 110, 32, 49, 48, 46, 49, 50, 32, 40, 66, 117, 105,
                 108, 100, 32, 49, 54, 65, 51, 50, 51, 41, 6, 0, 8, 122, 104, 95, 67, 78];
        assert_eq!(*reg_bytes, real_bytes);
    }

    #[test]
    fn test_real_time_bubble_request() {
        use std::str::FromStr;
        use std::net::Ipv4Addr;
        use heartbeater::singlenet::packets::{PacketFactoryMac, PacketAuthenticator};

        let authenticator = PacketAuthenticator::new("LLWLXA");
        let reg = PacketFactoryMac::real_time_bubble_request("05802278989@HYXY.XY",
                                                             Ipv4Addr::from_str("10.8.0.4")
                                                                 .unwrap(),
                                                             None,
                                                             None);
        let reg_bytes = reg.as_bytes(Some(&authenticator));
        let real_bytes: Vec<u8> =
            vec![83, 78, 0, 96, 11, 1, 166, 14, 39, 63, 156, 69, 236, 221, 210, 50, 156, 211, 85,
                 237, 232, 220, 1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72, 89,
                 88, 89, 46, 88, 89, 3, 0, 8, 49, 46, 49, 46, 48, 4, 0, 17, 77, 97, 99, 45, 83,
                 105, 110, 103, 108, 101, 116, 78, 101, 116, 2, 0, 7, 10, 8, 0, 4, 9, 0, 20, 49,
                 48, 58, 100, 100, 58, 98, 49, 58, 100, 53, 58, 57, 53, 58, 99, 97];
        assert_eq!(*reg_bytes, real_bytes);
    }

    #[test]
    fn test_bubble_request() {
        use std::str::FromStr;
        use std::net::Ipv4Addr;
        use heartbeater::singlenet::packets::{PacketFactoryMac, PacketAuthenticator};

        let authenticator = PacketAuthenticator::new("LLWLXA");
        let reg = PacketFactoryMac::bubble_request("05802278989@HYXY.XY",
                                                   Ipv4Addr::from_str("10.8.0.4").unwrap(),
                                                   None,
                                                   None);
        let reg_bytes = reg.as_bytes(Some(&authenticator));
        let real_bytes: Vec<u8> =
            vec![83, 78, 0, 96, 5, 1, 55, 73, 135, 12, 152, 235, 170, 225, 149, 154, 105, 61, 230,
                 140, 53, 242, 1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72, 89,
                 88, 89, 46, 88, 89, 3, 0, 8, 49, 46, 49, 46, 48, 4, 0, 17, 77, 97, 99, 45, 83,
                 105, 110, 103, 108, 101, 116, 78, 101, 116, 2, 0, 7, 10, 8, 0, 4, 9, 0, 20, 49,
                 48, 58, 100, 100, 58, 98, 49, 58, 100, 53, 58, 57, 53, 58, 99, 97];
        assert_eq!(*reg_bytes, real_bytes);
    }
}
