#![allow(dead_code)]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
#![cfg_attr(not(feature = "dev"), allow(unknown_lints))]

extern crate rustc_serialize;
extern crate linked_hash_map;
extern crate crypto as rust_crypto;
extern crate md4;
extern crate time;
extern crate byteorder;

pub mod dialer;
pub mod heartbeater;
mod utils;
mod crypto;

#[cfg(test)]
mod tests {
    use dialer::Dialer;

    #[test]
    fn test_netkeeper_username_encrypt() {
        use dialer::netkeeper::{NetkeeperDialer, Configuration};
        let dialer = NetkeeperDialer::load_from_config(Configuration::Zhejiang);
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "\r\n:R#(P 5005802278989@HYXY.XY");
    }

    #[test]
    fn test_singlenet_username_encrypt() {
        use dialer::singlenet::{SingleNetDialer, Configuration};
        let dialer = SingleNetDialer::load_from_config(Configuration::Hainan);
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "~LL_k6ecvpj2mrjA_05802278989@HYXY.XY");
    }

    #[test]
    fn test_ghca_username_encrypt() {
        use dialer::ghca::{GhcaDialer, Configuration};
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

    #[test]
    fn test_srun3k_v20_username_encrypt() {
        use dialer::srun3k::{Srun3kDialer, Configuration};

        let username = "admin";
        let dialer = Srun3kDialer::load_from_config(Configuration::TaLiMu);
        let encrypted_result = dialer.encrypt_account_v20(username);
        assert_eq!(encrypted_result, "{SRUN3}\r\nehqmr");
    }

    #[test]
    fn test_ipclient_macopener_packet() {
        use std::str::FromStr;
        use std::net::Ipv4Addr;
        use dialer::ipclient::{MACOpenPacket, ISPCode, Configuration};

        let packet = MACOpenPacket::new("a",
                                        Ipv4Addr::from_str("172.16.1.1").unwrap(),
                                        "40:61:86:87:9F:F1",
                                        ISPCode::CChinaUnicom);
        let packet_bytes = packet.as_bytes(Configuration::GUET.hash_key()).unwrap();

        let real_bytes: Vec<u8> = vec![97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 16, 1, 1, 52, 48, 58,
                                       54, 49, 58, 56, 54, 58, 56, 55, 58, 57, 70, 58, 70, 49, 0,
                                       0, 0, 1, 0, 255, 189, 40, 90];

        assert_eq!(packet_bytes, real_bytes);

        let packet_err = MACOpenPacket::new("05802278989@HYXY.XY05802278989@HYXY.\
                                             XY05802278989@HYXY.XY05802278989@HYXY.\
                                             XY05802278989@HYXY.XY",
                                            Ipv4Addr::from_str("172.16.1.1").unwrap(),
                                            "40:61:86:87:9F:F1",
                                            ISPCode::CChinaUnicom);
        assert!(packet_err.as_bytes(Configuration::GUET.hash_key()).is_err());
    }

    #[test]
    fn test_netkeeper_heartbeat() {
        use heartbeater::netkeeper::{Frame, Packet, AES128Encrypter};

        let mut frame = Frame::new("HEARTBEAT", None);
        frame.add("USER_NAME", "05802278989@HYXY.XY");
        frame.add("PASSWORD", "123456");
        frame.add("IP", "124.77.234.214");
        frame.add("MAC", "08:00:27:00:24:FD");
        frame.add("VERSION_NUMBER", "1.0.1");
        frame.add("PIN", "MAC_TEST");
        frame.add("DRIVER", "1");
        frame.add("KEY", "123456");

        let packet = Packet::new(30 as u8, 0x0205, frame);
        let encrypter = AES128Encrypter::new("xlzjhrprotocol3x").unwrap();

        let packet_bytes = packet.as_bytes(&encrypter);
        let real_bytes =
            vec![72, 82, 51, 48, 2, 5, 0, 0, 0, 160, 66, 100, 164, 73, 167, 41, 222, 211, 188, 8,
                 14, 110, 252, 246, 121, 119, 79, 18, 254, 193, 72, 163, 54, 136, 248, 60, 221,
                 177, 221, 0, 13, 10, 146, 141, 142, 244, 89, 10, 176, 106, 162, 242, 204, 38, 73,
                 34, 55, 137, 97, 126, 9, 165, 70, 31, 157, 168, 71, 197, 187, 163, 41, 229, 167,
                 53, 122, 190, 181, 154, 87, 111, 227, 123, 69, 129, 67, 51, 81, 241, 122, 165,
                 40, 52, 89, 244, 80, 95, 124, 126, 112, 49, 174, 27, 56, 156, 90, 142, 92, 15,
                 46, 198, 142, 57, 101, 139, 41, 47, 207, 36, 92, 216, 48, 176, 133, 151, 154,
                 242, 123, 13, 94, 251, 108, 64, 46, 78, 158, 38, 66, 163, 102, 61, 241, 207, 125,
                 163, 239, 153, 239, 75, 85, 0, 97, 237, 41, 117, 94, 251, 126, 197, 12, 140, 230,
                 63, 40, 52, 240, 253, 15, 197, 60, 48];
        assert_eq!(packet_bytes, real_bytes);
    }

    #[test]
    fn test_netkeeper_heartbeat_parse() {
        use std::io::BufReader;
        use heartbeater::netkeeper::{Packet, AES128Encrypter};

        let encrypter = AES128Encrypter::new("xlzjhrprotocol3x").unwrap();

        let origin_bytes: Vec<u8> =
            vec![72, 82, 51, 48, 2, 5, 0, 0, 0, 160, 66, 100, 164, 73, 167, 41, 222, 211, 188, 8,
                 14, 110, 252, 246, 121, 119, 79, 18, 254, 193, 72, 163, 54, 136, 248, 60, 221,
                 177, 221, 0, 13, 10, 146, 141, 142, 244, 89, 10, 176, 106, 162, 242, 204, 38, 73,
                 34, 55, 137, 97, 126, 9, 165, 70, 31, 157, 168, 71, 197, 187, 163, 41, 229, 167,
                 53, 122, 190, 181, 154, 87, 111, 227, 123, 69, 129, 67, 51, 81, 241, 122, 165,
                 40, 52, 89, 244, 80, 95, 124, 126, 112, 49, 174, 27, 56, 156, 90, 142, 92, 15,
                 46, 198, 142, 57, 101, 139, 41, 47, 207, 36, 92, 216, 48, 176, 133, 151, 154,
                 242, 123, 13, 94, 251, 108, 64, 46, 78, 158, 38, 66, 163, 102, 61, 241, 207, 125,
                 163, 239, 153, 239, 75, 85, 0, 97, 237, 41, 117, 94, 251, 126, 197, 12, 140, 230,
                 63, 40, 52, 240, 253, 15, 197, 60, 48];

        let mut buffer = BufReader::new(&origin_bytes as &[u8]);
        let packet = Packet::from_bytes(&mut buffer, &encrypter, None).unwrap();
        let packet_bytes = packet.as_bytes(&encrypter);

        assert_eq!(packet_bytes, origin_bytes);
    }

    #[test]
    fn test_keepalive_request_generate_and_parse() {
        use std::io::BufReader;
        use std::str::FromStr;
        use std::net::Ipv4Addr;
        use heartbeater::singlenet::packets::{PacketFactoryWin, PacketAuthenticator, Packet};

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
        assert_eq!(ka1_bytes, real1_bytes);
        assert_eq!(ka2_bytes, real2_bytes);

        let mut buffer = BufReader::new(&real1_bytes as &[u8]);
        let ka1_p1 = Packet::from_bytes(&mut buffer).unwrap();
        let ka1_p1_bytes = ka1_p1.as_bytes(None);
        assert_eq!(ka1_p1_bytes, real1_bytes);
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
        assert_eq!(reg_bytes, real_bytes);
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
        assert_eq!(reg_bytes, real_bytes);
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
        assert_eq!(reg_bytes, real_bytes);
    }
}
