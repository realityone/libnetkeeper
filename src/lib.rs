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
extern crate rand;

#[cfg(feature="drcom")]
pub mod drcom;
#[cfg(feature="netkeeper")]
pub mod netkeeper;
#[cfg(feature="ghca")]
pub mod ghca;
#[cfg(feature="ipclient")]
pub mod ipclient;
#[cfg(feature="singlenet")]
pub mod singlenet;
#[cfg(feature="srun3k")]
pub mod srun3k;

pub mod common;
mod crypto;

#[cfg(test)]
#[cfg(feature="netkeeper")]
mod netkeeper_tests {
    use common::dialer::Dialer;
    use netkeeper::dialer::{NetkeeperDialer, Configuration};
    use std::io::BufReader;
    use crypto::cipher::AES_128_ECB;
    use netkeeper::heartbeater::{Frame, Packet};

    #[test]
    fn test_netkeeper_username_encrypt() {
        let dialer = NetkeeperDialer::load_from_config(Configuration::Zhejiang);
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "\r\n:R#(P 5005802278989@HYXY.XY");
    }

    #[test]
    fn test_netkeeper_heartbeat() {
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
        let encrypter = AES_128_ECB::new(b"xlzjhrprotocol3x").unwrap();

        let packet_bytes = packet.as_bytes(&encrypter).unwrap();
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
        let encrypter = AES_128_ECB::new(b"xlzjhrprotocol3x").unwrap();
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
        let packet_bytes = packet.as_bytes(&encrypter).unwrap();
        assert_eq!(packet_bytes, origin_bytes);
    }
}

#[cfg(test)]
#[cfg(feature="singlenet")]
mod singlenet_tests {
    use common::dialer::Dialer;
    use singlenet::dialer::{SingleNetDialer, Configuration};
    use std::io::BufReader;
    use std::str::FromStr;
    use std::net::Ipv4Addr;
    use singlenet::heartbeater::{PacketFactoryMac, PacketFactoryWin, PacketAuthenticator, Packet};

    #[test]
    fn test_singlenet_username_encrypt() {
        let dialer = SingleNetDialer::load_from_config(Configuration::Hainan);
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "~LL_k6ecvpj2mrjA_05802278989@HYXY.XY");
    }


    #[test]
    fn test_keepalive_request_generate_and_parse() {
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

#[cfg(test)]
#[cfg(feature="ghca")]
mod ghca_tests {
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
}

#[cfg(test)]
#[cfg(feature="srun3k")]
mod srun3k_tests {
    use common::dialer::Dialer;
    use srun3k::dialer::{Srun3kDialer, Configuration};

    #[test]
    fn test_srun3k_v20_username_encrypt() {
        let username = "admin";
        let dialer = Srun3kDialer::load_from_config(Configuration::TaLiMu);
        let encrypted_result = dialer.encrypt_account_v20(username);
        assert_eq!(encrypted_result, "{SRUN3}\r\nehqmr");
    }
}

#[cfg(test)]
#[cfg(feature="ipclient")]
mod ipclient_tests {
    use std::str::FromStr;
    use std::net::Ipv4Addr;
    use ipclient::dialer::{MACOpenPacket, ISPCode, Configuration};

    #[test]
    fn test_ipclient_macopener_packet() {
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
}

#[cfg(test)]
#[cfg(feature="drcom")]
mod drcom_tests {
    #[cfg(test)]
    mod pppoe_tests {
        use std::io::BufReader;
        use std::net::Ipv4Addr;
        use std::str::FromStr;
        use drcom::pppoe::heartbeater::{ChallengeRequest, ChallengeResponse, HeartbeatRequest,
                                        HeartbeatFlag, KeepAliveRequest, KeepAliveResponse,
                                        KeepAliveResponseType, KeepAliveRequestFlag};

        #[test]
        fn test_drcom_pppoe_challenge() {
            let c = ChallengeRequest::new(Some(1));
            assert_eq!(vec![7, 1, 8, 0, 1, 0, 0, 0], c.as_bytes());

            let fake_response: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                                              15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                                              28, 29, 30, 31];
            let mut buffer = BufReader::new(&fake_response as &[u8]);
            let cr = ChallengeResponse::from_bytes(&mut buffer).unwrap();
            assert_eq!(cr.challenge_seed, 185207048);
            assert_eq!(cr.source_ip, Ipv4Addr::from_str("12.13.14.15").unwrap());
        }

        #[test]
        fn test_drcom_pppoe_heartbeat() {
            let flag_first = HeartbeatFlag::First;
            let flag_not_first = HeartbeatFlag::NotFirst;

            let hr1 = HeartbeatRequest::new(1,
                                            Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                            &flag_first,
                                            0x04030201u32,
                                            None,
                                            None,
                                            None);
            let hr2 = HeartbeatRequest::new(1,
                                            Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                            &flag_not_first,
                                            0x04030201u32,
                                            None,
                                            None,
                                            None);
            let hr3 = HeartbeatRequest::new(1,
                                            Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                            &flag_not_first,
                                            0x04030200u32,
                                            None,
                                            None,
                                            None);

            assert_eq!(hr1.as_bytes(),
                       vec![7, 1, 96, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 98, 0, 42, 1, 2,
                            3, 4, 192, 90, 161, 223, 81, 42, 143, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(hr2.as_bytes(),
                       vec![7, 1, 96, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 99, 0, 42, 1, 2,
                            3, 4, 192, 90, 161, 223, 81, 42, 143, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(hr3.as_bytes(),
                       vec![7, 1, 96, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 99, 0, 42, 0, 2,
                            3, 4, 136, 86, 26, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0]);
        }

        #[test]
        fn test_drcom_pppoe_keep_alive() {
            let flag_first = KeepAliveRequestFlag::First;
            let flag_not_first = KeepAliveRequestFlag::NotFirst;

            let ka1 = KeepAliveRequest::new(1u8, &flag_first, None, None, None);
            let ka2 = KeepAliveRequest::new(1u8, &flag_first, Some(3), None, None);
            let ka3 = KeepAliveRequest::new(1u8, &flag_not_first, Some(3), None, None);
            let ka4 = KeepAliveRequest::new(1u8,
                                            &flag_not_first,
                                            Some(3),
                                            Some(Ipv4Addr::from_str("1.2.3.4").unwrap()),
                                            Some(0x22221111u32));

            assert_eq!(ka1.as_bytes(),
                       vec![7, 1, 40, 0, 11, 1, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(ka2.as_bytes(),
                       vec![7, 1, 40, 0, 11, 3, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            199, 47, 49, 1, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(ka3.as_bytes(),
                       vec![7, 1, 40, 0, 11, 3, 220, 2, 47, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            199, 47, 49, 1, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(ka4.as_bytes(),
                       vec![7, 1, 40, 0, 11, 3, 220, 2, 47, 18, 0, 0, 0, 0, 0, 0, 17, 17, 34, 34,
                            82, 139, 161, 42, 71, 175, 94, 167, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0,
                            0]);

            let fake_response1: Vec<u8> = vec![7, 0, 0x28];
            let mut buffer1 = BufReader::new(&fake_response1 as &[u8]);
            let kar1 = KeepAliveResponse::from_bytes(&mut buffer1).unwrap();
            assert_eq!(kar1.response_type, KeepAliveResponseType::KeepAliveSucceed);

            let fake_response2: Vec<u8> = vec![7, 0, 0x10];
            let mut buffer2 = BufReader::new(&fake_response2 as &[u8]);
            let kar2 = KeepAliveResponse::from_bytes(&mut buffer2).unwrap();
            assert_eq!(kar2.response_type, KeepAliveResponseType::FileResponse);

            let fake_response3: Vec<u8> = vec![7, 0, 0x11];
            let mut buffer3 = BufReader::new(&fake_response3 as &[u8]);
            let kar3 = KeepAliveResponse::from_bytes(&mut buffer3).unwrap();
            assert_eq!(kar3.response_type,
                       KeepAliveResponseType::UnrecognizedResponse);
        }
    }

    #[cfg(test)]
    mod wired_tests {
        use std::io::BufReader;
        use std::net::Ipv4Addr;
        use std::str::FromStr;
        use drcom::wired::dialer::{LoginAccount, LoginResponse, ChallengeRequest,
                                   ChallengeResponse};
        use drcom::wired::heartbeater::{PhaseOneRequest, PhaseOneResponse, PhaseTwoRequest,
                                        HeartbeatFlag, PhaseTwoResponse};

        #[test]
        fn test_drcom_wired_challenge() {
            let c = ChallengeRequest::new(Some(1));
            assert_eq!(c.as_bytes(),
                       vec![1, 2, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

            {
                let fake_response: Vec<u8> = vec![2, 3, 4, 5, 6, 7, 8, 9, 10];
                let mut buffer = BufReader::new(&fake_response as &[u8]);
                let cr = ChallengeResponse::from_bytes(&mut buffer).unwrap();
                assert_eq!(cr.hash_salt, [6u8, 7u8, 8u8, 9u8]);
            }

            {
                let fake_response: Vec<u8> = vec![3, 3, 4, 5, 6, 7, 8, 9, 10];
                let mut buffer = BufReader::new(&fake_response as &[u8]);
                assert!(ChallengeResponse::from_bytes(&mut buffer).is_err());
            }
        }

        #[test]
        fn test_drcom_wired_login() {
            let mut la = LoginAccount::new("usernameusername", "password", [1, 2, 3, 4]);
            la.ipaddresses(&[Ipv4Addr::from_str("10.30.22.17").unwrap()])
                .mac_address([0xb8, 0x88, 0xe3, 0x05, 0x16, 0x80])
                .dog_flag(0x1)
                .client_version(0xa)
                .dog_version(0x0)
                .adapter_count(0x1)
                .control_check_status(0x20)
                .auto_logout(false)
                .broadcast_mode(false)
                .random(0x13e9)
                .auth_extra_option(0x0);

            {
                la.ror_version(false);
                let lr1 = la.login_request();
                let origin_bytes1 =
                    vec![3, 1, 0, 36, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172,
                         94, 102, 177, 222, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101,
                         114, 110, 97, 109, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 32, 1, 22, 39, 115, 211, 190, 110, 169, 80, 242, 73, 215, 59,
                         106, 173, 172, 242, 14, 27, 203, 29, 82, 153, 1, 10, 30, 22, 17, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 84, 80, 240, 75, 157, 179, 232, 1, 0, 0,
                         0, 0, 76, 73, 89, 85, 65, 78, 89, 85, 65, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0,
                         40, 10, 0, 0, 2, 0, 0, 0, 56, 48, 56, 57, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 2, 12, 224,
                         42, 126, 213, 0, 0, 184, 136, 227, 5, 22, 128, 0, 0, 233, 19];
                assert_eq!(lr1.unwrap().as_bytes().unwrap(), origin_bytes1);
            }

            {
                la.ror_version(true);
                let lr2 = la.login_request();
                let origin_bytes2 =
                    vec![3, 1, 0, 36, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172,
                         94, 102, 177, 222, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101,
                         114, 110, 97, 109, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 32, 1, 22, 39, 115, 211, 190, 110, 169, 80, 242, 73, 215, 59,
                         106, 173, 172, 242, 14, 27, 203, 29, 82, 153, 1, 10, 30, 22, 17, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 84, 80, 240, 75, 157, 179, 232, 1, 0, 0,
                         0, 0, 76, 73, 89, 85, 65, 78, 89, 85, 65, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0,
                         40, 10, 0, 0, 2, 0, 0, 0, 56, 48, 56, 57, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 8, 246,
                         118, 31, 45, 254, 12, 137, 112, 2, 12, 112, 131, 51, 46, 0, 0, 184, 136,
                         227, 5, 22, 128, 0, 0, 233, 19];
                assert_eq!(lr2.unwrap().as_bytes().unwrap(), origin_bytes2);
            }

            {
                let fake_response: Vec<u8> = vec![4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                                  14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                                                  26, 27, 28, 29, 30, 31];
                let mut buffer = BufReader::new(&fake_response as &[u8]);
                let cr = LoginResponse::from_bytes(&mut buffer).unwrap();
                assert_eq!(cr.keep_alive_key, [23, 24, 25, 26, 27, 28]);
            }

            {
                let mut la =
                    LoginAccount::new("usernameusername", "password", [0x7, 0x8, 0x9, 0x10]);
                la.ipaddresses(&[Ipv4Addr::from_str("1.2.3.4").unwrap()])
                    .mac_address([0xfa, 0xe1, 0x23, 0x45, 0x67, 0x89])
                    .dog_flag(0x5)
                    .client_version(0x1)
                    .dog_version(0x2)
                    .adapter_count(0x1)
                    .control_check_status(0x30)
                    .auto_logout(false)
                    .broadcast_mode(false)
                    .random(0x13e9)
                    .auth_extra_option(0x0)
                    .hostname("HAHAHA".to_string())
                    .service_pack("WINDOWS".to_string());

                la.ror_version(true);
                let lr = la.login_request();
                let origin_bytes =
                    vec![3, 1, 0, 36, 227, 154, 169, 77, 33, 112, 224, 233, 249, 52, 229, 206, 20,
                         132, 105, 72, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114,
                         110, 97, 109, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 48, 1, 25, 123, 138, 8, 70, 249, 200, 54, 139, 80, 235, 42, 110,
                         136, 213, 114, 194, 60, 249, 131, 44, 185, 1, 1, 2, 3, 4, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 78, 76, 93, 208, 174, 102, 158, 71, 5, 0, 0, 0, 0,
                         72, 65, 72, 65, 72, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40, 10, 0,
                         0, 2, 0, 0, 0, 87, 73, 78, 68, 79, 87, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 8, 156, 223, 214,
                         241, 178, 248, 148, 108, 2, 12, 160, 94, 79, 1, 0, 0, 250, 225, 35, 69,
                         103, 137, 0, 0, 233, 19];
                assert_eq!(lr.unwrap().as_bytes().unwrap(), origin_bytes);

                la.ror_version(false);
                let lr = la.login_request();
                let origin_bytes =
                    vec![3, 1, 0, 36, 227, 154, 169, 77, 33, 112, 224, 233, 249, 52, 229, 206, 20,
                         132, 105, 72, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114,
                         110, 97, 109, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 48, 1, 25, 123, 138, 8, 70, 249, 200, 54, 139, 80, 235, 42, 110,
                         136, 213, 114, 194, 60, 249, 131, 44, 185, 1, 1, 2, 3, 4, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 78, 76, 93, 208, 174, 102, 158, 71, 5, 0, 0, 0, 0,
                         72, 65, 72, 65, 72, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40, 10, 0,
                         0, 2, 0, 0, 0, 87, 73, 78, 68, 79, 87, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 12, 32, 0, 174,
                         219, 0, 0, 250, 225, 35, 69, 103, 137, 0, 0, 233, 19];
                assert_eq!(lr.unwrap().as_bytes().unwrap(), origin_bytes);
            }
        }

        #[test]
        fn test_drcom_wired_heartbeat() {
            let flag_first = HeartbeatFlag::First;
            let flag_not_first = HeartbeatFlag::NotFirst;

            let phase1 =
                PhaseOneRequest::new([1, 2, 3, 4], "password", [5, 6, 7, 8], Some(123456789));
            assert_eq!(phase1.as_bytes(),
                       vec![255, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94,
                            102, 177, 222, 0, 0, 0, 5, 6, 7, 8, 212, 112, 0, 0, 0, 0]);

            {
                let phase2 = PhaseTwoRequest::new(1,
                                                  [5, 6, 7, 8],
                                                  &flag_first,
                                                  Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                                  Some(1));
                assert_eq!(phase2.as_bytes(),
                           vec![7, 1, 40, 0, 11, 1, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            }

            {
                let phase2 = PhaseTwoRequest::new(1,
                                                  [5, 6, 7, 8],
                                                  &flag_first,
                                                  Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                                  Some(3));
                assert_eq!(phase2.as_bytes(),
                           vec![7, 1, 40, 0, 11, 3, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8,
                                0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
            }

            {
                let phase2 = PhaseTwoRequest::new(1,
                                                  [5, 6, 7, 8],
                                                  &flag_not_first,
                                                  Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                                  Some(3));
                assert_eq!(phase2.as_bytes(),
                           vec![7, 1, 40, 0, 11, 3, 220, 2, 47, 18, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8,
                                0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
            }

            {
                let fake_response: Vec<u8> = vec![7, 1, 0x28, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                                  14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                                                  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                                                  38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49];
                let mut buffer = BufReader::new(&fake_response as &[u8]);
                let response = PhaseTwoResponse::from_bytes(&mut buffer).unwrap();
                assert_eq!(response.sequence, 1);
                assert_eq!(response.keep_alive_key, [16, 17, 18, 19]);
            }

            {
                let fake_response: Vec<u8> = vec![7, 3, 4, 5, 6, 7, 8, 9, 10];
                let mut buffer = BufReader::new(&fake_response as &[u8]);
                assert!(PhaseOneResponse::from_bytes(&mut buffer).is_ok());
            }

            {
                let fake_response: Vec<u8> = vec![78, 3, 4, 5, 6, 7, 8, 9, 10];
                let mut buffer = BufReader::new(&fake_response as &[u8]);
                assert!(PhaseOneResponse::from_bytes(&mut buffer).is_err());
            }
        }
    }
}


#[cfg(test)]
mod tests {}
