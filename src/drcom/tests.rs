#[cfg(test)]
mod pppoe_tests {
    use drcom::pppoe::heartbeater::{
        ChallengeRequest, ChallengeResponse, HeartbeatFlag, HeartbeatRequest, KeepAliveRequest,
        KeepAliveRequestFlag, KeepAliveResponse, KeepAliveResponseType,
    };
    use std::io::BufReader;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_drcom_pppoe_challenge() {
        let c = ChallengeRequest::new(Some(1));
        assert_eq!(vec![7, 1, 8, 0, 1, 0, 0, 0], c.as_bytes());

        let fake_response: Vec<u8> = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let mut buffer = BufReader::new(&fake_response as &[u8]);
        let cr = ChallengeResponse::from_bytes(&mut buffer).unwrap();
        assert_eq!(cr.challenge_seed, 185_207_048);
        assert_eq!(cr.source_ip, Ipv4Addr::from_str("12.13.14.15").unwrap());
    }

    #[test]
    fn test_drcom_pppoe_heartbeat() {
        let flag_first = HeartbeatFlag::First;
        let flag_not_first = HeartbeatFlag::NotFirst;

        let hr1 = HeartbeatRequest::new(
            1,
            Ipv4Addr::from_str("1.2.3.4").unwrap(),
            &flag_first,
            0x04030201u32,
            None,
            None,
            None,
        );
        let hr2 = HeartbeatRequest::new(
            1,
            Ipv4Addr::from_str("1.2.3.4").unwrap(),
            &flag_not_first,
            0x04030201u32,
            None,
            None,
            None,
        );
        let hr3 = HeartbeatRequest::new(
            1,
            Ipv4Addr::from_str("1.2.3.4").unwrap(),
            &flag_not_first,
            0x04030200u32,
            None,
            None,
            None,
        );

        assert_eq!(
            hr1.as_bytes(),
            vec![
                7, 1, 96, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 98, 0, 42, 1, 2, 3, 4, 192, 90,
                161, 223, 81, 42, 143, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            hr2.as_bytes(),
            vec![
                7, 1, 96, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 99, 0, 42, 1, 2, 3, 4, 192, 90,
                161, 223, 81, 42, 143, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            hr3.as_bytes(),
            vec![
                7, 1, 96, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 99, 0, 42, 0, 2, 3, 4, 136, 86,
                26, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn test_drcom_pppoe_keep_alive() {
        let flag_first = KeepAliveRequestFlag::First;
        let flag_not_first = KeepAliveRequestFlag::NotFirst;

        let ka1 = KeepAliveRequest::new(1u8, &flag_first, None, None, None);
        let ka2 = KeepAliveRequest::new(1u8, &flag_first, Some(3), None, None);
        let ka3 = KeepAliveRequest::new(1u8, &flag_not_first, Some(3), None, None);
        let ka4 = KeepAliveRequest::new(
            1u8,
            &flag_not_first,
            Some(3),
            Some(Ipv4Addr::from_str("1.2.3.4").unwrap()),
            Some(0x22221111u32),
        );

        assert_eq!(
            ka1.as_bytes(),
            vec![
                7, 1, 40, 0, 11, 1, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            ka2.as_bytes(),
            vec![
                7, 1, 40, 0, 11, 3, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 199, 47, 49, 1,
                126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            ka3.as_bytes(),
            vec![
                7, 1, 40, 0, 11, 3, 220, 2, 47, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 199, 47, 49, 1,
                126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            ka4.as_bytes(),
            vec![
                7, 1, 40, 0, 11, 3, 220, 2, 47, 18, 0, 0, 0, 0, 0, 0, 17, 17, 34, 34, 82, 139, 161,
                42, 71, 175, 94, 167, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );

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
        assert_eq!(
            kar3.response_type,
            KeepAliveResponseType::UnrecognizedResponse
        );
    }
}

#[cfg(test)]
mod wired_tests {
    use drcom::wired::dialer::{ChallengeRequest, ChallengeResponse, LoginAccount, LoginResponse};
    use drcom::wired::heartbeater::{
        HeartbeatFlag, PhaseOneRequest, PhaseOneResponse, PhaseTwoRequest, PhaseTwoResponse,
    };
    use std::io::BufReader;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_drcom_wired_challenge() {
        let c = ChallengeRequest::new(Some(1));
        assert_eq!(
            c.as_bytes(),
            vec![1, 2, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

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
            let origin_bytes1 = vec![
                3, 1, 0, 36, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102,
                177, 222, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114, 110, 97, 109,
                101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 22, 39,
                115, 211, 190, 110, 169, 80, 242, 73, 215, 59, 106, 173, 172, 242, 14, 27, 203, 29,
                82, 153, 1, 10, 30, 22, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 84, 80, 240,
                75, 157, 179, 232, 1, 0, 0, 0, 0, 76, 73, 89, 85, 65, 78, 89, 85, 65, 78, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40,
                10, 0, 0, 2, 0, 0, 0, 56, 48, 56, 57, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0,
                2, 12, 224, 42, 126, 213, 0, 0, 184, 136, 227, 5, 22, 128, 0, 0, 233, 19,
            ];
            assert_eq!(lr1.unwrap().as_bytes().unwrap(), origin_bytes1);
        }

        {
            la.ror_version(true);
            let lr2 = la.login_request();
            let origin_bytes2 = vec![
                3, 1, 0, 36, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102,
                177, 222, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114, 110, 97, 109,
                101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 22, 39,
                115, 211, 190, 110, 169, 80, 242, 73, 215, 59, 106, 173, 172, 242, 14, 27, 203, 29,
                82, 153, 1, 10, 30, 22, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 84, 80, 240,
                75, 157, 179, 232, 1, 0, 0, 0, 0, 76, 73, 89, 85, 65, 78, 89, 85, 65, 78, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40,
                10, 0, 0, 2, 0, 0, 0, 56, 48, 56, 57, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0,
                0, 8, 246, 118, 31, 45, 254, 12, 137, 112, 2, 12, 112, 131, 51, 46, 0, 0, 184, 136,
                227, 5, 22, 128, 0, 0, 233, 19,
            ];
            assert_eq!(lr2.unwrap().as_bytes().unwrap(), origin_bytes2);
        }

        {
            let fake_response: Vec<u8> = vec![
                4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let mut buffer = BufReader::new(&fake_response as &[u8]);
            let cr = LoginResponse::from_bytes(&mut buffer).unwrap();
            assert_eq!(cr.keep_alive_key, [23, 24, 25, 26, 27, 28]);
        }

        {
            let mut la = LoginAccount::new("usernameusername", "password", [0x7, 0x8, 0x9, 0x10]);
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
            let origin_bytes = vec![
                3, 1, 0, 36, 227, 154, 169, 77, 33, 112, 224, 233, 249, 52, 229, 206, 20, 132, 105,
                72, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114, 110, 97, 109, 101,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 1, 25, 123, 138, 8,
                70, 249, 200, 54, 139, 80, 235, 42, 110, 136, 213, 114, 194, 60, 249, 131, 44, 185,
                1, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 76, 93, 208, 174, 102, 158,
                71, 5, 0, 0, 0, 0, 72, 65, 72, 65, 72, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40, 10, 0, 0, 2, 0,
                0, 0, 87, 73, 78, 68, 79, 87, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 8, 156,
                223, 214, 241, 178, 248, 148, 108, 2, 12, 160, 94, 79, 1, 0, 0, 250, 225, 35, 69,
                103, 137, 0, 0, 233, 19,
            ];
            assert_eq!(lr.unwrap().as_bytes().unwrap(), origin_bytes);

            la.ror_version(false);
            let lr = la.login_request();
            let origin_bytes = vec![
                3, 1, 0, 36, 227, 154, 169, 77, 33, 112, 224, 233, 249, 52, 229, 206, 20, 132, 105,
                72, 117, 115, 101, 114, 110, 97, 109, 101, 117, 115, 101, 114, 110, 97, 109, 101,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 1, 25, 123, 138, 8,
                70, 249, 200, 54, 139, 80, 235, 42, 110, 136, 213, 114, 194, 60, 249, 131, 44, 185,
                1, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 76, 93, 208, 174, 102, 158,
                71, 5, 0, 0, 0, 0, 72, 65, 72, 65, 72, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 114, 114, 114, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 40, 10, 0, 0, 2, 0,
                0, 0, 87, 73, 78, 68, 79, 87, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 12, 32, 0,
                174, 219, 0, 0, 250, 225, 35, 69, 103, 137, 0, 0, 233, 19,
            ];
            assert_eq!(lr.unwrap().as_bytes().unwrap(), origin_bytes);
        }
    }

    #[test]
    fn test_drcom_wired_heartbeat() {
        let flag_first = HeartbeatFlag::First;
        let flag_not_first = HeartbeatFlag::NotFirst;

        let phase1 = PhaseOneRequest::new([1, 2, 3, 4], "password", [5, 6, 7, 8], Some(123456789));
        assert_eq!(
            phase1.as_bytes(),
            vec![
                255, 174, 175, 144, 214, 168, 238, 67, 106, 128, 153, 49, 172, 94, 102, 177, 222,
                0, 0, 0, 5, 6, 7, 8, 212, 112, 0, 0, 0, 0,
            ]
        );

        {
            let phase2 = PhaseTwoRequest::new(
                1,
                [5, 6, 7, 8],
                &flag_first,
                Ipv4Addr::from_str("1.2.3.4").unwrap(),
                Some(1),
            );
            assert_eq!(
                phase2.as_bytes(),
                vec![
                    7, 1, 40, 0, 11, 1, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
            );
        }

        {
            let phase2 = PhaseTwoRequest::new(
                1,
                [5, 6, 7, 8],
                &flag_first,
                Ipv4Addr::from_str("1.2.3.4").unwrap(),
                Some(3),
            );
            assert_eq!(
                phase2.as_bytes(),
                vec![
                    7, 1, 40, 0, 11, 3, 15, 39, 47, 18, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0,
                    0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
            );
        }

        {
            let phase2 = PhaseTwoRequest::new(
                1,
                [5, 6, 7, 8],
                &flag_not_first,
                Ipv4Addr::from_str("1.2.3.4").unwrap(),
                Some(3),
            );
            assert_eq!(
                phase2.as_bytes(),
                vec![
                    7, 1, 40, 0, 11, 3, 220, 2, 47, 18, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0,
                    0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
            );
        }

        {
            let fake_response: Vec<u8> = vec![
                7, 1, 0x28, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                43, 44, 45, 46, 47, 48, 49,
            ];
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
