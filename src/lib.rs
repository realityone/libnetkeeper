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
    fn test_thunder_protocol() {
        use std::str::FromStr;
        use std::net::Ipv4Addr;
        use heartbeater::singlenet::packets::{Packet, PacketFactory};

        let mut tp1 = Packet::thunder_protocol("05802278989@HYXY.XY",
                                               Ipv4Addr::from_str("10.0.0.1").unwrap(),
                                               Some(1472483020),
                                               None,
                                               None);
        let mut tp2 = Packet::thunder_protocol("05802278989@HYXY.XY",
                                               Ipv4Addr::from_str("10.0.0.1").unwrap(),
                                               Some(1472483020),
                                               Some("ffb0b2af94693fd1ba4c93e6b9aebd3f"),
                                               None);
        let tp1_bytes = tp1.as_bytes(true);
        let tp2_bytes = tp2.as_bytes(true);
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
        assert_eq!(*tp1_bytes, real1_bytes);
        assert_eq!(*tp2_bytes, real2_bytes);
    }
}
