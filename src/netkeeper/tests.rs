use common::dialer::Dialer;
use crypto::cipher::AES_128_ECB;
use netkeeper::dialer::{Configuration, NetkeeperDialer};
use netkeeper::heartbeater::{Frame, Packet};
use std::io::BufReader;

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
    let real_bytes = vec![
        72, 82, 51, 48, 2, 5, 0, 0, 0, 160, 66, 100, 164, 73, 167, 41, 222, 211, 188, 8, 14, 110,
        252, 246, 121, 119, 79, 18, 254, 193, 72, 163, 54, 136, 248, 60, 221, 177, 221, 0, 13, 10,
        146, 141, 142, 244, 89, 10, 176, 106, 162, 242, 204, 38, 73, 34, 55, 137, 97, 126, 9, 165,
        70, 31, 157, 168, 71, 197, 187, 163, 41, 229, 167, 53, 122, 190, 181, 154, 87, 111, 227,
        123, 69, 129, 67, 51, 81, 241, 122, 165, 40, 52, 89, 244, 80, 95, 124, 126, 112, 49, 174,
        27, 56, 156, 90, 142, 92, 15, 46, 198, 142, 57, 101, 139, 41, 47, 207, 36, 92, 216, 48,
        176, 133, 151, 154, 242, 123, 13, 94, 251, 108, 64, 46, 78, 158, 38, 66, 163, 102, 61, 241,
        207, 125, 163, 239, 153, 239, 75, 85, 0, 97, 237, 41, 117, 94, 251, 126, 197, 12, 140, 230,
        63, 40, 52, 240, 253, 15, 197, 60, 48,
    ];
    assert_eq!(packet_bytes, real_bytes);
}

#[test]
fn test_netkeeper_heartbeat_parse() {
    let encrypter = AES_128_ECB::new(b"xlzjhrprotocol3x").unwrap();
    let origin_bytes: Vec<u8> = vec![
        72, 82, 51, 48, 2, 5, 0, 0, 0, 160, 66, 100, 164, 73, 167, 41, 222, 211, 188, 8, 14, 110,
        252, 246, 121, 119, 79, 18, 254, 193, 72, 163, 54, 136, 248, 60, 221, 177, 221, 0, 13, 10,
        146, 141, 142, 244, 89, 10, 176, 106, 162, 242, 204, 38, 73, 34, 55, 137, 97, 126, 9, 165,
        70, 31, 157, 168, 71, 197, 187, 163, 41, 229, 167, 53, 122, 190, 181, 154, 87, 111, 227,
        123, 69, 129, 67, 51, 81, 241, 122, 165, 40, 52, 89, 244, 80, 95, 124, 126, 112, 49, 174,
        27, 56, 156, 90, 142, 92, 15, 46, 198, 142, 57, 101, 139, 41, 47, 207, 36, 92, 216, 48,
        176, 133, 151, 154, 242, 123, 13, 94, 251, 108, 64, 46, 78, 158, 38, 66, 163, 102, 61, 241,
        207, 125, 163, 239, 153, 239, 75, 85, 0, 97, 237, 41, 117, 94, 251, 126, 197, 12, 140, 230,
        63, 40, 52, 240, 253, 15, 197, 60, 48,
    ];

    let mut buffer = BufReader::new(&origin_bytes as &[u8]);
    let packet = Packet::from_bytes(&mut buffer, &encrypter, None).unwrap();
    let packet_bytes = packet.as_bytes(&encrypter).unwrap();
    assert_eq!(packet_bytes, origin_bytes);
}
