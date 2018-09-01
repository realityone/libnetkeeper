use ipclient::dialer::{Configuration, ISPCode, MACOpenPacket};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[test]
fn test_ipclient_macopener_packet() {
    let packet = MACOpenPacket::new(
        "a",
        Ipv4Addr::from_str("172.16.1.1").unwrap(),
        "40:61:86:87:9F:F1",
        ISPCode::CChinaUnicom,
    );
    let packet_bytes = packet.as_bytes(Configuration::GUET.hash_key()).unwrap();

    let real_bytes: Vec<u8> = vec![
        97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        172, 16, 1, 1, 52, 48, 58, 54, 49, 58, 56, 54, 58, 56, 55, 58, 57, 70, 58, 70, 49, 0, 0, 0,
        1, 0, 255, 189, 40, 90,
    ];
    assert_eq!(packet_bytes, real_bytes);
    let packet_err = MACOpenPacket::new(
        "05802278989@HYXY.XY05802278989@HYXY.XY05802278989@HYXY.\
         XY05802278989@HYXY.XY05802278989@HYXY.XY",
        Ipv4Addr::from_str("172.16.1.1").unwrap(),
        "40:61:86:87:9F:F1",
        ISPCode::CChinaUnicom,
    );
    assert!(packet_err.as_bytes(Configuration::GUET.hash_key()).is_err());
}
