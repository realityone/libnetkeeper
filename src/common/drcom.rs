pub trait DrCOMCommon {
    fn code() -> u8 {
        7u8
    }

    fn pack_count(count: u32) -> u8 {
        (count & 0xFF) as u8
    }
}