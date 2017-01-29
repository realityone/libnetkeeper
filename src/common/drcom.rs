use std::io;
use common::reader::{ReadBytesError, ReaderHelper};

pub trait DrCOMCommon {
    fn code() -> u8 {
        7u8
    }

    fn pack_count(count: u32) -> u8 {
        (count & 0xFF) as u8
    }
}

pub trait DrCOMResponseCommon {
    fn unexpected_code() -> u8 {
        0x4du8
    }

    fn validate_packet<R>(input: &mut io::BufReader<R>) -> Result<(), ReadBytesError>
        where R: io::Read
    {
        let code_bytes = try!(input.read_bytes(1));
        let code = code_bytes[0];
        if code == Self::unexpected_code() {
            return Err(ReadBytesError::UnexpectedBytes(code_bytes));
        }
        Ok(())
    }
}
