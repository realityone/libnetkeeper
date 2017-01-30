use std::io;
use common::reader::{ReadBytesError, ReaderHelper};

pub mod heartbeater;

#[derive(Debug)]
pub enum DrCOMValidateError {
    CodeMismatch(u8),
    PacketReadError(ReadBytesError),
}

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

    fn validate_stream<R>(input: &mut io::BufReader<R>) -> Result<(), DrCOMValidateError>
        where R: io::Read
    {
        let code_bytes = try!(input.read_bytes(1).map_err(DrCOMValidateError::PacketReadError));
        let code = code_bytes[0];
        if code == Self::unexpected_code() {
            return Err(DrCOMValidateError::CodeMismatch(code));
        }
        Ok(())
    }
}
