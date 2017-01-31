use std::io;
use common::reader::{ReadBytesError, ReaderHelper};

pub mod pppoe;
pub mod wired;

#[derive(Debug)]
pub enum DrCOMValidateError {
    CodeMismatch(u8),
    PacketReadError(ReadBytesError),
}

pub trait DrCOMCommon {
    fn code() -> u8 {
        7u8
    }
}

pub trait DrCOMResponseCommon {
    fn validate_stream<R, V>(input: &mut io::BufReader<R>,
                             validator: V)
                             -> Result<(), DrCOMValidateError>
        where R: io::Read,
              V: FnOnce(u8) -> bool
    {
        let code_bytes = try!(input.read_bytes(1).map_err(DrCOMValidateError::PacketReadError));
        let code = code_bytes[0];
        if !validator(code) {
            return Err(DrCOMValidateError::CodeMismatch(code));
        }
        Ok(())
    }
}
