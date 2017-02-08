// copy from https://github.com/drcoms/drcom-generic
use std::io;
use std::fmt::Debug;

use common::reader::{ReadBytesError, ReaderHelper};

pub mod pppoe;
pub mod wired;

#[cfg(test)]
mod tests;

const PASSWORD_MAX_LEN: usize = 16;
const USERNAME_MAX_LEN: usize = 16;
const PACKET_MAGIC_NUMBER: u16 = 0x0103u16;

pub trait DrCOMFlag: Debug {
    fn as_u32(&self) -> u32;
}

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
