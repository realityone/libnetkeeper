use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReadBytesError {
    #[error("expected {expected} bytes, but the stream ended after {actual}")]
    UnexpectedEof { expected: usize, actual: usize },

    #[error("failed to read from the stream")]
    Io(#[source] io::Error),
}

pub trait ReaderHelper: io::Read {
    fn read_bytes(&mut self, required_length: usize) -> Result<Vec<u8>, ReadBytesError> {
        let mut bytes = vec![0; required_length];
        let mut read_length = 0;

        while read_length < required_length {
            let remaining = bytes
                .get_mut(read_length..)
                .ok_or(ReadBytesError::UnexpectedEof {
                    expected: required_length,
                    actual: read_length,
                })?;
            match self.read(remaining) {
                Ok(0) => {
                    return Err(ReadBytesError::UnexpectedEof {
                        expected: required_length,
                        actual: read_length,
                    });
                }
                Ok(length) => {
                    read_length = read_length.saturating_add(length);
                }
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(ReadBytesError::Io(source)),
            }
        }

        Ok(bytes)
    }

    fn read_byte(&mut self) -> Result<u8, ReadBytesError> {
        self.read_exact_array().map(|[byte]| byte)
    }

    fn read_exact_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], ReadBytesError> {
        self.read_bytes(LENGTH)?
            .try_into()
            .map_err(|bytes: Vec<u8>| ReadBytesError::UnexpectedEof {
                expected: LENGTH,
                actual: bytes.len(),
            })
    }
}

impl<R: io::Read> ReaderHelper for io::BufReader<R> {}

#[test]
fn test_read_bytes() {
    let bytes: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut buffer = io::BufReader::new(&bytes as &[u8]);

    let bytes03 = buffer.read_bytes(3).unwrap();
    assert_eq!(bytes03, vec![1, 2, 3]);

    let bytes45 = buffer.read_bytes(2).unwrap();
    assert_eq!(bytes45, vec![4, 5]);

    let bytes611 = buffer.read_bytes(6);
    assert!(bytes611.is_err());
}
