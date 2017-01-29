use std::io;

#[derive(Debug)]
pub enum ReadBytesError {
    // Expect length {}, got {}
    LengthMismatch(usize, usize),
    // IO Error from std library
    IOError(io::Error),
}

pub trait ReaderHelper: io::Read {
    fn read_bytes(&mut self, required_length: usize) -> Result<Vec<u8>, ReadBytesError> {
        let mut bytes_container: Vec<u8> = vec![0; required_length];
        match self.read(&mut bytes_container) {
            Ok(length) => {
                if length != required_length {
                    Err(ReadBytesError::LengthMismatch(required_length, length))
                } else {
                    Ok(bytes_container)
                }
            }
            Err(e) => Err(ReadBytesError::IOError(e)),
        }
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