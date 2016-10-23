use std::io;

#[derive(Debug)]
pub enum ReadBytesError {
    // Expect length {}, got {}
    LengthMismatch(usize, usize),
    // Unexpected bytes
    UnexpectedBytes(Vec<u8>),
    // IO Error from std library
    IOError(io::Error),
}

#[macro_export]
macro_rules! read_bytes {
    ($r:expr, $n:expr) => (
        {
            let result: Result<Vec<u8>, ReadBytesError>;
            let mut bytes_container: Vec<u8> = vec![0; $n];
            result = match $r.read(&mut bytes_container) {
                Ok(length) => {
                    if length != $n {
                        Err(ReadBytesError::LengthMismatch($n, length))
                    } else {
                        Ok(bytes_container)
                    }
                },
                Err(e) => {
                    Err(ReadBytesError::IOError(e))
                },
            };
            result 
        }
    )
}

#[test]
fn test_read_bytes() {
    use std::io::{BufReader, Read};

    let bytes: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut buffer = BufReader::new(&bytes as &[u8]);

    let bytes03 = read_bytes!(&mut buffer, 3).unwrap();
    assert_eq!(bytes03, vec![1, 2, 3]);

    let bytes45 = read_bytes!(&mut buffer, 2).unwrap();
    assert_eq!(bytes45, vec![4, 5]);

    let bytes611 = read_bytes!(&mut buffer, 6);
    assert!(bytes611.is_err());
}