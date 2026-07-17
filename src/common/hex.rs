pub trait ToHex {
    fn to_hex(&self) -> String;
}

static CHARS: &[u8] = b"0123456789abcdef";

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        let mut v = Vec::with_capacity(self.len() * 2);
        for &byte in self.iter() {
            v.push(CHARS[(byte >> 4) as usize]);
            v.push(CHARS[(byte & 0xf) as usize]);
        }

        String::from_utf8(v).expect("hex digits are valid UTF-8")
    }
}
