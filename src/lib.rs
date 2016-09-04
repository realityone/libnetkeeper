extern crate rustc_serialize;
extern crate openssl;
extern crate time;

mod netkeeper;
mod singlenet;
mod utils;

#[cfg(test)]
mod tests {
    #[test]
    fn test_netkeeper_username_encrypt() {
        use netkeeper::load_default_dialer;
        let dialer = load_default_dialer();
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "\r\n:R#(P 5005802278989@HYXY.XY");
    }

    #[test]
    fn test_singlenet_username_encrypt() {
        use singlenet::load_default_dialer;
        let dialer = load_default_dialer();
        let encrypted = dialer.encrypt_account("05802278989@HYXY.XY", Some(1472483020));
        assert_eq!(encrypted, "~LL_k6ecvpj2mrjA_05802278989@HYXY.XY");
    }
}
