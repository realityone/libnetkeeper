# libnetkeeper

[![Build Status](https://travis-ci.org/realityone/libnetkeeper.svg?branch=master)](https://travis-ci.org/realityone/libnetkeeper)

The netkeeper toolkits write in rust.

We want integrate more algorithms in rust to avoid suffering memory management in C/C++.
And rust can be happy to cross compile to another platform, such as `MIPS` or `ARM`.

## State

Current we support these algorithms with fully test case:

- [SingleNet](https://github.com/singlenet/Anti_teNelgniS)
- Netkeeper
- [DrCOM](https://github.com/drcoms/drcom-generic)

And some not tested algorithms:

- SRun3k
- GHCA
- IPClient

## Documents

> TBD

## Develop

First of all, you have to install rust and use nightly build, [rustup](https://www.rustup.rs) is recommended.

### Run Test

```bash
$ cargo test --features=dev
...
test singlenet::dialer::test_hash_key ... ok
test netkeeper_tests::test_netkeeper_heartbeat_parse ... ok
test singlenet::heartbeater::test_authenticator ... ok
test singlenet::heartbeater::test_calc_seq ... ok
test singlenet_tests::test_bubble_request ... ok
test singlenet_tests::test_real_time_bubble_request ... ok
test singlenet_tests::test_register_request ... ok
test singlenet_tests::test_singlenet_username_encrypt ... ok
test srun3k_tests::test_srun3k_v20_username_encrypt ... ok
test singlenet_tests::test_keepalive_request_generate_and_parse ... ok

test result: ok. 36 passed; 0 failed; 0 ignored; 0 measured

   Doc-tests netkeeper

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured
```

### Work With Stable Rust

`libnetkeeper` should be compatible with stable rust in `default` feature.

If you are using stable rust, everything will be fine except `clippy`.

```bash
$ cargo build --features=default --release
   Compiling libnetkeeper v0.1.0 (file:///Users/realityone/Documents/Softs/libnetkeeper)
    Finished release [optimized] target(s) in 5.50 secs
```

### Issue or Pull Request

Please fell free to open an issue or create a pull request if you have any question.

### License

`libnetkeeper` is under GPLv3 License.