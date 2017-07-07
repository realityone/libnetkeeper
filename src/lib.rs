#![allow(dead_code)]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
#![cfg_attr(not(feature = "dev"), allow(unknown_lints))]

extern crate rustc_serialize;
extern crate linked_hash_map;
extern crate crypto as rust_crypto;
extern crate md4;
extern crate chrono;
extern crate byteorder;
extern crate rand;

#[cfg(feature="drcom")]
pub mod drcom;
#[cfg(feature="netkeeper")]
pub mod netkeeper;
#[cfg(feature="ghca")]
pub mod ghca;
#[cfg(feature="ipclient")]
pub mod ipclient;
#[cfg(feature="singlenet")]
pub mod singlenet;
#[cfg(feature="srun3k")]
pub mod srun3k;

pub mod common;
mod crypto;

#[cfg(test)]
mod tests {}
