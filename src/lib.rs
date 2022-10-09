#![deny(clippy::all)]
#![warn(clippy::cargo)]
#![forbid(unsafe_code)]

mod jwt;

mod client;
pub use self::client::{Error, Config, Client};
