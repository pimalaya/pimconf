#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;
#[cfg(any(feature = "client", feature = "cli"))]
extern crate std;

#[cfg(feature = "autoconfig")]
pub mod autoconfig;
#[cfg(any(
    feature = "autoconfig",
    feature = "pacc",
    feature = "rfc6186",
    feature = "rfc6764",
    feature = "rfc8620"
))]
pub mod coroutine;
#[cfg(feature = "pacc")]
pub mod pacc;
#[cfg(feature = "rfc6186")]
pub mod rfc6186;
#[cfg(feature = "rfc6764")]
pub mod rfc6764;
#[cfg(feature = "rfc8620")]
pub mod rfc8620;
#[cfg(feature = "search")]
pub mod search;
#[cfg(any(
    feature = "autoconfig",
    feature = "pacc",
    feature = "rfc6186",
    feature = "rfc6764",
    feature = "rfc8620"
))]
pub mod shared;
