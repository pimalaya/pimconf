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
#[cfg(feature = "cli")]
pub mod cli;
// The compose orchestrator needs the std stream substrate AND at least
// one discovery mechanism to compose; without a mechanism it has
// nothing to run.
#[cfg(all(
    feature = "stream",
    any(
        feature = "autoconfig",
        feature = "pacc",
        feature = "rfc6186",
        feature = "rfc6764",
        feature = "rfc8620"
    )
))]
pub mod compose;
#[cfg(any(
    feature = "autoconfig",
    feature = "pacc",
    feature = "rfc6186",
    feature = "rfc6764",
    feature = "rfc8620",
    feature = "rfc8414",
    feature = "rfc9728"
))]
pub mod coroutine;
#[cfg(feature = "pacc")]
pub mod pacc;
#[cfg(feature = "rfc6186")]
pub mod rfc6186;
#[cfg(feature = "rfc6764")]
pub mod rfc6764;
#[cfg(feature = "rfc8414")]
pub mod rfc8414;
#[cfg(feature = "rfc8620")]
pub mod rfc8620;
#[cfg(feature = "rfc8620")]
pub mod rfc9110;
#[cfg(feature = "rfc9728")]
pub mod rfc9728;
#[cfg(any(
    feature = "autoconfig",
    feature = "pacc",
    feature = "rfc6186",
    feature = "rfc6764",
    feature = "rfc8620"
))]
pub mod shared;
