//! Mozilla Thunderbird autoconfiguration discovery.

#[cfg(feature = "client")]
pub mod client;
pub mod isp;
pub mod mailconf;
pub mod mx;

pub mod config;
