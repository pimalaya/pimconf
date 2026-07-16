//! RFC 6186 SRV-based mail service discovery.

#[cfg(feature = "client")]
pub mod client;
pub mod discover;
pub mod srv;

pub mod service;
