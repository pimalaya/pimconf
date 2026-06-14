//! RFC 6764 SRV-based CalDAV/CardDAV service discovery.

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
pub mod discover;
#[cfg(feature = "client")]
pub mod resolve;
pub mod srv;
pub mod types;
#[cfg(feature = "client")]
pub mod well_known;
