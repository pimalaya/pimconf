//! Unified email address to service configs search.

pub mod all;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
pub mod first;
pub mod providers;
pub mod types;
