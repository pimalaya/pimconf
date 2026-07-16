//! Plumbing shared across the discovery mechanisms: the DNS transport
//! and record coroutines, the HTTP GET helper, and the std client's
//! stream pool.

pub mod dns;
#[cfg(any(feature = "autoconfig", feature = "pacc"))]
pub mod http;
#[cfg(feature = "client")]
pub mod pool;
