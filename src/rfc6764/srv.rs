//! # DNS SRV query coroutine (RFC 6764)
//!
//! RFC 6764 §3 publishes four SRV qnames per domain:
//!
//! - `_caldav._tcp.<domain>`   plain HTTP CalDAV
//! - `_caldavs._tcp.<domain>`  HTTPS CalDAV
//! - `_carddav._tcp.<domain>`  plain HTTP CardDAV
//! - `_carddavs._tcp.<domain>` HTTPS CardDAV
//!
//! The SRV exchange itself is service-agnostic, so this module just
//! re-exports the generic coroutine defined in [`crate::rfc6186::srv`]
//! and lets the rfc6764 [`discover`] orchestrator feed it the four
//! CalDAV/CardDAV qnames.
//!
//! [`discover`]: crate::rfc6764::discover

pub use crate::rfc6186::srv::{DiscoveryDnsSrv, DiscoveryDnsSrvError, SrvRecord};
