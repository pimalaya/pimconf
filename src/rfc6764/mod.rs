//! RFC 6764 CalDAV/CardDAV service discovery.
//!
//! RFC 6764 locates CalDAV/CardDAV services through DNS SRV records
//! (§3), DNS TXT records (§4) and `.well-known` URIs (§5), used
//! together or separately. This module exposes all three: SRV lookups
//! ([`discover`]), the TXT `path` lookup ([`txt`]) and the
//! `.well-known` probe ([`well_known`]), plus a [`resolve`] coroutine
//! that chains them into a single `domain -> context root` walk.
//!
//! [`discover`]: crate::rfc6764::discover
//! [`txt`]: crate::rfc6764::txt
//! [`well_known`]: crate::rfc6764::well_known
//! [`resolve`]: crate::rfc6764::resolve

#[cfg(feature = "client")]
pub mod client;
pub mod discover;
pub mod resolve;
pub mod srv;
pub mod txt;
pub mod types;
pub mod well_known;
