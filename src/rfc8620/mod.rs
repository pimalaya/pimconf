//! RFC 8620 JMAP service autodiscovery.
//!
//! RFC 8620 §2.2 locates the JMAP Session resource through a DNS SRV
//! record (`_jmap._tcp.<domain>`, §2.2) and the `/.well-known/jmap`
//! URI (RFC 8615). This module exposes the `.well-known` probe
//! ([`well_known`]) plus a [`resolve`] coroutine that chains the SRV
//! lookup into a single `domain -> session URL` walk.
//!
//! [`well_known`]: crate::rfc8620::well_known
//! [`resolve`]: crate::rfc8620::resolve

pub mod resolve;
pub mod well_known;
