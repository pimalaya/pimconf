#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! I/O-free discovery of PIM (email, calendar, contacts) services.
//!
//! Given an email address or a domain, the coroutines here find where
//! a user's mail, calendar or contacts live and how to authenticate,
//! by probing the mechanisms providers publish: Mozilla autoconfig,
//! PACC, DNS SRV records (RFC 6186), CalDAV and CardDAV well-known and
//! SRV discovery (RFC 6764), the JMAP session resource (RFC 8620) and
//! OAuth 2.0 authorization-server and protected-resource metadata
//! (RFC 8414, RFC 9728).
//!
//! Like the rest of the io-* family the crate is layered. The
//! coroutine layer is no_std state machines that emit read and write
//! requests without performing any I/O, one module per mechanism or
//! RFC. The client layer wraps them into standard, blocking clients
//! over a stream. The CLI layer, behind the cli feature, exposes
//! discovery as a command-line binary.
//!
//! The compose module reduces the individual mechanisms into a single
//! ranked list of service configurations, and the shared module holds
//! the DNS and HTTP plumbing they have in common. Every module sits
//! behind a cargo feature named after its mechanism or RFC.

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;
#[cfg(any(feature = "client", feature = "cli"))]
extern crate std;

#[cfg(feature = "autoconfig")]
pub mod autoconfig;
#[cfg(feature = "cli")]
pub mod cli;
// NOTE: the compose bricks need at least one discovery mechanism to
// compose; without a mechanism there is nothing to reduce. The std
// orchestrator inside (compose::client) is further gated on the
// stream feature.
#[cfg(any(
    feature = "autoconfig",
    feature = "pacc",
    feature = "rfc6186",
    feature = "rfc6764",
    feature = "rfc8620"
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
