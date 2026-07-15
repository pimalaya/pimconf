//! Types shared across RFC 6764 CalDAV/CardDAV discovery (SRV records
//! and `.well-known` URIs).

use alloc::{format, string::String};

use serde::{Deserialize, Serialize};

use crate::rfc6186::types::SrvService;

/// CalDAV vs CardDAV: selects the SRV service labels and the
/// `.well-known` path used by RFC 6764 discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DiscoveryDavService {
    /// CalDAV (`_caldav(s)._tcp`, `/.well-known/caldav`).
    Caldav,
    /// CardDAV (`_carddav(s)._tcp`, `/.well-known/carddav`).
    Carddav,
}

impl DiscoveryDavService {
    /// The `.well-known` request path, leading slash included
    /// (RFC 6764 §5).
    pub fn well_known_path(self) -> &'static str {
        match self {
            Self::Caldav => "/.well-known/caldav",
            Self::Carddav => "/.well-known/carddav",
        }
    }

    /// The bare well-known service name (RFC 8615 registry entry), as
    /// expected by [`io_http::rfc8615::well_known`].
    pub fn service_name(self) -> &'static str {
        match self {
            Self::Caldav => "caldav",
            Self::Carddav => "carddav",
        }
    }

    /// The RFC 6764 §3 SRV/TXT query name for this service on `domain`,
    /// e.g. `_carddavs._tcp.example.org` (secure) or
    /// `_carddav._tcp.example.org` (plain).
    pub fn srv_qname(self, secure: bool, domain: &str) -> String {
        let service = match (self, secure) {
            (Self::Caldav, true) => "_caldavs",
            (Self::Caldav, false) => "_caldav",
            (Self::Carddav, true) => "_carddavs",
            (Self::Carddav, false) => "_carddav",
        };

        format!("{service}._tcp.{domain}")
    }
}

/// Best-of-each-service summary produced by the combined RFC 6764
/// flow. Each slot carries the SRV record with the lowest priority
/// (and highest weight on ties), or `None` when that service did not
/// publish a record on the queried domain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebdavSrvReport {
    pub caldav: Option<SrvService>,
    pub caldavs: Option<SrvService>,
    pub carddav: Option<SrvService>,
    pub carddavs: Option<SrvService>,
}
