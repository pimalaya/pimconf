//! Types yielded by RFC 6764 SRV-based CalDAV/CardDAV discovery.

use serde::{Deserialize, Serialize};

use crate::rfc6186::types::SrvService;

/// CalDAV vs CardDAV: selects the SRV service labels and the
/// `.well-known` path used by RFC 6764 discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DavService {
    /// CalDAV (`_caldav(s)._tcp`, `/.well-known/caldav`).
    Caldav,
    /// CardDAV (`_carddav(s)._tcp`, `/.well-known/carddav`).
    Carddav,
}

impl DavService {
    /// The `.well-known` request path, leading slash included
    /// (RFC 6764 §5).
    pub fn well_known_path(self) -> &'static str {
        match self {
            Self::Caldav => "/.well-known/caldav",
            Self::Carddav => "/.well-known/carddav",
        }
    }
}

/// Best-of-each-service summary produced by the combined RFC 6764
/// flow. Each slot carries the SRV record with the lowest priority
/// (and highest weight on ties), or `None` when that service did not
/// publish a record on the queried domain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Rfc6764Report {
    pub caldav: Option<SrvService>,
    pub caldavs: Option<SrvService>,
    pub carddav: Option<SrvService>,
    pub carddavs: Option<SrvService>,
}
