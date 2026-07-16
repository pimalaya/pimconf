//! SRV service records produced by RFC 6186 mail service discovery.

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Best-of-each-service summary produced by the combined RFC 6186
/// flow. Each slot carries the SRV record with the lowest priority
/// (and highest weight on ties), or `None` when that service did not
/// publish a record on the queried domain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiscoverySrvReport {
    /// Best IMAP SRV record (`_imap._tcp`), or `None` if absent.
    pub imap: Option<DiscoverySrvService>,
    /// Best IMAPS SRV record (`_imaps._tcp`), or `None` if absent.
    pub imaps: Option<DiscoverySrvService>,
    /// Best message submission SRV record (`_submission._tcp`), or
    /// `None` if absent.
    pub submission: Option<DiscoverySrvService>,
}

/// One SRV record stripped to the fields a mail client actually uses:
/// where to connect (`host`, `port`) and how the runtime picked it
/// among siblings (`priority`, `weight`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoverySrvService {
    /// Hostname of the server to connect to.
    pub host: String,
    /// TCP port the server listens on.
    pub port: u16,
    /// SRV priority: lower values are preferred.
    pub priority: u16,
    /// SRV weight: higher values are preferred among equal-priority
    /// records.
    pub weight: u16,
}
