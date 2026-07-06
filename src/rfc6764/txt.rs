//! # RFC 6764 §4 DNS TXT `path` discovery coroutine
//!
//! [`DiscoveryWebdavTxt`] wraps the shared [`DiscoveryDnsTxt`]
//! coroutine to query the TXT record at a CalDAV/CardDAV SRV name
//! (e.g. `_carddavs._tcp.example.org`) and extract its `path` key
//! (RFC 6764 §4). That key carries the context path of the service on
//! the host named by the matching SRV record, letting a client skip
//! the `.well-known` round-trip.
//!
//! Per RFC 1035 §3.3.14 a TXT record is a sequence of length-prefixed
//! character-strings; the coroutine concatenates them before looking
//! for the `path=` key. A name with no `path` record resolves to
//! `None` (normal: the caller then falls back to `.well-known`); only
//! a DNS-level failure resolves to an error.

use core::str;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::trace;
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::dns::{DiscoveryDnsTxt, DiscoveryDnsTxtError},
};

/// Errors emitted by [`DiscoveryWebdavTxt`].
#[derive(Debug, Error)]
pub enum DiscoveryWebdavTxtError {
    #[error(transparent)]
    Dns(#[from] DiscoveryDnsTxtError),
}

/// I/O-free coroutine that queries a CalDAV/CardDAV SRV name for its
/// RFC 6764 §4 TXT `path` key, completing with the context path or
/// `None` when the name publishes no `path` record.
pub struct DiscoveryWebdavTxt {
    txt: DiscoveryDnsTxt,
}

impl DiscoveryWebdavTxt {
    /// Builds a coroutine that queries TXT records for `qname` (a full
    /// SRV name such as `_carddavs._tcp.example.org`). `resolver` must
    /// be a `tcp://host:port` DNS-over-TCP resolver URL.
    pub fn new(qname: impl ToString, resolver: Url) -> Self {
        Self {
            txt: DiscoveryDnsTxt::new(qname, resolver),
        }
    }
}

impl DiscoveryCoroutine for DiscoveryWebdavTxt {
    type Yield = DiscoveryYield;
    type Return = Result<Option<String>, DiscoveryWebdavTxtError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match self.txt.resume(arg) {
            DiscoveryCoroutineState::Yielded(y) => DiscoveryCoroutineState::Yielded(y),
            DiscoveryCoroutineState::Complete(Err(err)) => {
                DiscoveryCoroutineState::Complete(Err(err.into()))
            }
            DiscoveryCoroutineState::Complete(Ok(records)) => {
                for record in records {
                    let mut joined = Vec::new();

                    // TODO: restore when the domain new API is
                    // released:
                    //
                    // for cs in record.rdata.iter() {
                    //     joined.extend_from_slice(&cs.octets);
                    // }
                    for cs in record.data().iter() {
                        joined.extend_from_slice(cs);
                    }

                    let Some(value) = joined.strip_prefix(b"path=") else {
                        trace!("no `path=` key in TXT record, skip");
                        continue;
                    };

                    let Ok(path) = str::from_utf8(value) else {
                        trace!("`path=` TXT value is not valid UTF-8, skip");
                        continue;
                    };

                    let path = path.trim();
                    if path.is_empty() {
                        trace!("`path=` TXT value is empty, skip");
                        continue;
                    }

                    trace!("found RFC 6764 TXT path `{path}`");
                    return DiscoveryCoroutineState::Complete(Ok(Some(path.to_string())));
                }

                DiscoveryCoroutineState::Complete(Ok(None))
            }
        }
    }
}
