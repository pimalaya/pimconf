//! # Mozilla autoconfig `mailconf=<URL>` TXT discovery coroutine
//!
//! [`DiscoveryMailconf`] wraps the shared [`DiscoveryDnsTxt`]
//! coroutine to query TXT records for a domain and locate one
//! prefixed with `mailconf=`. Per the Mozilla
//! [Autoconfiguration] convention, that prefix introduces a URL
//! pointing at an autoconfig XML document.
//!
//! Per RFC 1035 §3.3.14 a TXT record is a sequence of length-prefixed
//! character-strings. Long values may be split across multiple
//! character-strings; the coroutine concatenates them (no separator,
//! per RFC 6376 §3.6.2.2 / RFC 7208 §3.3) before checking the prefix.
//!
//! Per-record failures (missing `mailconf=` prefix, non-UTF-8 value,
//! malformed URL) are skipped silently: the coroutine only fails if
//! no record at the queried name yields a valid URL.
//!
//! [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration

use core::str;

use alloc::{string::ToString, vec::Vec};

use log::trace;
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::dns::{DiscoveryDnsTxt, DiscoveryDnsTxtError},
};

/// Errors that can occur during a single mailconf discovery.
#[derive(Debug, Error)]
pub enum DiscoveryMailconfError {
    #[error(transparent)]
    Dns(#[from] DiscoveryDnsTxtError),
    #[error("no `mailconf=` TXT record found for the queried domain")]
    NoMailconfRecord,
}

/// I/O-free coroutine that performs a TXT lookup and extracts the
/// first valid `mailconf=<URL>` value.
pub struct DiscoveryMailconf {
    txt: DiscoveryDnsTxt,
}

impl DiscoveryMailconf {
    /// Returns a coroutine ready to query `domain` for TXT records on
    /// the first [`resume`]. `resolver` must be a `tcp://host:port`
    /// URL pointing at a DNS-over-TCP resolver.
    ///
    /// [`resume`]: DiscoveryMailconf::resume
    pub fn new(domain: impl ToString, resolver: Url) -> Self {
        Self {
            txt: DiscoveryDnsTxt::new(domain, resolver),
        }
    }
}

impl DiscoveryCoroutine for DiscoveryMailconf {
    type Yield = DiscoveryYield;
    type Return = Result<Url, DiscoveryMailconfError>;

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

                    let Some(value) = joined.strip_prefix(b"mailconf=") else {
                        trace!("no `mailconf=` prefix in TXT record, skip");
                        continue;
                    };

                    let Ok(url_str) = str::from_utf8(value) else {
                        trace!("`mailconf=` TXT value is not valid UTF-8, skip");
                        continue;
                    };

                    let Ok(url) = Url::parse(url_str.trim()) else {
                        trace!("`mailconf=` TXT value `{url_str}` is not a valid URL, skip");
                        continue;
                    };

                    return DiscoveryCoroutineState::Complete(Ok(url));
                }

                DiscoveryCoroutineState::Complete(Err(DiscoveryMailconfError::NoMailconfRecord))
            }
        }
    }
}
