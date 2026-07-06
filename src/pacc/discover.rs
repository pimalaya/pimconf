//! # PACC discovery coroutine
//!
//! [`DiscoveryPacc`] performs the full PACC exchange defined by
//! [draft-ietf-mailmaint-pacc-02] in three steps, in order:
//!
//! 1. HTTPS GET the well-known URL
//!    `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`
//!    and keep the raw response bytes.
//! 2. DNS TXT lookup for `_ua-auto-config.<domain>`. Each record is
//!    parsed as a `v=UAAC1; a=sha256; d=<base64>` tag set; the first
//!    record whose decoded `d` digest constant-time matches a SHA-256
//!    of the raw HTTP body wins.
//! 3. Once a record matches, parse the raw bytes as JSON and yield
//!    the resulting [`PaccConfig`].
//!
//! Per RFC 1035 §3.3.14 a TXT record is a sequence of length-prefixed
//! character-strings. Long values get split across multiple
//! character-strings; the coroutine concatenates them (no separator,
//! per RFC 6376 §3.6.2.2 / RFC 7208 §3.3) before parsing.
//!
//! Each yielded event carries the [`Url`] of the endpoint the
//! coroutine wants to talk to: the well-known PACC URL for the HTTPS
//! fetch and a `tcp://host:port` resolver URL for the DNS digest
//! lookup. The runtime is expected to maintain one stream per
//! `(scheme, host, port)`.
//!
//! [draft-ietf-mailmaint-pacc-02]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02

use core::mem;

use alloc::{
    format, str,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use log::trace;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    pacc::types::PaccConfig,
    shared::{
        dns::{DiscoveryDnsTxt, DiscoveryDnsTxtError},
        http::{HttpGet, HttpGetError},
    },
};

/// Errors that can occur during a single PACC discovery.
#[derive(Debug, Error)]
pub enum DiscoveryPaccError {
    #[error("PACC URL for domain `{1}` is not valid")]
    InvalidUrl(#[source] ParseError, String),
    #[error("no `_ua-auto-config` TXT record matched the configuration body")]
    NoValidTxtRecord,
    #[error("PACC body matched the published digest but is not valid JSON")]
    Json(#[source] serde_json::Error),

    #[error(transparent)]
    Http(#[from] HttpGetError),
    #[error(transparent)]
    Dns(#[from] DiscoveryDnsTxtError),
}

#[derive(Default)]
enum State {
    Get,
    Verify,
    #[default]
    Done,
}

/// I/O-free coroutine that performs the full PACC discovery
/// (fetch → digest verification → JSON parse) for a given domain.
pub struct DiscoveryPacc {
    state: State,
    fetch: HttpGet,
    verify: DiscoveryDnsTxt,
    raw_body: Vec<u8>,
}

impl DiscoveryPacc {
    /// Builds the well-known PACC URL for `domain`:
    /// `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`.
    pub fn url(domain: impl AsRef<str>) -> Result<Url, DiscoveryPaccError> {
        let d = domain.as_ref().trim_matches('.');
        let url = format!("https://ua-auto-config.{d}/.well-known/user-agent-configuration.json");
        Url::parse(&url).map_err(|err| DiscoveryPaccError::InvalidUrl(err, d.to_string()))
    }

    /// Builds a discoverer for `domain`. The `resolver` URL must use
    /// a `tcp://host:port` form and is yielded back by the inner DNS
    /// coroutine on every `WantsRead` / `WantsWrite` so the runtime
    /// can route the bytes to the correct stream.
    pub fn new(domain: impl AsRef<str>, resolver: Url) -> Result<Self, DiscoveryPaccError> {
        let url = Self::url(domain.as_ref())?;
        let qname = format!("_ua-auto-config.{}", domain.as_ref().trim_matches('.'));

        Ok(Self {
            state: State::Get,
            fetch: HttpGet::new(url),
            verify: DiscoveryDnsTxt::new(qname, resolver),
            raw_body: Vec::new(),
        })
    }
}

impl DiscoveryCoroutine for DiscoveryPacc {
    type Yield = DiscoveryYield;
    type Return = Result<PaccConfig, DiscoveryPaccError>;

    fn resume(
        &mut self,
        mut arg: Option<&[u8]>,
    ) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        loop {
            match mem::take(&mut self.state) {
                State::Get => match self.fetch.resume(arg.take()) {
                    DiscoveryCoroutineState::Yielded(y) => {
                        self.state = State::Get;
                        return DiscoveryCoroutineState::Yielded(y);
                    }
                    DiscoveryCoroutineState::Complete(Ok(bytes)) => {
                        self.raw_body = bytes;
                        self.state = State::Verify;
                    }
                    DiscoveryCoroutineState::Complete(Err(err)) => {
                        return DiscoveryCoroutineState::Complete(Err(err.into()));
                    }
                },
                State::Verify => match self.verify.resume(arg.take()) {
                    DiscoveryCoroutineState::Yielded(y) => {
                        self.state = State::Verify;
                        return DiscoveryCoroutineState::Yielded(y);
                    }
                    DiscoveryCoroutineState::Complete(Err(err)) => {
                        return DiscoveryCoroutineState::Complete(Err(err.into()));
                    }
                    DiscoveryCoroutineState::Complete(Ok(records)) => {
                        for record in records {
                            let mut config = Vec::new();

                            // TODO: restore when the domain new API
                            // is released:
                            //
                            // for data in record.rdata.iter() {
                            //     config.extend_from_slice(&data.octets);
                            // }
                            for data in record.data().iter() {
                                config.extend_from_slice(data);
                            }

                            let Ok(config) = str::from_utf8(&config) else {
                                trace!("invalid UTF-8 TXT record, skip");
                                continue;
                            };

                            let mut v = None;
                            let mut a = None;
                            let mut d = None;

                            for tag in config.split(';') {
                                let Some((name, val)) = tag.split_once('=') else {
                                    continue;
                                };

                                match name.trim() {
                                    n if n.eq_ignore_ascii_case("v") => v = Some(val.trim()),
                                    n if n.eq_ignore_ascii_case("a") => a = Some(val.trim()),
                                    n if n.eq_ignore_ascii_case("d") => d = Some(val.trim()),
                                    _ => continue,
                                }
                            }

                            let (Some(v), Some(a), Some(d)) = (v, a, d) else {
                                trace!("missing v, a or d in TXT record, skip");
                                continue;
                            };

                            if !v.eq_ignore_ascii_case("UAAC1") {
                                trace!("invalid `v`: expect `UAAC1` got `{v}`, skip");
                                continue;
                            }

                            if !a.eq_ignore_ascii_case("sha256") {
                                trace!("invalid `a`: expect `sha256` got `{a}`, skip");
                                continue;
                            }

                            let expected_digest = match BASE64.decode(d) {
                                Ok(digest) => {
                                    trace!("expected digest: {digest:x?}");
                                    digest
                                }
                                Err(err) => {
                                    trace!("invalid base64 digest `{d}`, skip: {err}");
                                    continue;
                                }
                            };

                            let actual_digest = Sha256::digest(&self.raw_body);
                            trace!("actual digest: {actual_digest:x?}");

                            if !bool::from(expected_digest.ct_eq(&actual_digest)) {
                                trace!("digest mismatch, skip");
                                continue;
                            }

                            return match serde_json::from_slice(&self.raw_body) {
                                Ok(config) => DiscoveryCoroutineState::Complete(Ok(config)),
                                Err(err) => DiscoveryCoroutineState::Complete(Err(
                                    DiscoveryPaccError::Json(err),
                                )),
                            };
                        }

                        return DiscoveryCoroutineState::Complete(Err(
                            DiscoveryPaccError::NoValidTxtRecord,
                        ));
                    }
                },
                State::Done => panic!("DiscoveryPacc::resume called after completion"),
            }
        }
    }
}
