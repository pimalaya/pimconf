//! # Combined RFC 6186 SRV discovery coroutine
//!
//! [`DiscoverySrv`] runs the three RFC 6186 SRV queries
//! (`_imap._tcp.<domain>`, `_imaps._tcp.<domain>`,
//! `_submission._tcp.<domain>`) in series, picks the best record per
//! service (lowest priority, highest weight on ties; already sorted
//! by [`DiscoveryDnsSrv`]), and yields a single [`SrvReport`] when
//! all three steps have completed.
//!
//! A per-service DNS failure (`InvalidQname`, `QueryTooLarge`,
//! `InvalidResponse`) terminates the whole coroutine with
//! [`DiscoverySrvError`]; empty SRV answers do not, the matching slot
//! is simply left as `None` in the report.

use core::mem;

use alloc::{
    format,
    string::{String, ToString},
};

use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6186::{
        srv::{DiscoveryDnsSrv, DiscoveryDnsSrvError, SrvRecord},
        types::{SrvReport, SrvService},
    },
};

/// Errors emitted by [`DiscoverySrv`].
#[derive(Debug, Error)]
pub enum DiscoverySrvError {
    #[error("DNS SRV lookup for `_imap._tcp` failed: {0}")]
    Imap(#[source] DiscoveryDnsSrvError),
    #[error("DNS SRV lookup for `_imaps._tcp` failed: {0}")]
    Imaps(#[source] DiscoveryDnsSrvError),
    #[error("DNS SRV lookup for `_submission._tcp` failed: {0}")]
    Submission(#[source] DiscoveryDnsSrvError),
}

#[derive(Default)]
enum State {
    Imap(DiscoveryDnsSrv),
    Imaps(DiscoveryDnsSrv),
    Submission(DiscoveryDnsSrv),
    #[default]
    Done,
}

/// I/O-free combined coroutine that runs the three RFC 6186 SRV
/// queries and assembles their best records into a [`SrvReport`].
pub struct DiscoverySrv {
    state: State,
    domain: String,
    resolver: Url,
    report: SrvReport,
}

impl DiscoverySrv {
    /// Builds the orchestrator. `resolver` must be a `tcp://host:port`
    /// URL pointing at a DNS-over-TCP resolver; it is yielded back on
    /// every `WantsRead` / `WantsWrite` so the runtime can route the
    /// bytes to the correct stream.
    pub fn new(domain: impl AsRef<str>, resolver: Url) -> Self {
        let domain = domain.as_ref().trim_matches('.').to_string();
        let imap = DiscoveryDnsSrv::new(format!("_imap._tcp.{domain}"), resolver.clone());

        Self {
            state: State::Imap(imap),
            domain,
            resolver,
            report: SrvReport::default(),
        }
    }
}

impl DiscoveryCoroutine for DiscoverySrv {
    type Yield = DiscoveryYield;
    type Return = Result<SrvReport, DiscoverySrvError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::Imap(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    self.report.imap = records.into_iter().next().map(into_service);
                    self.state = State::Imaps(DiscoveryDnsSrv::new(
                        format!("_imaps._tcp.{}", self.domain),
                        self.resolver.clone(),
                    ));
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Imap(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoverySrvError::Imap(err)))
                }
            },
            State::Imaps(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    self.report.imaps = records.into_iter().next().map(into_service);
                    self.state = State::Submission(DiscoveryDnsSrv::new(
                        format!("_submission._tcp.{}", self.domain),
                        self.resolver.clone(),
                    ));
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Imaps(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoverySrvError::Imaps(err)))
                }
            },
            State::Submission(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    self.report.submission = records.into_iter().next().map(into_service);
                    DiscoveryCoroutineState::Complete(Ok(mem::take(&mut self.report)))
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Submission(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoverySrvError::Submission(err)))
                }
            },
            State::Done => panic!("DiscoverySrv::resume called after completion"),
        }
    }
}

fn into_service(record: SrvRecord) -> SrvService {
    SrvService {
        host: record
            .rdata
            .name
            .to_string()
            .trim_end_matches('.')
            .to_string(),
        port: record.rdata.port.get(),
        priority: record.rdata.priority.get(),
        weight: record.rdata.weight.get(),
    }
}
