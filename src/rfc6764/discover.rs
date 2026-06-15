//! # Combined RFC 6764 SRV discovery coroutine
//!
//! [`DiscoveryWebdavSrv`] runs the four RFC 6764 §3 SRV queries
//! (`_caldav._tcp.<domain>`, `_caldavs._tcp.<domain>`,
//! `_carddav._tcp.<domain>`, `_carddavs._tcp.<domain>`) in series,
//! picks the best record per service (lowest priority, highest weight
//! on ties; already sorted by [`DiscoveryDnsSrv`]), and yields a
//! single [`WebdavSrvReport`] when all four steps have completed.
//!
//! A per-service DNS failure (`InvalidQname`, `QueryTooLarge`,
//! `InvalidResponse`) terminates the whole coroutine with
//! [`DiscoveryWebdavSrvError`]; empty SRV answers do not, the matching
//! slot is simply left as `None` in the report.

use core::mem;

use alloc::{
    format,
    string::{String, ToString},
};

use domain::new::{
    base::{
        Record,
        name::{NameBuf, RevNameBuf},
    },
    rdata::Srv,
};
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6186::types::SrvService,
    rfc6764::{
        srv::{DiscoveryDnsSrv, DiscoveryDnsSrvError},
        types::WebdavSrvReport,
    },
};

/// Errors emitted by [`DiscoveryWebdavSrv`].
#[derive(Debug, Error)]
pub enum DiscoveryWebdavSrvError {
    #[error("DNS SRV lookup for `_caldav._tcp` failed: {0}")]
    Caldav(#[source] DiscoveryDnsSrvError),
    #[error("DNS SRV lookup for `_caldavs._tcp` failed: {0}")]
    Caldavs(#[source] DiscoveryDnsSrvError),
    #[error("DNS SRV lookup for `_carddav._tcp` failed: {0}")]
    Carddav(#[source] DiscoveryDnsSrvError),
    #[error("DNS SRV lookup for `_carddavs._tcp` failed: {0}")]
    Carddavs(#[source] DiscoveryDnsSrvError),
}

#[derive(Default)]
enum State {
    Caldav(DiscoveryDnsSrv),
    Caldavs(DiscoveryDnsSrv),
    Carddav(DiscoveryDnsSrv),
    Carddavs(DiscoveryDnsSrv),
    #[default]
    Done,
}

/// I/O-free combined coroutine that runs the four RFC 6764 SRV
/// queries and assembles their best records into a [`WebdavSrvReport`].
pub struct DiscoveryWebdavSrv {
    state: State,
    domain: String,
    resolver: Url,
    report: WebdavSrvReport,
}

impl DiscoveryWebdavSrv {
    /// Builds the orchestrator. `resolver` must be a `tcp://host:port`
    /// URL pointing at a DNS-over-TCP resolver; it is yielded back on
    /// every `WantsRead` / `WantsWrite` so the runtime can route the
    /// bytes to the correct stream.
    pub fn new(domain: impl AsRef<str>, resolver: Url) -> Self {
        let domain = domain.as_ref().trim_matches('.').to_string();
        let caldav = DiscoveryDnsSrv::new(format!("_caldav._tcp.{domain}"), resolver.clone());

        Self {
            state: State::Caldav(caldav),
            domain,
            resolver,
            report: WebdavSrvReport::default(),
        }
    }
}

impl DiscoveryCoroutine for DiscoveryWebdavSrv {
    type Yield = DiscoveryYield;
    type Return = Result<WebdavSrvReport, DiscoveryWebdavSrvError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::Caldav(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    self.report.caldav = records.into_iter().next().map(into_service);
                    self.state = State::Caldavs(DiscoveryDnsSrv::new(
                        format!("_caldavs._tcp.{}", self.domain),
                        self.resolver.clone(),
                    ));
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Caldav(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryWebdavSrvError::Caldav(err)))
                }
            },
            State::Caldavs(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    self.report.caldavs = records.into_iter().next().map(into_service);
                    self.state = State::Carddav(DiscoveryDnsSrv::new(
                        format!("_carddav._tcp.{}", self.domain),
                        self.resolver.clone(),
                    ));
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Caldavs(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryWebdavSrvError::Caldavs(err)))
                }
            },
            State::Carddav(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    self.report.carddav = records.into_iter().next().map(into_service);
                    self.state = State::Carddavs(DiscoveryDnsSrv::new(
                        format!("_carddavs._tcp.{}", self.domain),
                        self.resolver.clone(),
                    ));
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Carddav(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryWebdavSrvError::Carddav(err)))
                }
            },
            State::Carddavs(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    self.report.carddavs = records.into_iter().next().map(into_service);
                    DiscoveryCoroutineState::Complete(Ok(mem::take(&mut self.report)))
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Carddavs(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryWebdavSrvError::Carddavs(err)))
                }
            },
            State::Done => panic!("DiscoveryWebdavSrv::resume called after completion"),
        }
    }
}

fn into_service(record: Record<RevNameBuf, Srv<NameBuf>>) -> SrvService {
    SrvService {
        host: record
            .rdata
            .target
            .to_string()
            .trim_end_matches('.')
            .to_string(),
        port: record.rdata.port.get(),
        priority: record.rdata.priority.get(),
        weight: record.rdata.weight.get(),
    }
}
