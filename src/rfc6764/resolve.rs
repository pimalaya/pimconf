//! # Combined RFC 6764 resolve coroutine
//!
//! [`ResolveDav`] turns a bare domain into a CalDAV/CardDAV context
//! root. It runs the RFC 6764 §3 SRV lookups, picks the best record
//! for the requested service (secure `_caldavs`/`_carddavs` first,
//! plain `_caldav`/`_carddav` next), then probes `.well-known` on that
//! origin to follow the context-path redirect. When the domain
//! publishes no SRV record it falls back to `https://<domain>:443/`.
//!
//! Composing the DNS step (over the `tcp://` resolver) and the HTTPS
//! well-known step in one coroutine works because every yield carries
//! its endpoint URL: the std client routes each step through the
//! matching stream in its [`StreamPool`].
//!
//! [`StreamPool`]: crate::shared::pool::StreamPool

use core::mem;

use alloc::{
    format,
    string::{String, ToString},
};

use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6186::types::SrvService,
    rfc6764::{
        discover::{DiscoveryRfc6764, DiscoveryRfc6764Error},
        types::DavService,
        well_known::{WellKnown, WellKnownError},
    },
};

/// Errors emitted by [`ResolveDav`].
#[derive(Debug, Error)]
pub enum ResolveDavError {
    #[error(transparent)]
    Srv(#[from] DiscoveryRfc6764Error),
    #[error(transparent)]
    WellKnown(#[from] WellKnownError),
    #[error("RFC 6764 resolve built an invalid origin URL `{0}`: {1}")]
    InvalidOrigin(String, #[source] url::ParseError),
}

/// I/O-free `domain -> DAV context root` resolver.
pub struct ResolveDav {
    service: DavService,
    domain: String,
    state: State,
}

impl ResolveDav {
    /// Builds a resolver for `service` on `domain`. `resolver` is the
    /// `tcp://host:port` DNS-over-TCP resolver URL used for the SRV
    /// lookups.
    pub fn new(domain: impl AsRef<str>, service: DavService, resolver: Url) -> Self {
        let domain = domain.as_ref().trim_matches('.').to_string();
        let srv = DiscoveryRfc6764::new(&domain, resolver);

        Self {
            service,
            domain,
            state: State::Srv(srv),
        }
    }

    fn origin(
        &self,
        secure: Option<SrvService>,
        plain: Option<SrvService>,
    ) -> Result<Url, ResolveDavError> {
        let (scheme, host, port) = match (secure, plain) {
            (Some(s), _) => ("https", s.host, s.port),
            (None, Some(p)) => ("http", p.host, p.port),
            (None, None) => ("https", self.domain.clone(), 443),
        };

        let raw = format!("{scheme}://{host}:{port}/");
        Url::parse(&raw).map_err(|err| ResolveDavError::InvalidOrigin(raw, err))
    }
}

impl DiscoveryCoroutine for ResolveDav {
    type Yield = DiscoveryYield;
    type Return = Result<Url, ResolveDavError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::Srv(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(report)) => {
                    let (secure, plain) = match self.service {
                        DavService::Caldav => (report.caldavs, report.caldav),
                        DavService::Carddav => (report.carddavs, report.carddav),
                    };

                    let origin = match self.origin(secure, plain) {
                        Ok(origin) => origin,
                        Err(err) => return DiscoveryCoroutineState::Complete(Err(err)),
                    };

                    self.state = State::WellKnown(WellKnown::new(origin, self.service));
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Srv(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(err.into()))
                }
            },
            State::WellKnown(mut wk) => match wk.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(url)) => {
                    DiscoveryCoroutineState::Complete(Ok(url))
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::WellKnown(wk);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(err.into()))
                }
            },
            State::Done => panic!("ResolveDav::resume called after completion"),
        }
    }
}

#[derive(Default)]
enum State {
    Srv(DiscoveryRfc6764),
    WellKnown(WellKnown),
    #[default]
    Done,
}
