//! # Combined RFC 8620 resolve coroutine
//!
//! [`ResolveJmap`] turns a bare domain into a JMAP Session resource
//! URL by chaining the two RFC 8620 §2.2 mechanisms:
//!
//! 1. An SRV lookup on `_jmap._tcp.<domain>`, picking the best record
//!    to fix the origin host and port (the session is always HTTPS).
//! 2. A `.well-known/jmap` probe on that origin, following any
//!    redirect chain to the session resource.
//!
//! When the domain publishes no SRV record it falls back to
//! `https://<domain>:443/` and probes `.well-known/jmap` there. An
//! origin answering neither a redirect nor 2xx/401 on the probe means
//! no JMAP service: the resolve completes with
//! [`ResolveJmapError::NotFound`].
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

use log::{debug, trace};
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6186::srv::DiscoveryDnsSrv,
    rfc8620::well_known::{JmapSessionResource, WellKnownJmap, WellKnownJmapError},
};

/// Errors emitted by [`ResolveJmap`].
#[derive(Debug, Error)]
pub enum ResolveJmapError {
    #[error(transparent)]
    WellKnown(#[from] WellKnownJmapError),
    #[error("RFC 8620 resolve built an invalid origin URL `{0}`: {1}")]
    InvalidOrigin(String, #[source] url::ParseError),
    #[error("RFC 8620 resolve found no JMAP session on `{0}`")]
    NotFound(Url),
}

/// I/O-free `domain -> JMAP session resource` resolver.
pub struct ResolveJmap {
    domain: String,
    state: State,
}

impl ResolveJmap {
    /// Builds a resolver for `domain`. `resolver` is the
    /// `tcp://host:port` DNS-over-TCP resolver URL used for the SRV
    /// lookup.
    pub fn new(domain: impl AsRef<str>, resolver: Url) -> Self {
        let domain = domain.as_ref().trim_matches('.').to_string();
        let srv = DiscoveryDnsSrv::new(format!("_jmap._tcp.{domain}"), resolver);

        Self {
            domain,
            state: State::Srv(srv),
        }
    }

    fn origin(&self, srv: Option<(String, u16)>) -> Result<Url, ResolveJmapError> {
        let (host, port) = srv.unwrap_or_else(|| (self.domain.clone(), 443));

        // RFC 8620 §2.2: the session resource is always HTTPS,
        // whatever the SRV record's port.
        let raw = format!("https://{host}:{port}/");
        Url::parse(&raw).map_err(|err| ResolveJmapError::InvalidOrigin(raw, err))
    }

    fn probe(
        &mut self,
        srv: Option<(String, u16)>,
    ) -> DiscoveryCoroutineState<DiscoveryYield, Result<JmapSessionResource, ResolveJmapError>>
    {
        let origin = match self.origin(srv) {
            Ok(origin) => origin,
            Err(err) => return DiscoveryCoroutineState::Complete(Err(err)),
        };

        let probe = WellKnownJmap::new(origin.clone());
        self.state = State::WellKnown { probe, origin };
        self.resume(None)
    }
}

impl DiscoveryCoroutine for ResolveJmap {
    type Yield = DiscoveryYield;
    type Return = Result<JmapSessionResource, ResolveJmapError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::Srv(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(records)) => {
                    // Best record first (lowest priority, highest
                    // weight), already sorted by the SRV coroutine.
                    let best = records.into_iter().next().map(|record| {
                        let srv = record.into_data();
                        let host = srv.target().to_string().trim_end_matches('.').to_string();
                        (host, srv.port())
                    });
                    self.probe(best)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Srv(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                // NOTE: an unreachable resolver (mobile networks
                // routinely block outbound DNS) must not kill the
                // resolve: proceed as if no SRV record was published
                // and probe `.well-known/jmap` on the domain itself,
                // whose HTTPS socket resolves through the OS.
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    debug!("skip failed SRV lookup, probe .well-known/jmap");
                    trace!("{err:?}");
                    self.probe(None)
                }
            },
            State::WellKnown { mut probe, origin } => match probe.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(Some(session))) => {
                    DiscoveryCoroutineState::Complete(Ok(session))
                }
                DiscoveryCoroutineState::Complete(Ok(None)) => {
                    DiscoveryCoroutineState::Complete(Err(ResolveJmapError::NotFound(origin)))
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::WellKnown { probe, origin };
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(err.into()))
                }
            },
            State::Done => panic!("ResolveJmap::resume called after completion"),
        }
    }
}

#[derive(Default)]
enum State {
    Srv(DiscoveryDnsSrv),
    WellKnown {
        probe: WellKnownJmap,
        origin: Url,
    },
    #[default]
    Done,
}
