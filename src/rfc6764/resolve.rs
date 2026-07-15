//! # Combined RFC 6764 resolve coroutine
//!
//! [`DiscoveryDavResolve`] turns a bare domain into a CalDAV/CardDAV context
//! root by chaining the three RFC 6764 mechanisms:
//!
//! 1. SRV lookups (§3), picking the best record for the requested
//!    service (secure `_caldavs`/`_carddavs` first, plain
//!    `_caldav`/`_carddav` next) to fix the origin host and port.
//! 2. A TXT `path` lookup (§4) on that same SRV name: when present,
//!    its path is joined onto the origin and returned, skipping the
//!    `.well-known` round-trip.
//! 3. Otherwise a `.well-known` probe (§5) on the origin, following
//!    the context-path redirect.
//!
//! When the domain publishes no SRV record it falls back to
//! `https://<domain>:443/` and probes `.well-known` there.
//!
//! Composing the DNS steps (over the `tcp://` resolver) and the HTTPS
//! well-known step in one coroutine works because every yield carries
//! its endpoint URL: the std client routes each step through the
//! matching stream in its [`DiscoveryStreamPool`].
//!
//! [`DiscoveryStreamPool`]: crate::shared::pool::DiscoveryStreamPool

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
    rfc6186::types::SrvService,
    rfc6764::{
        discover::{DiscoveryWebdavSrv, DiscoveryWebdavSrvError},
        txt::{DiscoveryWebdavTxt, DiscoveryWebdavTxtError},
        types::DiscoveryDavService,
        well_known::{DiscoveryWellKnown, DiscoveryWellKnownError},
    },
};

/// Errors emitted by [`DiscoveryDavResolve`].
#[derive(Debug, Error)]
pub enum DiscoveryDavResolveError {
    #[error(transparent)]
    Srv(#[from] DiscoveryWebdavSrvError),
    #[error(transparent)]
    Txt(#[from] DiscoveryWebdavTxtError),
    #[error(transparent)]
    DiscoveryWellKnown(#[from] DiscoveryWellKnownError),
    #[error("RFC 6764 resolve built an invalid origin URL `{0}`: {1}")]
    InvalidOrigin(String, #[source] url::ParseError),
    #[error("RFC 6764 resolve could not apply TXT path `{0}`: {1}")]
    InvalidPath(String, #[source] url::ParseError),
}

/// I/O-free `domain -> DAV context root` resolver.
pub struct DiscoveryDavResolve {
    service: DiscoveryDavService,
    domain: String,
    resolver: Url,
    state: State,
}

impl DiscoveryDavResolve {
    /// Builds a resolver for `service` on `domain`. `resolver` is the
    /// `tcp://host:port` DNS-over-TCP resolver URL used for the SRV
    /// and TXT lookups.
    pub fn new(domain: impl AsRef<str>, service: DiscoveryDavService, resolver: Url) -> Self {
        let domain = domain.as_ref().trim_matches('.').to_string();
        let srv = DiscoveryWebdavSrv::new(&domain, resolver.clone());

        Self {
            service,
            domain,
            resolver,
            state: State::Srv(srv),
        }
    }

    fn origin(
        &self,
        secure: Option<SrvService>,
        plain: Option<SrvService>,
    ) -> Result<Url, DiscoveryDavResolveError> {
        let (scheme, host, port) = match (secure, plain) {
            (Some(s), _) => ("https", s.host, s.port),
            (None, Some(p)) => ("http", p.host, p.port),
            (None, None) => ("https", self.domain.clone(), 443),
        };

        let raw = format!("{scheme}://{host}:{port}/");
        Url::parse(&raw).map_err(|err| DiscoveryDavResolveError::InvalidOrigin(raw, err))
    }
}

impl DiscoveryCoroutine for DiscoveryDavResolve {
    type Yield = DiscoveryYield;
    type Return = Result<Url, DiscoveryDavResolveError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::Srv(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(report)) => {
                    let (secure, plain) = match self.service {
                        DiscoveryDavService::Caldav => (report.caldavs, report.caldav),
                        DiscoveryDavService::Carddav => (report.carddavs, report.carddav),
                    };

                    // RFC 6764 §6 only queries the TXT `path` record for
                    // a name that actually published an SRV record; with
                    // no SRV record there is no service name to look up.
                    let txt_qname = match (&secure, &plain) {
                        (Some(_), _) => Some(self.service.srv_qname(true, &self.domain)),
                        (None, Some(_)) => Some(self.service.srv_qname(false, &self.domain)),
                        (None, None) => None,
                    };

                    let origin = match self.origin(secure, plain) {
                        Ok(origin) => origin,
                        Err(err) => return DiscoveryCoroutineState::Complete(Err(err)),
                    };

                    self.state = match txt_qname {
                        Some(qname) => {
                            let txt = DiscoveryWebdavTxt::new(qname, self.resolver.clone());
                            State::Txt { txt, origin }
                        }
                        None => {
                            let probe = DiscoveryWellKnown::new(origin.clone(), self.service);
                            State::DiscoveryWellKnown { probe, origin }
                        }
                    };
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Srv(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                // NOTE: an unreachable resolver (mobile networks
                // routinely block outbound DNS) must not kill the
                // resolve: proceed as if no SRV record was published
                // and probe `.well-known` on the domain itself, whose
                // HTTPS socket resolves through the OS.
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    debug!("skip failed SRV lookups, probe .well-known");
                    trace!("{err:?}");

                    let origin = match self.origin(None, None) {
                        Ok(origin) => origin,
                        Err(err) => return DiscoveryCoroutineState::Complete(Err(err)),
                    };

                    let probe = DiscoveryWellKnown::new(origin.clone(), self.service);
                    self.state = State::DiscoveryWellKnown { probe, origin };
                    self.resume(None)
                }
            },
            State::Txt { mut txt, origin } => match txt.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(Some(path))) => match origin.join(&path) {
                    Ok(root) => DiscoveryCoroutineState::Complete(Ok(root)),
                    Err(err) => DiscoveryCoroutineState::Complete(Err(
                        DiscoveryDavResolveError::InvalidPath(path, err),
                    )),
                },
                DiscoveryCoroutineState::Complete(Ok(None)) => {
                    let probe = DiscoveryWellKnown::new(origin.clone(), self.service);
                    self.state = State::DiscoveryWellKnown { probe, origin };
                    self.resume(None)
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Txt { txt, origin };
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(err.into()))
                }
            },
            State::DiscoveryWellKnown { mut probe, origin } => match probe.resume(arg) {
                DiscoveryCoroutineState::Complete(Ok(url)) => {
                    DiscoveryCoroutineState::Complete(Ok(url.unwrap_or(origin)))
                }
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::DiscoveryWellKnown { probe, origin };
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(err.into()))
                }
            },
            State::Done => panic!("DiscoveryDavResolve::resume called after completion"),
        }
    }
}

#[derive(Default)]
enum State {
    Srv(DiscoveryWebdavSrv),
    Txt {
        txt: DiscoveryWebdavTxt,
        origin: Url,
    },
    DiscoveryWellKnown {
        probe: DiscoveryWellKnown,
        origin: Url,
    },
    #[default]
    Done,
}
