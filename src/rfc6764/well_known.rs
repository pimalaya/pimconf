//! # `.well-known/{caldav,carddav}` redirect probe (RFC 6764 §5)
//!
//! [`DiscoveryWellKnown`] sends one HTTP GET to `<origin>/.well-known/{service}`
//! and reports the DAV context root: a 3xx redirect resolves to
//! `Some(Location)`, any non-redirect response resolves to `None` (the
//! probe found nothing authoritative on that origin). It reuses the
//! generic RFC 8615 probe from [`io_http`] and only adds the
//! [`DiscoveryYield`] plumbing so the std client can route bytes
//! through the matching stream.
//!
//! Discovery runs unauthenticated by design (RFC 6764 bootstrap); the
//! per-user principal walk that needs credentials lives in the WebDAV
//! client, not here.

use alloc::boxed::Box;

use io_http::{
    coroutine::{HttpCoroutine, HttpCoroutineState, HttpYield},
    rfc8615::well_known::{Http11WellKnown, Http11WellKnownError},
};
use log::trace;
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6764::service::DiscoveryDavService,
};

/// Errors emitted by [`DiscoveryWellKnown`].
#[derive(Debug, Error)]
pub enum DiscoveryWellKnownError {
    /// The underlying HTTP well-known request or response failed.
    #[error(transparent)]
    Http(#[from] Http11WellKnownError),
}

/// I/O-free `.well-known` redirect probe. Yields its origin URL on
/// every step so the std client routes bytes through the matching
/// HTTPS stream. Completes with the redirect target, or `None` when the
/// origin did not redirect.
pub struct DiscoveryWellKnown {
    origin: Url,
    state: State,
}

impl DiscoveryWellKnown {
    /// Builds a probe for `service` against `origin`, a scheme + host
    /// + port root such as `https://carddav.example.com/`.
    pub fn new(origin: Url, service: DiscoveryDavService) -> Self {
        let state = match Http11WellKnown::prepare_request(origin.as_str(), service.service_name())
        {
            Ok(request) => State::Probe(Box::new(Http11WellKnown::new(request))),
            Err(err) => State::Failed(Some(err.into())),
        };

        Self { origin, state }
    }
}

impl DiscoveryCoroutine for DiscoveryWellKnown {
    type Yield = DiscoveryYield;
    type Return = Result<Option<Url>, DiscoveryWellKnownError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Failed(err) => {
                let err = err
                    .take()
                    .expect("DiscoveryWellKnown resumed after completion");
                DiscoveryCoroutineState::Complete(Err(err))
            }
            State::Probe(probe) => match probe.resume(arg) {
                HttpCoroutineState::Yielded(HttpYield::WantsRead) => {
                    DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                        url: self.origin.clone(),
                    })
                }
                HttpCoroutineState::Yielded(HttpYield::WantsWrite(bytes)) => {
                    DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                        url: self.origin.clone(),
                        bytes,
                    })
                }
                HttpCoroutineState::Complete(Ok(output)) => match output.redirect_url {
                    Some(url) => {
                        trace!("well-known redirected to {url}");
                        DiscoveryCoroutineState::Complete(Ok(Some(url)))
                    }
                    None => {
                        trace!(
                            "well-known returned {} without redirect",
                            *output.response.status
                        );
                        DiscoveryCoroutineState::Complete(Ok(None))
                    }
                },
                HttpCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(err.into()))
                }
            },
        }
    }
}

enum State {
    Probe(Box<Http11WellKnown>),
    Failed(Option<DiscoveryWellKnownError>),
}
