//! # HTTP authentication scheme probe (RFC 9110 §11.6.1)
//!
//! [`DiscoveryProbeAuth`] GETs a URL unauthenticated, follows any redirect
//! chain, and reports the lowercased authentication schemes the
//! terminal response advertised through `WWW-Authenticate` (a 401 per
//! RFC 9110 §11.6.1; empty when the response carried none). This is
//! how a client learns which schemes an HTTP service accepts, per
//! service: account-level configuration documents cannot express that
//! a provider takes passwords on CardDAV but only bearer tokens on
//! JMAP (fastmail does exactly this).

use alloc::{string::String, vec::Vec};

use io_http::{
    coroutine::{HttpCoroutine, HttpCoroutineState, HttpYield},
    rfc8615::well_known::{Http11WellKnown, Http11WellKnownError},
    rfc9110::{request::HttpRequest, response::HttpResponse},
};
use log::trace;
use thiserror::Error;
use url::Url;

use crate::coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield};

/// Redirect hops followed before giving up on a looping chain.
const MAX_HOPS: u8 = 5;

/// Errors emitted by [`DiscoveryProbeAuth`].
#[derive(Debug, Error)]
pub enum DiscoveryProbeAuthError {
    #[error(transparent)]
    Http(#[from] Http11WellKnownError),
}

/// I/O-free authentication scheme probe. Yields its current target
/// URL on every step so the std client routes bytes through the
/// matching HTTPS stream, hopping streams when a redirect crosses
/// origins. Completes with the schemes the terminal response
/// advertised (empty when it advertised none, or the redirect chain
/// looped).
pub struct DiscoveryProbeAuth {
    target: Url,
    hops: u8,
    probe: Http11WellKnown,
}

impl DiscoveryProbeAuth {
    /// Builds a probe against `target`, any HTTP URL.
    pub fn new(target: Url) -> Self {
        Self::request(target, 0)
    }

    /// One GET of the redirect walk, against `target`.
    fn request(target: Url, hops: u8) -> Self {
        let probe = Http11WellKnown::new(HttpRequest::get(target.clone()));

        Self {
            target,
            hops,
            probe,
        }
    }
}

impl DiscoveryCoroutine for DiscoveryProbeAuth {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<String>, DiscoveryProbeAuthError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match self.probe.resume(arg) {
            HttpCoroutineState::Yielded(HttpYield::WantsRead) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                    url: self.target.clone(),
                })
            }
            HttpCoroutineState::Yielded(HttpYield::WantsWrite(bytes)) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                    url: self.target.clone(),
                    bytes,
                })
            }
            HttpCoroutineState::Complete(Ok(output)) => match output.redirect_url {
                Some(next) => {
                    if self.hops >= MAX_HOPS {
                        trace!("auth probe redirected more than {MAX_HOPS} times, give up");
                        return DiscoveryCoroutineState::Complete(Ok(Vec::new()));
                    }

                    trace!("auth probe redirected to {next}");
                    *self = Self::request(next, self.hops + 1);
                    self.resume(None)
                }
                None => {
                    let schemes = auth_schemes(&output.response);
                    trace!(
                        "auth probe answered {} at {} (schemes {schemes:?})",
                        *output.response.status, self.target,
                    );
                    DiscoveryCoroutineState::Complete(Ok(schemes))
                }
            },
            HttpCoroutineState::Complete(Err(err)) => {
                DiscoveryCoroutineState::Complete(Err(err.into()))
            }
        }
    }
}

/// Lowercased scheme names of every `WWW-Authenticate` challenge of
/// the response (parsed by io-http's rfc9110 challenge module).
pub fn auth_schemes(response: &HttpResponse) -> Vec<String> {
    response
        .challenges()
        .into_iter()
        .map(|challenge| challenge.scheme)
        .collect()
}
