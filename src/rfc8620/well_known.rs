//! # `.well-known/jmap` session probe (RFC 8620 §2.2)
//!
//! [`WellKnownJmap`] GETs `<origin>/.well-known/jmap` and follows any
//! redirect chain (RFC 8620 locates the session resource "following
//! any redirects"; apex domains routinely bounce through marketing
//! hosts), then reports the JMAP Session resource from the terminal
//! response: a 2xx or 401 resolves to the final URL (the session
//! resource lives there; 401 only means it wants credentials,
//! discovery runs unauthenticated by design) along with the
//! authentication schemes the 401 advertised, and any other status
//! resolves to `None` (no JMAP behind that origin). It reuses the
//! generic RFC 8615 probe from [`io_http`] and only adds the redirect
//! walk and the [`DiscoveryYield`] plumbing so the std client can
//! route each hop through the matching stream.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

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

/// Errors emitted by [`WellKnownJmap`].
#[derive(Debug, Error)]
pub enum WellKnownJmapError {
    #[error(transparent)]
    Http(#[from] Http11WellKnownError),
}

/// The JMAP Session resource located by the probe: its URL and the
/// lowercased authentication schemes its unauthenticated 401
/// advertised through `WWW-Authenticate` (empty when the terminal
/// response was a 2xx, or advertised nothing).
#[derive(Clone, Debug)]
pub struct JmapSessionResource {
    pub url: Url,
    pub auth_schemes: Vec<String>,
}

/// I/O-free `.well-known/jmap` session probe. Yields its current
/// target URL on every step so the std client routes bytes through
/// the matching HTTPS stream, hopping streams when a redirect crosses
/// origins. Completes with the session resource, or `None` when the
/// origin serves no JMAP.
pub struct WellKnownJmap {
    target: Url,
    hops: u8,
    probe: Http11WellKnown,
}

impl WellKnownJmap {
    /// Builds a probe against `origin`, a scheme + host + port root
    /// such as `https://api.example.com/`.
    pub fn new(origin: Url) -> Self {
        let mut target = origin;
        target.set_path("/.well-known/jmap");
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

impl DiscoveryCoroutine for WellKnownJmap {
    type Yield = DiscoveryYield;
    type Return = Result<Option<JmapSessionResource>, WellKnownJmapError>;

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
                        trace!("well-known jmap redirected more than {MAX_HOPS} times, give up");
                        return DiscoveryCoroutineState::Complete(Ok(None));
                    }

                    trace!("well-known jmap redirected to {next}");
                    *self = Self::request(next, self.hops + 1);
                    self.resume(None)
                }
                None => match *output.response.status {
                    200..=299 | 401 => {
                        let auth_schemes = auth_schemes(&output.response);
                        trace!(
                            "well-known jmap answered {}, session lives at {} (schemes {:?})",
                            *output.response.status, self.target, auth_schemes
                        );
                        DiscoveryCoroutineState::Complete(Ok(Some(JmapSessionResource {
                            url: self.target.clone(),
                            auth_schemes,
                        })))
                    }
                    status => {
                        trace!("well-known jmap answered {status}, no JMAP behind this origin");
                        DiscoveryCoroutineState::Complete(Ok(None))
                    }
                },
            },
            HttpCoroutineState::Complete(Err(err)) => {
                DiscoveryCoroutineState::Complete(Err(err.into()))
            }
        }
    }
}

/// Lowercased scheme names of every `WWW-Authenticate` challenge
/// (RFC 9110 §11.6.1). Challenges and their parameters share the comma
/// separator, so a chunk only counts as a scheme when its first token
/// carries no `=` (parameters always do).
fn auth_schemes(response: &HttpResponse) -> Vec<String> {
    let mut schemes = Vec::new();

    for (name, value) in &response.headers {
        if !name.eq_ignore_ascii_case("WWW-Authenticate") {
            continue;
        }

        for chunk in value.split(',') {
            let Some(token) = chunk.split_whitespace().next() else {
                continue;
            };

            if !token.contains('=') {
                schemes.push(token.to_ascii_lowercase().to_string());
            }
        }
    }

    schemes
}
