//! # `.well-known/{caldav,carddav}` redirect probe (RFC 6764 §5)
//!
//! [`WellKnown`] sends one HTTP GET to `<origin>/.well-known/{service}`
//! and resolves the DAV context root: a 3xx redirect resolves to its
//! `Location`, any non-redirect response falls back to `origin`. Pair
//! it with an HTTP session opened on `origin` so the std client can
//! route the bytes through the matching stream.
//!
//! Discovery runs unauthenticated by design (RFC 6764 bootstrap); the
//! per-user principal walk that needs credentials lives in the WebDAV
//! client, not here.

use alloc::string::ToString;

use io_http::{
    coroutine::{HttpCoroutine, HttpCoroutineState},
    rfc9110::{
        request::HttpRequest,
        send::{HttpSendOutput, HttpSendYield},
    },
    rfc9112::send::{Http11Send, Http11SendError},
};
use log::trace;
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6764::types::DavService,
};

/// Errors emitted by [`WellKnown`].
#[derive(Debug, Error)]
pub enum WellKnownError {
    #[error(transparent)]
    Http(#[from] Http11SendError),
}

/// I/O-free `.well-known` redirect probe. Yields its origin URL on
/// every step so the std client routes bytes through the matching
/// HTTPS stream.
pub struct WellKnown {
    origin: Url,
    send: Http11Send,
}

impl WellKnown {
    /// Builds a probe for `service` against `origin`, a scheme + host
    /// + port root such as `https://carddav.example.com/`.
    pub fn new(origin: Url, service: DavService) -> Self {
        let mut url = origin.clone();
        url.set_path(service.well_known_path());

        let host = url.host_str().unwrap_or_default().to_string();
        let req = HttpRequest::get(url).header("Host", host);

        Self {
            origin,
            send: Http11Send::new(req),
        }
    }
}

impl DiscoveryCoroutine for WellKnown {
    type Yield = DiscoveryYield;
    type Return = Result<Url, WellKnownError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match self.send.resume(arg) {
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                    url: self.origin.clone(),
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                    url: self.origin.clone(),
                    bytes,
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, .. }) => {
                trace!("well-known redirected to {url}");
                DiscoveryCoroutineState::Complete(Ok(url))
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                trace!(
                    "well-known returned {} without redirect; falling back to origin",
                    *response.status
                );
                DiscoveryCoroutineState::Complete(Ok(self.origin.clone()))
            }
            HttpCoroutineState::Complete(Err(err)) => {
                DiscoveryCoroutineState::Complete(Err(err.into()))
            }
        }
    }
}
