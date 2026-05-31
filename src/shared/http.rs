//! # Shared HTTP module
//!
//! [`HttpGet`] sends one HTTP/1.1 GET on a fully-qualified [`Url`]
//! and returns the raw response body bytes. It rejects redirects and
//! non-success status codes: both autoconfig and PACC need the
//! response that came from the original origin.
//!
//! Body deserialization is the caller's responsibility: autoconfig
//! parses the bytes as XML, PACC parses them as JSON and also keeps
//! the raw bytes for digest verification.
//!
//! [`HttpGet`] sits at the io-http / pimconf boundary: it wraps
//! io-http's [`Http11Send`] and translates its
//! [`HttpCoroutineState`](io_http::coroutine::HttpCoroutineState)
//! into the pimconf shape, tagging every yielded I/O step with
//! the request [`Url`] so the std client can route through
//! [`crate::shared::pool::StreamPool`].

use alloc::{borrow::ToOwned, vec::Vec};

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

use crate::coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield};

/// Errors that can occur during a single HTTP GET exchange.
#[derive(Debug, Error)]
pub enum HttpGetError {
    #[error("HTTP GET returned unexpected status {0}")]
    Status(u16),
    #[error("HTTP GET reached unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
    #[error(transparent)]
    Http(#[from] Http11SendError),
}

/// I/O-free coroutine that performs one HTTP GET and yields the
/// response body as raw bytes.
pub struct HttpGet {
    url: Url,
    send: Http11Send,
}

impl HttpGet {
    /// Builds a GET for `url`. Pair with an HTTP session opened on
    /// the same URL.
    pub fn new(url: Url) -> Self {
        let host = url.host_str().unwrap_or("127.0.0.1").to_owned();
        let req = HttpRequest::get(url.clone()).header("Host", host);

        Self {
            url,
            send: Http11Send::new(req),
        }
    }
}

impl DiscoveryCoroutine for HttpGet {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<u8>, HttpGetError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if !response.status.is_success() =>
            {
                trace!("{response:?}");
                DiscoveryCoroutineState::Complete(Err(HttpGetError::Status(*response.status)))
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                trace!("{response:?}");
                DiscoveryCoroutineState::Complete(Ok(response.body))
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                    url: self.url.clone(),
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                    url: self.url.clone(),
                    bytes,
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { response, url, .. }) => {
                trace!("{response:?}");
                DiscoveryCoroutineState::Complete(Err(HttpGetError::Redirect {
                    url,
                    code: *response.status,
                }))
            }
            HttpCoroutineState::Complete(Err(err)) => {
                DiscoveryCoroutineState::Complete(Err(err.into()))
            }
        }
    }
}
