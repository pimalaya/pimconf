//! # Per-URL ISP autoconfig HTTP+XML fetch
//!
//! [`DiscoveryIsp`] is a single-URL fetch coroutine: it drives one
//! [`DiscoveryHttpGet`] cycle and parses the response body as a Mozilla
//! [Autoconfiguration] XML document. URL selection and stream routing
//! are the runtime's responsibility: the caller pairs this coroutine
//! with one of the static URL helpers ([`main_url`], [`fallback_url`],
//! [`db_url`], [`all_urls`]) and keeps a single HTTP stream open
//! against that URL. The coroutine itself does not echo the URL on
//! `WantsRead` / `WantsWrite`; multi-URL orchestration is the
//! caller's responsibility.
//!
//! [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration
//! [`main_url`]: DiscoveryIsp::main_url
//! [`fallback_url`]: DiscoveryIsp::fallback_url
//! [`db_url`]: DiscoveryIsp::db_url
//! [`all_urls`]: DiscoveryIsp::all_urls

use alloc::{
    format,
    string::{FromUtf8Error, String},
};

use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    autoconfig::types::Autoconfig,
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::http::{DiscoveryHttpGet, DiscoveryHttpGetError},
};

/// Errors that can occur during a single ISP autoconfig HTTP exchange.
#[derive(Debug, Error)]
pub enum DiscoveryIspError {
    #[error("ISP call returned invalid UTF-8 body")]
    Utf8(#[source] FromUtf8Error),
    #[error("ISP call returned invalid XML body")]
    Xml(#[source] serde_xml_rs::Error),
    #[error(transparent)]
    Http(#[from] DiscoveryHttpGetError),
}

/// HTTP+XML fetch coroutine for a single ISP autoconfig URL.
pub struct DiscoveryIsp {
    get: DiscoveryHttpGet,
}

impl DiscoveryIsp {
    /// Builds the URL for the main ISP location
    /// (`http[s]://autoconfig.<domain>/mail/config-v1.1.xml?...`).
    pub fn main_url(
        local_part: impl AsRef<str>,
        domain: impl AsRef<str>,
        secure: bool,
    ) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let email = format!("{}@{domain}", local_part.as_ref());
        let s = if secure { "s" } else { "" };
        let url =
            format!("http{s}://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={email}");
        Url::parse(&url)
    }

    /// Builds the URL for the alternative ISP location
    /// (`http[s]://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`).
    pub fn fallback_url(domain: impl AsRef<str>, secure: bool) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let s = if secure { "s" } else { "" };
        let url = format!("http{s}://{domain}/.well-known/autoconfig/mail/config-v1.1.xml");
        Url::parse(&url)
    }

    /// Builds the URL for the Thunderbird ISPDB
    /// (`http[s]://autoconfig.thunderbird.net/v1.1/<domain>`).
    pub fn db_url(domain: impl AsRef<str>, secure: bool) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let s = if secure { "s" } else { "" };
        let url = format!("http{s}://autoconfig.thunderbird.net/v1.1/{domain}");
        Url::parse(&url)
    }

    /// Returns the five candidate URLs the runtime should try in
    /// order: secure and plaintext flavors of [`Self::main_url`] and
    /// [`Self::fallback_url`], then [`Self::db_url`] (secure only).
    pub fn all_urls(
        local_part: impl AsRef<str>,
        domain: impl AsRef<str>,
    ) -> Result<[Url; 5], ParseError> {
        let local_part = local_part.as_ref();
        let domain = domain.as_ref();

        Ok([
            Self::main_url(local_part, domain, true)?,
            Self::main_url(local_part, domain, false)?,
            Self::fallback_url(domain, true)?,
            Self::fallback_url(domain, false)?,
            Self::db_url(domain, true)?,
        ])
    }

    /// Builds a fetcher for `url`. The runtime is expected to hold a
    /// stream open on that URL for the lifetime of the coroutine.
    pub fn new(url: Url) -> Self {
        Self {
            get: DiscoveryHttpGet::new(url),
        }
    }
}

impl DiscoveryCoroutine for DiscoveryIsp {
    type Yield = DiscoveryYield;
    type Return = Result<Autoconfig, DiscoveryIspError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match self.get.resume(arg) {
            DiscoveryCoroutineState::Yielded(y) => DiscoveryCoroutineState::Yielded(y),
            DiscoveryCoroutineState::Complete(Err(err)) => {
                DiscoveryCoroutineState::Complete(Err(err.into()))
            }
            DiscoveryCoroutineState::Complete(Ok(bytes)) => {
                let body = match String::from_utf8(bytes) {
                    Ok(body) => body,
                    Err(err) => {
                        return DiscoveryCoroutineState::Complete(Err(DiscoveryIspError::Utf8(
                            err,
                        )));
                    }
                };

                match serde_xml_rs::from_str(&body) {
                    Ok(autoconfig) => DiscoveryCoroutineState::Complete(Ok(autoconfig)),
                    Err(err) => DiscoveryCoroutineState::Complete(Err(DiscoveryIspError::Xml(err))),
                }
            }
        }
    }
}
