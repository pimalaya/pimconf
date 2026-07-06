//! # Standard, blocking autoconfig discovery client
//!
//! [`DiscoveryAutoconfigClientStd`] exposes one method per Mozilla
//! autoconfig primitive ([`isp`], [`isp_fallback`], [`ispdb`],
//! [`mx`], [`mailconf`]); each runs exactly one coroutine end-to-end
//! through a local [`StreamPool`]. Composition (try several
//! candidates, fall back through MX-derived parents, race variants in
//! parallel, ...) is the caller's responsibility.
//!
//! Construction:
//!
//! - Light: [`new`] returns a client with only the default `tcp`
//!   factory registered. Plug `http` / `https` factories via
//!   [`with_factory`].
//! - Full: under the `stream` feature, chain [`with_tls`] after
//!   [`new`] to auto-register `http` / `https` factories backed by
//!   [`pimalaya_stream::std::stream::StreamStd`].
//!
//! [`new`]: DiscoveryAutoconfigClientStd::new
//! [`with_factory`]: DiscoveryAutoconfigClientStd::with_factory
//! [`with_tls`]: DiscoveryAutoconfigClientStd::with_tls
//! [`isp`]: DiscoveryAutoconfigClientStd::isp
//! [`isp_fallback`]: DiscoveryAutoconfigClientStd::isp_fallback
//! [`ispdb`]: DiscoveryAutoconfigClientStd::ispdb
//! [`mx`]: DiscoveryAutoconfigClientStd::mx
//! [`mailconf`]: DiscoveryAutoconfigClientStd::mailconf

use std::io;

use alloc::vec::Vec;

// TODO: restore when the domain new API is released:
// use domain::new::{
//     base::{
//         Record,
//         name::{NameBuf, RevNameBuf},
//     },
//     rdata::Mx,
// };
use thiserror::Error;
use url::Url;

use crate::{
    autoconfig::{
        isp::{DiscoveryIsp, DiscoveryIspError},
        mailconf::{DiscoveryMailconf, DiscoveryMailconfError},
        mx::{DiscoveryDnsMx, DiscoveryDnsMxError, MxRecord},
        types::Autoconfig,
    },
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::pool::{Stream, StreamPool},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`DiscoveryAutoconfigClientStd`].
#[derive(Debug, Error)]
pub enum DiscoveryAutoconfigClientStdError {
    /// A single ISP fetch (main / fallback / db URL) failed.
    #[error(transparent)]
    Isp(#[from] DiscoveryIspError),
    /// The DNS MX coroutine errored out.
    #[error(transparent)]
    DnsMx(#[from] DiscoveryDnsMxError),
    /// The mailconf TXT coroutine errored out.
    #[error(transparent)]
    Mailconf(#[from] DiscoveryMailconfError),
    /// `DiscoveryIsp::*_url` could not build the candidate URL from
    /// the caller's input.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// [`StreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking Mozilla autoconfig discovery client.
pub struct DiscoveryAutoconfigClientStd {
    dns: Url,
    pool: StreamPool,
}

impl DiscoveryAutoconfigClientStd {
    /// Builds a client that resolves DNS lookups through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver).
    /// The underlying pool is pre-populated with the default `tcp`
    /// factory only; plug `http` / `https` factories via
    /// [`with_factory`] before calling any HTTPS-bound method, or
    /// chain [`with_tls`] under the `stream` feature.
    ///
    /// [`with_factory`]: Self::with_factory
    /// [`with_tls`]: Self::with_tls
    pub fn new(dns: Url) -> Self {
        Self {
            dns,
            pool: StreamPool::new(),
        }
    }

    /// Registers (or replaces) the pool factory for `scheme`.
    pub fn with_factory<F, S>(mut self, scheme: &'static str, factory: F) -> Self
    where
        F: FnMut(&Url) -> anyhow::Result<S> + 'static,
        S: Stream + 'static,
    {
        self.pool = self.pool.with_factory(scheme, factory);
        self
    }

    /// Bootstraps the pool with `http` / `https` factories backed by
    /// [`pimalaya_stream::std::stream::StreamStd`] using the given
    /// `tls` profile. ALPN is read from `tls.rustls.alpn`; callers
    /// typically pre-populate it with `["http/1.1"]`. Gated by the
    /// `stream` feature.
    #[cfg(feature = "stream")]
    pub fn with_tls(mut self, tls: pimalaya_stream::tls::Tls) -> Self {
        self.pool = self.pool.with_http_factories(tls);
        self
    }

    /// Fetches the ISP main URL
    /// (`http[s]://autoconfig.<domain>/mail/config-v1.1.xml?emailaddress=...`).
    pub fn isp(
        &mut self,
        local_part: &str,
        domain: &str,
        secure: bool,
    ) -> Result<Autoconfig, DiscoveryAutoconfigClientStdError> {
        let url = DiscoveryIsp::main_url(local_part, domain, secure)?;
        self.run(DiscoveryIsp::new(url))
    }

    /// Fetches the ISP fallback URL
    /// (`http[s]://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`).
    pub fn isp_fallback(
        &mut self,
        domain: &str,
        secure: bool,
    ) -> Result<Autoconfig, DiscoveryAutoconfigClientStdError> {
        let url = DiscoveryIsp::fallback_url(domain, secure)?;
        self.run(DiscoveryIsp::new(url))
    }

    /// Fetches the Thunderbird ISPDB
    /// (`http[s]://autoconfig.thunderbird.net/v1.1/<domain>`).
    pub fn ispdb(
        &mut self,
        domain: &str,
        secure: bool,
    ) -> Result<Autoconfig, DiscoveryAutoconfigClientStdError> {
        let url = DiscoveryIsp::db_url(domain, secure)?;
        self.run(DiscoveryIsp::new(url))
    }

    /// Returns the MX records for `domain`, sorted by ascending
    /// preference (best first). Empty when the response carries no
    /// MX answers.
    pub fn mx(&mut self, domain: &str) -> Result<Vec<MxRecord>, DiscoveryAutoconfigClientStdError> {
        self.run(DiscoveryDnsMx::new(domain, self.dns.clone()))
    }

    /// Looks up the `mailconf=<URL>` TXT record on `domain` and
    /// returns the parsed redirect URL.
    pub fn mailconf(&mut self, domain: &str) -> Result<Url, DiscoveryAutoconfigClientStdError> {
        self.run(DiscoveryMailconf::new(domain, self.dns.clone()))
    }

    /// Drives any standard-shape [`DiscoveryCoroutine`]
    /// (`Yield = DiscoveryYield`, `Return = Result<T, E>`) against the
    /// pool until it terminates. Each yielded I/O step is routed to
    /// the stream open on the matching URL.
    fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, DiscoveryAutoconfigClientStdError>
    where
        C: DiscoveryCoroutine<Yield = DiscoveryYield, Return = Result<T, E>>,
        DiscoveryAutoconfigClientStdError: From<E>,
    {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryCoroutineState::Complete(Ok(out)) => return Ok(out),
                DiscoveryCoroutineState::Complete(Err(err)) => return Err(err.into()),
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead { url }) => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite { url, bytes }) => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }
}
