//! # Standard, blocking RFC 6764 SRV discovery client
//!
//! [`DiscoveryRfc6764ClientStd`] drives the [`DiscoveryRfc6764`]
//! combined coroutine (four SRV queries: best-record-per-service
//! assembly) end-to-end through a local [`StreamPool`]. One method:
//! [`discover`].
//!
//! Only the default `tcp` factory is needed: SRV discovery never
//! opens an HTTPS connection. Custom DNS transports plug in via
//! [`with_factory`].
//!
//! [`with_factory`]: DiscoveryRfc6764ClientStd::with_factory
//! [`discover`]: DiscoveryRfc6764ClientStd::discover

use std::io;

use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6764::{
        discover::{DiscoveryRfc6764, DiscoveryRfc6764Error},
        resolve::{ResolveDav, ResolveDavError},
        types::{DavService, Rfc6764Report},
    },
    shared::pool::{Stream, StreamPool},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`DiscoveryRfc6764ClientStd::discover`].
#[derive(Debug, Error)]
pub enum DiscoveryRfc6764ClientStdError {
    /// The combined SRV coroutine errored out on one of its four
    /// lookups.
    #[error(transparent)]
    Discovery(#[from] DiscoveryRfc6764Error),
    /// The combined `domain -> context root` resolve coroutine failed.
    #[error(transparent)]
    Resolve(#[from] ResolveDavError),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// [`StreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking RFC 6764 SRV discovery client.
pub struct DiscoveryRfc6764ClientStd {
    dns: Url,
    pool: StreamPool,
}

impl DiscoveryRfc6764ClientStd {
    /// Builds a client that resolves SRV records through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver).
    /// The underlying pool is pre-populated with the default `tcp`
    /// factory; SRV discovery never opens HTTPS, so HTTPS factories
    /// are unnecessary.
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

    /// Registers `http`/`https` pool factories backed by `tls`, so the
    /// client can also run the `.well-known` probe in
    /// [`resolve`](Self::resolve). SRV-only callers do not need this.
    #[cfg(feature = "stream")]
    pub fn with_tls(mut self, tls: pimalaya_stream::tls::Tls) -> Self {
        self.pool = self.pool.with_http_factories(tls);
        self
    }

    /// Runs the four RFC 6764 SRV lookups (`_caldav._tcp`,
    /// `_caldavs._tcp`, `_carddav._tcp`, `_carddavs._tcp`) on
    /// `domain` and returns the best record per service.
    pub fn discover(
        &mut self,
        domain: &str,
    ) -> Result<Rfc6764Report, DiscoveryRfc6764ClientStdError> {
        let coroutine = DiscoveryRfc6764::new(domain, self.dns.clone());
        self.run(coroutine)
    }

    /// Resolves `domain` to a CalDAV/CardDAV context root: runs the SRV
    /// lookups, then follows the `.well-known` redirect on the best
    /// origin. Falls back to `https://<domain>:443/` when no SRV record
    /// is published. Requires [`with_tls`](Self::with_tls) so the pool
    /// can open the HTTPS `.well-known` connection.
    #[cfg(feature = "stream")]
    pub fn resolve(
        &mut self,
        domain: &str,
        service: DavService,
    ) -> Result<Url, DiscoveryRfc6764ClientStdError> {
        let coroutine = ResolveDav::new(domain, service, self.dns.clone());
        self.run(coroutine)
    }

    /// Pumps any pimconf coroutine (`Yield = DiscoveryYield`) through
    /// the stream pool until completion.
    fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, DiscoveryRfc6764ClientStdError>
    where
        C: DiscoveryCoroutine<Yield = DiscoveryYield, Return = Result<T, E>>,
        E: Into<DiscoveryRfc6764ClientStdError>,
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
