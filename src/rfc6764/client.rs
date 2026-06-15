//! # Standard, blocking RFC 6764 CalDAV/CardDAV discovery client
//!
//! [`DiscoveryWebdavClientStd`] pumps the RFC 6764 discovery coroutines
//! end-to-end through a local [`StreamPool`], exposing one entry point
//! per mechanism: [`discover`] (SRV records, §3), [`txt`] (the TXT
//! `path` lookup, §4) and [`well_known`] (a single `.well-known` probe,
//! §5), plus [`resolve`] (SRV then TXT then `.well-known`, into a
//! context root).
//!
//! [`discover`] and [`txt`] need only the default `tcp` factory, since
//! the DNS lookups run over DNS-over-TCP. The `.well-known` steps in
//! [`well_known`] and [`resolve`] open HTTPS, so those callers must
//! register the HTTP factories via [`with_tls`]. Custom DNS transports
//! plug in via [`with_factory`].
//!
//! [`with_factory`]: DiscoveryWebdavClientStd::with_factory
//! [`with_tls`]: DiscoveryWebdavClientStd::with_tls
//! [`discover`]: DiscoveryWebdavClientStd::discover
//! [`txt`]: DiscoveryWebdavClientStd::txt
//! [`resolve`]: DiscoveryWebdavClientStd::resolve
//! [`well_known`]: DiscoveryWebdavClientStd::well_known

use std::io;

use alloc::string::String;

use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6764::{
        discover::{DiscoveryWebdavSrv, DiscoveryWebdavSrvError},
        resolve::{ResolveDav, ResolveDavError},
        txt::{DiscoveryWebdavTxt, DiscoveryWebdavTxtError},
        types::{DavService, WebdavSrvReport},
        well_known::{WellKnown, WellKnownError},
    },
    shared::pool::{Stream, StreamPool},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`DiscoveryWebdavClientStd::discover`].
#[derive(Debug, Error)]
pub enum DiscoveryWebdavClientStdError {
    /// The combined SRV coroutine errored out on one of its four
    /// lookups.
    #[error(transparent)]
    Discovery(#[from] DiscoveryWebdavSrvError),
    /// The combined `domain -> context root` resolve coroutine failed.
    #[error(transparent)]
    Resolve(#[from] ResolveDavError),
    /// The standalone TXT `path` lookup failed.
    #[error(transparent)]
    Txt(#[from] DiscoveryWebdavTxtError),
    /// The standalone `.well-known` probe failed.
    #[error(transparent)]
    WellKnown(#[from] WellKnownError),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// [`StreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking RFC 6764 CalDAV/CardDAV discovery client.
pub struct DiscoveryWebdavClientStd {
    dns: Url,
    pool: StreamPool,
}

impl DiscoveryWebdavClientStd {
    /// Builds a client that resolves SRV records through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver).
    /// The underlying pool is pre-populated with the default `tcp`
    /// factory, which is all [`discover`](Self::discover) needs; add
    /// the HTTP factories via [`with_tls`](Self::with_tls) before
    /// running the `.well-known` steps.
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
    ) -> Result<WebdavSrvReport, DiscoveryWebdavClientStdError> {
        let coroutine = DiscoveryWebdavSrv::new(domain, self.dns.clone());
        self.run(coroutine)
    }

    /// Queries the RFC 6764 §4 TXT `path` record for `service` on
    /// `domain` (the secure `_caldavs`/`_carddavs` name) and returns
    /// the advertised context path, or `None` when no `path` record is
    /// published. Runs over DNS-over-TCP, so it needs no HTTP factory.
    pub fn txt(
        &mut self,
        domain: &str,
        service: DavService,
    ) -> Result<Option<String>, DiscoveryWebdavClientStdError> {
        let qname = service.srv_qname(true, domain);
        let coroutine = DiscoveryWebdavTxt::new(qname, self.dns.clone());
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
    ) -> Result<Url, DiscoveryWebdavClientStdError> {
        let coroutine = ResolveDav::new(domain, service, self.dns.clone());
        self.run(coroutine)
    }

    /// Probes `.well-known/{service}` on `origin` (a scheme + host +
    /// port root) as a standalone mechanism: returns `Some(location)`
    /// when the origin redirects to a context root, `None` when it does
    /// not. Lets callers order it freely against SRV/PACC. Requires
    /// [`with_tls`](Self::with_tls).
    #[cfg(feature = "stream")]
    pub fn well_known(
        &mut self,
        origin: Url,
        service: DavService,
    ) -> Result<Option<Url>, DiscoveryWebdavClientStdError> {
        let coroutine = WellKnown::new(origin, service);
        self.run(coroutine)
    }

    /// Pumps any pimconf coroutine (`Yield = DiscoveryYield`) through
    /// the stream pool until completion.
    fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, DiscoveryWebdavClientStdError>
    where
        C: DiscoveryCoroutine<Yield = DiscoveryYield, Return = Result<T, E>>,
        E: Into<DiscoveryWebdavClientStdError>,
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
