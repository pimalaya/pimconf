//! # Standard, blocking RFC 6186 SRV discovery client
//!
//! [`DiscoverySrvClientStd`] drives the [`DiscoverySrv`] combined
//! coroutine (three SRV queries → best-record-per-service assembly)
//! end-to-end through a local [`DiscoveryStreamPool`]. One method:
//! [`discover`].
//!
//! Only the default `tcp` factory is needed: SRV discovery never
//! opens an HTTPS connection. Custom DNS transports plug in via
//! [`with_factory`].
//!
//! [`new`]: DiscoverySrvClientStd::new
//! [`with_factory`]: DiscoverySrvClientStd::with_factory
//! [`discover`]: DiscoverySrvClientStd::discover

use std::io;

use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6186::{
        discover::{DiscoverySrv, DiscoverySrvError},
        types::SrvReport,
    },
    shared::pool::{DiscoveryStreamPool, Stream},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`DiscoverySrvClientStd::discover`].
#[derive(Debug, Error)]
pub enum DiscoverySrvClientStdError {
    /// The combined SRV coroutine errored out on one of its three
    /// lookups.
    #[error(transparent)]
    Discovery(#[from] DiscoverySrvError),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// [`DiscoveryStreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking RFC 6186 SRV discovery client.
pub struct DiscoverySrvClientStd {
    dns: Url,
    pool: DiscoveryStreamPool,
}

impl DiscoverySrvClientStd {
    /// Builds a client that resolves SRV records through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver).
    /// The underlying pool is pre-populated with the default `tcp`
    /// factory; SRV discovery never opens HTTPS, so [`with_tls`] (and
    /// `http`/`https` factories) are unnecessary.
    ///
    /// [`with_tls`]: crate::pacc::client::DiscoveryPaccClientStd::with_tls
    pub fn new(dns: Url) -> Self {
        Self {
            dns,
            pool: DiscoveryStreamPool::new(),
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

    /// Runs the three RFC 6186 SRV lookups (`_imap._tcp`,
    /// `_imaps._tcp`, `_submission._tcp`) on `domain` and returns
    /// the best record per service.
    pub fn discover(&mut self, domain: &str) -> Result<SrvReport, DiscoverySrvClientStdError> {
        let mut coroutine = DiscoverySrv::new(domain, self.dns.clone());
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryCoroutineState::Complete(Ok(report)) => return Ok(report),
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
