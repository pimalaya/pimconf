//! # Standard, blocking PACC discovery client
//!
//! [`DiscoveryPaccClientStd`] drives the [`DiscoveryPacc`] coroutine
//! end-to-end through a local [`StreamPool`]. One method:
//! [`discover`], which runs the full PACC exchange (HTTPS fetch of
//! the well-known URL → DNS TXT digest verification → JSON parse) for
//! one domain.
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
//! [`new`]: DiscoveryPaccClientStd::new
//! [`with_factory`]: DiscoveryPaccClientStd::with_factory
//! [`with_tls`]: DiscoveryPaccClientStd::with_tls
//! [`discover`]: DiscoveryPaccClientStd::discover

use std::io;

use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    pacc::{
        discover::{DiscoveryPacc, DiscoveryPaccError},
        types::PaccConfig,
    },
    shared::pool::{Stream, StreamPool},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`DiscoveryPaccClientStd::discover`].
#[derive(Debug, Error)]
pub enum DiscoveryPaccClientStdError {
    /// The underlying PACC coroutine errored out.
    #[error(transparent)]
    Discovery(#[from] DiscoveryPaccError),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// [`StreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking PACC discovery client.
pub struct DiscoveryPaccClientStd {
    dns: Url,
    pool: StreamPool,
}

impl DiscoveryPaccClientStd {
    /// Builds a client that resolves the digest TXT record through
    /// `dns` (a `tcp://host:port` URL pointing at a DNS-over-TCP
    /// resolver). The underlying pool is pre-populated with the
    /// default `tcp` factory only; plug `http` / `https` factories
    /// via [`with_factory`] before calling [`discover`], or chain
    /// [`with_tls`] under the `stream` feature.
    ///
    /// [`with_factory`]: Self::with_factory
    /// [`with_tls`]: Self::with_tls
    /// [`discover`]: Self::discover
    pub fn new(dns: Url) -> Self {
        Self {
            dns,
            pool: StreamPool::new(),
        }
    }

    /// Registers (or replaces) the pool factory for `scheme`. Pass a
    /// lowercase literal (`"https"`, `"tcp"`, …).
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

    /// Runs the full PACC discovery for `domain`. Streams are opened
    /// on demand: HTTPS to the well-known PACC URL, plain TCP to the
    /// configured DNS resolver.
    pub fn discover(&mut self, domain: &str) -> Result<PaccConfig, DiscoveryPaccClientStdError> {
        let mut coroutine = DiscoveryPacc::new(domain, self.dns.clone())?;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryCoroutineState::Complete(Ok(config)) => return Ok(config),
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
