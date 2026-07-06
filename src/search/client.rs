//! # Standard, blocking search client
//!
//! [`SearchClientStd`] pumps the search coroutines end-to-end through
//! a local [`StreamPool`]: [`search_all`] collects every config the
//! known mechanisms produce, [`search_first`] stops at the first
//! mechanism yielding any. Both chain DNS lookups and HTTPS fetches,
//! so callers must register the HTTP factories via [`with_tls`] (or
//! [`with_factory`]).
//!
//! [`search_all`]: SearchClientStd::search_all
//! [`search_first`]: SearchClientStd::search_first
//! [`with_tls`]: SearchClientStd::with_tls
//! [`with_factory`]: SearchClientStd::with_factory

use std::io;

use alloc::{collections::BTreeSet, vec::Vec};

use log::{debug, trace};
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    search::{
        all::{SearchAll, SearchError},
        first::SearchFirst,
        types::{Service, ServiceConfig},
    },
    shared::pool::{Stream, StreamPool},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`SearchClientStd`].
#[derive(Debug, Error)]
pub enum SearchClientStdError {
    /// The search coroutine rejected its input.
    #[error(transparent)]
    Search(#[from] SearchError),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// [`StreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking unified search client.
pub struct SearchClientStd {
    dns: Url,
    pool: StreamPool,
}

impl SearchClientStd {
    /// Builds a client that resolves DNS lookups through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver).
    /// The underlying pool is pre-populated with the default `tcp`
    /// factory only; register the HTTP factories via
    /// [`with_tls`](Self::with_tls) before searching.
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

    /// Registers `http`/`https` pool factories backed by `tls`, so
    /// the client can run the HTTPS-bound mechanisms (PACC,
    /// autoconfig, `.well-known`).
    #[cfg(feature = "stream")]
    pub fn with_tls(mut self, tls: pimalaya_stream::tls::Tls) -> Self {
        self.pool = self.pool.with_http_factories(tls);
        self
    }

    /// Runs every mechanism and returns all configs found for
    /// `email`, restricted to `services` (empty means all services).
    pub fn search_all(
        &mut self,
        email: &str,
        services: BTreeSet<Service>,
    ) -> Result<Vec<ServiceConfig>, SearchClientStdError> {
        let coroutine = SearchAll::new(email, services, self.dns.clone())?;
        self.run(coroutine)
    }

    /// Runs mechanisms in order and returns the configs of the first
    /// one yielding any, or an empty list when none does.
    pub fn search_first(
        &mut self,
        email: &str,
        services: BTreeSet<Service>,
    ) -> Result<Vec<ServiceConfig>, SearchClientStdError> {
        let coroutine = SearchFirst::new(email, services, self.dns.clone())?;
        self.run(coroutine)
    }

    /// Pumps the search coroutine through the stream pool until
    /// completion.
    ///
    /// Unlike the per-mechanism clients, I/O failures are not fatal
    /// here: a stream that cannot be opened, read or written is
    /// signalled to the coroutine as EOF (an empty resume slice), so
    /// the failing mechanism errors out and the search moves on to
    /// the next one.
    fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, SearchClientStdError>
    where
        C: DiscoveryCoroutine<Yield = DiscoveryYield, Return = Result<T, E>>,
        E: Into<SearchClientStdError>,
    {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryCoroutineState::Complete(Ok(out)) => return Ok(out),
                DiscoveryCoroutineState::Complete(Err(err)) => return Err(err.into()),
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead { url }) => {
                    match self.pool.get(&url).and_then(|s| Ok(s.read(&mut buf)?)) {
                        Ok(n) => arg = Some(&buf[..n]),
                        Err(err) => {
                            debug!("search read failed, signal EOF");
                            trace!("{url}: {err:?}");
                            arg = Some(&[]);
                        }
                    }
                }
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite { url, bytes }) => {
                    match self.pool.get(&url).and_then(|s| Ok(s.write_all(&bytes)?)) {
                        Ok(()) => {}
                        Err(err) => {
                            debug!("search write failed, signal EOF");
                            trace!("{url}: {err:?}");
                            arg = Some(&[]);
                        }
                    }
                }
            }
        }
    }
}
