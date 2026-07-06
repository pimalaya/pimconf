//! # Search-first coroutine
//!
//! [`SearchFirst`] runs the same mechanism chain as
//! [`SearchAll`](crate::search::all::SearchAll) but completes as soon
//! as one mechanism yields at least one config matching the requested
//! services. An empty result means no mechanism produced anything.

use alloc::{collections::BTreeSet, vec::Vec};

use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    search::{
        all::{SearchAll, SearchError},
        types::{Service, ServiceConfig},
    },
};

/// I/O-free coroutine that stops at the first mechanism producing at
/// least one config.
pub struct SearchFirst(SearchAll);

impl SearchFirst {
    /// Builds a search for `email`, restricted to `services` (empty
    /// means all services). `resolver` must be a `tcp://host:port`
    /// DNS-over-TCP resolver URL.
    pub fn new(
        email: impl AsRef<str>,
        services: BTreeSet<Service>,
        resolver: Url,
    ) -> Result<Self, SearchError> {
        Ok(Self(SearchAll::build(email, services, resolver, true)?))
    }
}

impl DiscoveryCoroutine for SearchFirst {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<ServiceConfig>, SearchError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        self.0.resume(arg)
    }
}
