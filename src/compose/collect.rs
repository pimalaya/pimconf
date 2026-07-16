//! # Config collector
//!
//! [`DiscoveryConfigCollector`] is the pure half of a config compose: consumers
//! run the discovery bricks however they want (sequentially, or in
//! parallel on their own transports) and feed each mechanism's
//! configs in mechanism-priority order; the collector filters them
//! against the requested services and merges duplicates. No I/O
//! happens here, which is what lets orchestration live on the
//! consumer's side.

use alloc::{collections::BTreeSet, vec::Vec};

use crate::compose::config::{DiscoveryService, DiscoveryServiceConfig};

/// Pure accumulator reducing per-mechanism config lists into one
/// deduplicated list.
pub struct DiscoveryConfigCollector {
    services: BTreeSet<DiscoveryService>,
    configs: Vec<DiscoveryServiceConfig>,
}

impl DiscoveryConfigCollector {
    /// Builds a collector restricted to `services` (empty means all
    /// services).
    pub fn new(services: BTreeSet<DiscoveryService>) -> Self {
        Self {
            services,
            configs: Vec::new(),
        }
    }

    /// Whether configs of this service are collected. Orchestrators
    /// use it to skip mechanisms that can only produce filtered-out
    /// services.
    pub fn wants(&self, service: DiscoveryService) -> bool {
        self.services.is_empty() || self.services.contains(&service)
    }

    /// Keeps the configs matching the requested services. A config
    /// whose service, endpoint and username were already collected by
    /// an earlier mechanism merges its authentication methods into the
    /// existing config instead of duplicating it. HTTP endpoints
    /// compare as normalized URLs, and a subdomain of an already
    /// collected host counts as the same service reached through a
    /// rotated backend name: the parent host wins the endpoint, since
    /// only it is worth persisting in an account.
    pub fn collect(&mut self, configs: Vec<DiscoveryServiceConfig>) {
        for config in configs {
            if !self.wants(config.service) {
                continue;
            }

            let existing = self.configs.iter_mut().find(|c| {
                c.service == config.service
                    && c.username == config.username
                    && (c.endpoint.equivalent(&config.endpoint)
                        || c.endpoint.subdomain_of(&config.endpoint)
                        || config.endpoint.subdomain_of(&c.endpoint))
            });

            match existing {
                Some(existing) => {
                    if existing.endpoint.subdomain_of(&config.endpoint) {
                        existing.endpoint = config.endpoint;
                        existing.source = config.source;
                    }
                    for method in config.auth {
                        if !existing.auth.contains(&method) {
                            existing.auth.push(method);
                        }
                    }
                }
                None => self.configs.push(config),
            }
        }
    }

    /// Whether nothing has been collected yet.
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    /// Returns the collected configs, consuming the collector.
    pub fn finish(self) -> Vec<DiscoveryServiceConfig> {
        self.configs
    }
}
