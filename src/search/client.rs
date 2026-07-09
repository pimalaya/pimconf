//! # Standard, blocking search client
//!
//! [`SearchClientStd`] orchestrates the discovery bricks in parallel:
//! one OS thread per mechanism, each pumping its coroutine through
//! its own [`StreamPool`], the outputs reduced in mechanism-priority
//! order by the pure [`ConfigCollector`]. A final probe pass then
//! asks each collected HTTP endpoint which authentication schemes it
//! advertises on its unauthenticated 401 (PACC §5.4.2) and refines
//! the config's password and bearer methods accordingly, one thread
//! per config.
//!
//! Mechanism failures are logged and skipped: only an invalid email
//! address fails the whole search. Mechanisms irrelevant to the
//! requested services are never started.

use std::thread;

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

use log::{debug, trace};
use pimalaya_stream::tls::Tls;
use thiserror::Error;
use url::Url;

use crate::{
    autoconfig::{isp::DiscoveryIsp, mailconf::DiscoveryMailconf, mx::DiscoveryDnsMx},
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    pacc::discover::DiscoveryPacc,
    rfc6186::discover::DiscoverySrv,
    rfc6764::{resolve::ResolveDav, types::DavService},
    rfc8620::resolve::ResolveJmap,
    rfc9110::ProbeAuth,
    search::{
        collect::ConfigCollector,
        providers::Provider,
        types::{ConfigSource, Service, ServiceConfig},
    },
    shared::pool::StreamPool,
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`SearchClientStd`].
#[derive(Debug, Error)]
pub enum SearchClientStdError {
    /// The input is not a valid `local@domain` email address.
    #[error("Search email `{0}` is missing the `@` separator")]
    InvalidEmail(String),
}

/// Std-blocking parallel search orchestrator.
pub struct SearchClientStd {
    dns: Url,
    tls: Tls,
}

impl SearchClientStd {
    /// Builds a client that resolves DNS lookups through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver) and
    /// runs the HTTPS-bound mechanisms over `tls`.
    pub fn new(dns: Url, tls: Tls) -> Self {
        Self { dns, tls }
    }

    /// Runs every mechanism in parallel and returns all configs found
    /// for `email`, restricted to `services` (empty means all
    /// services).
    pub fn search_all(
        &self,
        email: &str,
        services: BTreeSet<Service>,
    ) -> Result<Vec<ServiceConfig>, SearchClientStdError> {
        self.search(email, services, false)
    }

    /// Same mechanism set as [`search_all`](Self::search_all), but
    /// keeps only the configs of the highest-priority mechanism that
    /// produced any; an empty result means no mechanism produced
    /// anything. The mechanisms still run in parallel, so this trades
    /// no latency, only output size.
    pub fn search_first(
        &self,
        email: &str,
        services: BTreeSet<Service>,
    ) -> Result<Vec<ServiceConfig>, SearchClientStdError> {
        self.search(email, services, true)
    }

    fn search(
        &self,
        email: &str,
        services: BTreeSet<Service>,
        first: bool,
    ) -> Result<Vec<ServiceConfig>, SearchClientStdError> {
        let email = email.trim();

        let Some((local, domain)) = email.split_once('@') else {
            return Err(SearchClientStdError::InvalidEmail(email.to_string()));
        };
        let domain = domain.trim_matches('.').to_ascii_lowercase();

        debug!("begin config search");
        trace!("email {email}, first: {first}, services: {services:?}");

        let mut collector = ConfigCollector::new(services);

        let wants_mail = [Service::Imap, Service::Pop3, Service::Smtp]
            .iter()
            .any(|s| collector.wants(*s));

        // Mechanism outputs, in priority order. The fixed provider
        // domain rule is pure and comes first; when it matches, the
        // MX-based provider detection is pointless and skipped.
        let mut outputs: Vec<Vec<ServiceConfig>> = Vec::new();

        let provider = Provider::from_domain(&domain);
        if let Some(provider) = provider {
            debug!("email domain matched a fixed provider rule");
            trace!("{domain} -> {provider:?}");
            outputs.push(provider.configs(email));
        }

        outputs.extend(thread::scope(|scope| {
            let domain = &domain;
            let mut handles = Vec::new();

            if provider.is_none() {
                handles.push(scope.spawn(|| self.run_mx(domain, email)));
            }

            handles.push(scope.spawn(|| self.run_pacc(domain)));

            if wants_mail {
                handles.push(scope.spawn(|| self.run_isp_main(local, domain, email)));
                handles.push(scope.spawn(|| self.run_isp_fallback(domain, email)));
                handles.push(scope.spawn(|| self.run_mailconf(domain, email)));
                handles.push(scope.spawn(|| self.run_ispdb(domain, email)));
            }

            if collector.wants(Service::Imap) || collector.wants(Service::Smtp) {
                handles.push(scope.spawn(|| self.run_srv(domain)));
            }

            if collector.wants(Service::Caldav) {
                handles.push(scope.spawn(|| self.run_dav(domain, DavService::Caldav)));
            }

            if collector.wants(Service::Carddav) {
                handles.push(scope.spawn(|| self.run_dav(domain, DavService::Carddav)));
            }

            if collector.wants(Service::Jmap) {
                handles.push(scope.spawn(|| self.run_jmap(domain)));
            }

            handles
                .into_iter()
                .map(|handle| handle.join().unwrap_or_default())
                .collect::<Vec<_>>()
        }));

        for configs in outputs {
            collector.collect(configs);

            if first && !collector.is_empty() {
                debug!("keep first mechanism yielding configs");
                break;
            }
        }

        let mut configs = collector.finish();
        self.probe(&mut configs);

        debug!("end of config search");
        trace!("{configs:?}");
        Ok(configs)
    }

    /// A fresh stream pool for one mechanism thread: the default
    /// `tcp` factory for DNS lookups, plus `http`/`https` factories
    /// backed by the client's TLS.
    fn pool(&self) -> StreamPool {
        StreamPool::new().with_http_factories(self.tls.clone())
    }

    /// Probes each config's endpoints for their advertised
    /// authentication schemes, in parallel, and refines the configs
    /// in place. Within one config, the URLs are tried in order until
    /// one advertises any scheme.
    fn probe(&self, configs: &mut [ServiceConfig]) {
        let schemes: Vec<Option<Vec<String>>> = thread::scope(|scope| {
            let handles: Vec<_> = configs
                .iter()
                .map(|config| {
                    let urls = config.probe_urls();
                    scope.spawn(move || {
                        for url in urls {
                            debug!("probe endpoint authentication schemes");
                            trace!("{url}");

                            match run(&mut self.pool(), ProbeAuth::new(url)) {
                                Ok(schemes) if !schemes.is_empty() => return Some(schemes),
                                // Nothing learned at this URL: the
                                // config's next URL gets its turn.
                                Ok(_) => {}
                                Err(err) => {
                                    debug!("skip failed auth probe");
                                    trace!("{err:?}");
                                }
                            }
                        }
                        None
                    })
                })
                .collect();

            handles
                .into_iter()
                .map(|handle| handle.join().unwrap_or(None))
                .collect()
        });

        for (config, schemes) in configs.iter_mut().zip(schemes) {
            if let Some(schemes) = schemes {
                config.refine_auth(&schemes);
            }
        }
    }

    /// Detects a provider hosting the domain through its MX records
    /// (Google Workspace, Microsoft 365) and returns its fixed
    /// configs.
    fn run_mx(&self, domain: &str, email: &str) -> Vec<ServiceConfig> {
        let mx = DiscoveryDnsMx::new(domain, self.dns.clone());

        match run(&mut self.pool(), mx) {
            Ok(records) => {
                for record in records {
                    let exchange = record.data().exchange().to_string();

                    if let Some(provider) = Provider::from_mx(&exchange) {
                        debug!("MX record matched a fixed provider rule");
                        trace!("{exchange} -> {provider:?}");
                        return provider.configs(email);
                    }
                }
                Vec::new()
            }
            Err(err) => {
                debug!("skip MX provider detection");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_pacc(&self, domain: &str) -> Vec<ServiceConfig> {
        let pacc = match DiscoveryPacc::new(domain, self.dns.clone()) {
            Ok(pacc) => pacc,
            Err(err) => {
                debug!("skip PACC discovery");
                trace!("{err:?}");
                return Vec::new();
            }
        };

        match run(&mut self.pool(), pacc) {
            Ok(config) => ServiceConfig::from_pacc(&config),
            Err(err) => {
                debug!("skip PACC discovery");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_isp_main(&self, local: &str, domain: &str, email: &str) -> Vec<ServiceConfig> {
        match DiscoveryIsp::main_url(local, domain, true) {
            Ok(url) => self.run_isp(url, email, ConfigSource::IspMain),
            Err(err) => {
                debug!("skip autoconfig ISP main URL");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_isp_fallback(&self, domain: &str, email: &str) -> Vec<ServiceConfig> {
        match DiscoveryIsp::fallback_url(domain, true) {
            Ok(url) => self.run_isp(url, email, ConfigSource::IspFallback),
            Err(err) => {
                debug!("skip autoconfig ISP fallback URL");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_ispdb(&self, domain: &str, email: &str) -> Vec<ServiceConfig> {
        match DiscoveryIsp::db_url(domain, true) {
            Ok(url) => self.run_isp(url, email, ConfigSource::Ispdb),
            Err(err) => {
                debug!("skip autoconfig ISPDB URL");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    /// Follows the mailconf TXT redirect to its autoconfig document.
    fn run_mailconf(&self, domain: &str, email: &str) -> Vec<ServiceConfig> {
        let mailconf = DiscoveryMailconf::new(domain, self.dns.clone());

        match run(&mut self.pool(), mailconf) {
            Ok(url) => {
                debug!("follow mailconf TXT redirect");
                trace!("{url}");
                self.run_isp(url, email, ConfigSource::Mailconf)
            }
            Err(err) => {
                debug!("skip mailconf TXT redirect");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_isp(&self, url: Url, email: &str, source: ConfigSource) -> Vec<ServiceConfig> {
        match run(&mut self.pool(), DiscoveryIsp::new(url)) {
            Ok(config) => ServiceConfig::from_autoconfig(&config, email, source),
            Err(err) => {
                debug!("skip autoconfig document");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_srv(&self, domain: &str) -> Vec<ServiceConfig> {
        let srv = DiscoverySrv::new(domain, self.dns.clone());

        match run(&mut self.pool(), srv) {
            Ok(report) => ServiceConfig::from_srv(&report),
            Err(err) => {
                debug!("skip RFC 6186 SRV discovery");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_dav(&self, domain: &str, service: DavService) -> Vec<ServiceConfig> {
        let resolve = ResolveDav::new(domain, service, self.dns.clone());

        let config_service = match service {
            DavService::Caldav => Service::Caldav,
            DavService::Carddav => Service::Carddav,
        };

        match run(&mut self.pool(), resolve) {
            Ok(url) => vec![ServiceConfig::from_dav(config_service, url)],
            Err(err) => {
                debug!("skip RFC 6764 DAV resolve");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }

    fn run_jmap(&self, domain: &str) -> Vec<ServiceConfig> {
        let resolve = ResolveJmap::new(domain, self.dns.clone());

        match run(&mut self.pool(), resolve) {
            Ok(session) => vec![ServiceConfig::from_jmap(session.url, &session.auth_schemes)],
            Err(err) => {
                debug!("skip RFC 8620 JMAP resolve");
                trace!("{err:?}");
                Vec::new()
            }
        }
    }
}

/// Pumps one discovery coroutine through the pool until completion.
///
/// I/O failures are not fatal: a stream that cannot be opened, read
/// or written is signalled to the coroutine as EOF (an empty resume
/// slice), so the mechanism errors out on its own and the caller
/// skips it.
fn run<C, T, E>(pool: &mut StreamPool, mut coroutine: C) -> Result<T, E>
where
    C: DiscoveryCoroutine<Yield = DiscoveryYield, Return = Result<T, E>>,
{
    let mut buf = [0u8; READ_BUFFER_SIZE];
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            DiscoveryCoroutineState::Complete(res) => return res,
            DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead { url }) => {
                match pool.get(&url).and_then(|s| Ok(s.read(&mut buf)?)) {
                    Ok(n) => arg = Some(&buf[..n]),
                    Err(err) => {
                        debug!("search read failed, signal EOF");
                        trace!("{url}: {err:?}");
                        arg = Some(&[]);
                    }
                }
            }
            DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite { url, bytes }) => {
                match pool.get(&url).and_then(|s| Ok(s.write_all(&bytes)?)) {
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
