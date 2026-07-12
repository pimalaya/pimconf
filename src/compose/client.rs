//! # Standard, blocking compose client
//!
//! [`ComposeClientStd`] orchestrates the discovery bricks in parallel:
//! one OS thread per mechanism, each pumping its coroutine through
//! its own [`StreamPool`], the outputs reduced in mechanism-priority
//! order by the pure [`ConfigCollector`]. A final probe pass then
//! asks each collected HTTP endpoint which authentication schemes it
//! advertises on its unauthenticated 401 (PACC §5.4.2) and refines
//! the config's password and bearer methods accordingly, one thread
//! per config.
//!
//! Mechanism failures are logged and skipped: only an invalid email
//! address fails the whole compose. Mechanisms irrelevant to the
//! requested services are never started.

use std::thread;

#[cfg(feature = "rfc8414")]
use alloc::collections::BTreeMap;
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

use log::{debug, trace};
use pimalaya_stream::tls::Tls;
use thiserror::Error;
use url::Url;

#[cfg(feature = "autoconfig")]
use crate::autoconfig::{isp::DiscoveryIsp, mailconf::DiscoveryMailconf, mx::DiscoveryDnsMx};
#[cfg(feature = "rfc8414")]
use crate::compose::types::AuthMethod;
#[cfg(feature = "autoconfig")]
use crate::compose::types::ConfigSource;
#[cfg(feature = "pacc")]
use crate::pacc::discover::DiscoveryPacc;
#[cfg(feature = "rfc6186")]
use crate::rfc6186::discover::DiscoverySrv;
#[cfg(feature = "rfc6764")]
use crate::rfc6764::{resolve::ResolveDav, types::DavService};
#[cfg(feature = "rfc8414")]
use crate::rfc8414::{OauthServerMetadata, ResolveOauthServer};
#[cfg(feature = "rfc8620")]
use crate::rfc8620::resolve::ResolveJmap;
#[cfg(feature = "rfc8620")]
use crate::rfc9110::ProbeAuth;
#[cfg(feature = "rfc9728")]
use crate::rfc9728::{OauthResourceMetadata, ResolveOauthResource};
use crate::{
    compose::{
        collect::ConfigCollector,
        providers::Provider,
        types::{Service, ServiceConfig},
    },
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::pool::StreamPool,
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`ComposeClientStd`].
#[derive(Debug, Error)]
pub enum ComposeClientStdError {
    /// The input is not a valid `local@domain` email address.
    #[error("Email address `{0}` is missing the `@` separator")]
    InvalidEmail(String),
}

/// Std-blocking parallel compose orchestrator.
pub struct ComposeClientStd {
    dns: Url,
    tls: Tls,
}

impl ComposeClientStd {
    /// Builds a client that resolves DNS lookups through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver) and
    /// runs the HTTPS-bound mechanisms over `tls`.
    pub fn new(dns: Url, tls: Tls) -> Self {
        Self { dns, tls }
    }

    /// Runs every mechanism in parallel and returns all configs found
    /// for `email`, restricted to `services` (empty means all
    /// services).
    pub fn compose_all(
        &self,
        email: &str,
        services: BTreeSet<Service>,
    ) -> Result<Vec<ServiceConfig>, ComposeClientStdError> {
        self.compose(email, services, false)
    }

    /// Same mechanism set as [`compose_all`](Self::compose_all), but
    /// keeps only the configs of the highest-priority mechanism that
    /// produced any; an empty result means no mechanism produced
    /// anything. The mechanisms still run in parallel, so this trades
    /// no latency, only output size.
    pub fn compose_first(
        &self,
        email: &str,
        services: BTreeSet<Service>,
    ) -> Result<Vec<ServiceConfig>, ComposeClientStdError> {
        self.compose(email, services, true)
    }

    /// Runs every mechanism in parallel and returns their raw,
    /// unmerged configs for `email`, restricted to `services` (empty
    /// means all). Unlike [`compose_all`](Self::compose_all), the
    /// per-mechanism outputs are not reduced against each other: each
    /// config keeps its own source and cross-mechanism duplicates are
    /// preserved.
    pub fn compose_raw(
        &self,
        email: &str,
        services: BTreeSet<Service>,
    ) -> Result<Vec<ServiceConfig>, ComposeClientStdError> {
        let outputs = self.parallel_outputs(email, &services)?;

        let mut configs: Vec<ServiceConfig> = outputs
            .into_iter()
            .flatten()
            .filter(|config| services.is_empty() || services.contains(&config.service))
            .collect();

        self.resolve_issuers(&mut configs);

        Ok(configs)
    }

    /// Discovers the fixed-provider configs for `email`: the domain
    /// rule first, then MX-based detection. Raw and unmerged.
    pub fn provider(&self, email: &str) -> Vec<ServiceConfig> {
        self.detect_provider(email)
            .map(|provider| provider.configs(email))
            .unwrap_or_default()
    }

    /// The fixed Google configs for `email` when it is Google-hosted
    /// (domain rule or MX records), otherwise empty.
    pub fn is_google(&self, email: &str) -> Vec<ServiceConfig> {
        match self.detect_provider(email) {
            Some(Provider::Google) => Provider::Google.configs(email),
            _ => Vec::new(),
        }
    }

    /// The fixed Microsoft configs for `email` when it is
    /// Microsoft-hosted (domain rule or MX records), otherwise empty.
    pub fn is_microsoft(&self, email: &str) -> Vec<ServiceConfig> {
        match self.detect_provider(email) {
            Some(Provider::Microsoft) => Provider::Microsoft.configs(email),
            _ => Vec::new(),
        }
    }

    /// Runs every Mozilla autoconfig location (ISP main, ISP fallback,
    /// ISPDB, mailconf) for `email`. Raw and unmerged.
    #[cfg(feature = "autoconfig")]
    pub fn autoconfig(&self, email: &str) -> Vec<ServiceConfig> {
        let local = email.split_once('@').map(|(local, _)| local).unwrap_or("");
        let domain = domain_part(email);

        let mut configs = Vec::new();
        configs.extend(self.run_isp_main(local, &domain, email));
        configs.extend(self.run_isp_fallback(&domain, email));
        configs.extend(self.run_ispdb(&domain, email));
        configs.extend(self.run_mailconf(&domain, email));
        configs
    }

    /// Runs RFC 6186 SRV mail discovery for `input` (an email address
    /// or a bare domain). Raw.
    #[cfg(feature = "rfc6186")]
    pub fn srv(&self, input: &str) -> Vec<ServiceConfig> {
        self.run_srv(&domain_part(input))
    }

    /// Runs PACC discovery for `input` (an email address or a bare
    /// domain). Raw.
    #[cfg(feature = "pacc")]
    pub fn pacc(&self, input: &str) -> Vec<ServiceConfig> {
        self.run_pacc(&domain_part(input))
    }

    /// Runs RFC 6764 CalDAV or CardDAV resolution for `input` (an
    /// email address or a bare domain). Raw.
    #[cfg(feature = "rfc6764")]
    pub fn dav(&self, input: &str, service: DavService) -> Vec<ServiceConfig> {
        self.run_dav(&domain_part(input), service)
    }

    /// Runs RFC 8620 JMAP session resolution for `input` (an email
    /// address or a bare domain). Raw.
    #[cfg(feature = "rfc8620")]
    pub fn jmap(&self, input: &str) -> Vec<ServiceConfig> {
        self.run_jmap(&domain_part(input))
    }

    /// Probes `url` for the authentication schemes it advertises on an
    /// unauthenticated 401 response. `None` when the probe failed or
    /// nothing was advertised.
    #[cfg(feature = "rfc8620")]
    pub fn auth(&self, url: Url) -> Option<Vec<String>> {
        match run(&mut self.pool(), ProbeAuth::new(url)) {
            Ok(schemes) if !schemes.is_empty() => Some(schemes),
            _ => None,
        }
    }

    /// Fetches `issuer`'s RFC 8414 authorization server metadata,
    /// trying the OAuth well-known URL then the OpenID Connect
    /// Discovery one. `None` when neither resolves.
    #[cfg(feature = "rfc8414")]
    pub fn oauth_server(&self, issuer: &Url) -> Option<OauthServerMetadata> {
        let well_known = OauthServerMetadata::well_known_url(issuer);
        if let Ok(metadata) = run(&mut self.pool(), ResolveOauthServer::new(well_known)) {
            return Some(metadata);
        }

        let openid = OauthServerMetadata::openid_well_known_url(issuer);
        run(&mut self.pool(), ResolveOauthServer::new(openid)).ok()
    }

    /// Fetches `resource`'s RFC 9728 protected resource metadata from
    /// its well-known URL. `None` when it does not resolve.
    #[cfg(feature = "rfc9728")]
    pub fn oauth_resource(&self, resource: &Url) -> Option<OauthResourceMetadata> {
        let well_known = OauthResourceMetadata::well_known_url(resource);
        run(&mut self.pool(), ResolveOauthResource::new(well_known)).ok()
    }

    fn compose(
        &self,
        email: &str,
        services: BTreeSet<Service>,
        first: bool,
    ) -> Result<Vec<ServiceConfig>, ComposeClientStdError> {
        debug!("begin config compose");
        trace!("email {email}, first: {first}, services: {services:?}");

        let outputs = self.parallel_outputs(email, &services)?;
        let mut collector = ConfigCollector::new(services);

        for configs in outputs {
            collector.collect(configs);

            if first && !collector.is_empty() {
                debug!("keep first mechanism yielding configs");
                break;
            }
        }

        let mut configs = collector.finish();
        self.probe(&mut configs);
        self.resolve_issuers(&mut configs);

        debug!("end of config compose");
        trace!("{configs:?}");
        Ok(configs)
    }

    /// Runs every mechanism relevant to `services` in parallel (one
    /// thread each) and returns their outputs in mechanism-priority
    /// order, one entry per mechanism, unreduced.
    fn parallel_outputs(
        &self,
        email: &str,
        services: &BTreeSet<Service>,
    ) -> Result<Vec<Vec<ServiceConfig>>, ComposeClientStdError> {
        let email = email.trim();

        let Some((local, domain)) = email.split_once('@') else {
            return Err(ComposeClientStdError::InvalidEmail(email.to_string()));
        };
        let domain = domain.trim_matches('.').to_ascii_lowercase();

        let wants = |service: Service| services.is_empty() || services.contains(&service);
        let wants_mail = wants(Service::Imap) || wants(Service::Pop3) || wants(Service::Smtp);

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

            if wants(Service::Imap) || wants(Service::Smtp) {
                handles.push(scope.spawn(|| self.run_srv(domain)));
            }

            #[cfg(feature = "rfc6764")]
            if wants(Service::Caldav) {
                handles.push(scope.spawn(|| self.run_dav(domain, DavService::Caldav)));
            }

            #[cfg(feature = "rfc6764")]
            if wants(Service::Carddav) {
                handles.push(scope.spawn(|| self.run_dav(domain, DavService::Carddav)));
            }

            if wants(Service::Jmap) {
                handles.push(scope.spawn(|| self.run_jmap(domain)));
            }

            handles
                .into_iter()
                .map(|handle| handle.join().unwrap_or_default())
                .collect::<Vec<_>>()
        }));

        Ok(outputs)
    }

    /// Resolves every `OauthIssuer` auth method in place: fetches the
    /// issuer's RFC 8414 metadata and replaces the bare issuer with
    /// the concrete grants it advertises. Each distinct issuer is
    /// resolved once, in parallel; unresolvable issuers are left as
    /// they were.
    #[cfg(feature = "rfc8414")]
    fn resolve_issuers(&self, configs: &mut [ServiceConfig]) {
        let issuers: BTreeSet<String> = configs
            .iter()
            .flat_map(|config| &config.auth)
            .filter_map(|method| match method {
                AuthMethod::OauthIssuer(issuer) => Some(issuer.clone()),
                _ => None,
            })
            .collect();

        if issuers.is_empty() {
            return;
        }

        let resolved: BTreeMap<String, Vec<AuthMethod>> = thread::scope(|scope| {
            let handles: Vec<_> = issuers
                .iter()
                .map(|issuer| scope.spawn(move || (issuer.clone(), self.resolve_issuer(issuer))))
                .collect();

            handles
                .into_iter()
                .filter_map(|handle| handle.join().ok())
                .collect()
        });

        for config in configs.iter_mut() {
            let mut auth = Vec::new();

            for method in config.auth.drain(..) {
                match method {
                    AuthMethod::OauthIssuer(issuer) => match resolved.get(&issuer) {
                        Some(methods) => auth.extend(methods.iter().cloned()),
                        None => auth.push(AuthMethod::OauthIssuer(issuer)),
                    },
                    other => auth.push(other),
                }
            }

            config.auth = auth;
        }
    }

    /// No-op when RFC 8414 is not compiled in: discovered issuers stay
    /// as bare `OauthIssuer` methods.
    #[cfg(not(feature = "rfc8414"))]
    fn resolve_issuers(&self, _configs: &mut [ServiceConfig]) {}

    /// Resolves one issuer to the grants its RFC 8414 metadata
    /// advertises (authorization code grant, plus device grant when
    /// the metadata names a device authorization endpoint). Falls back
    /// to the bare issuer when the metadata cannot be fetched or names
    /// no usable endpoints.
    #[cfg(feature = "rfc8414")]
    fn resolve_issuer(&self, issuer: &str) -> Vec<AuthMethod> {
        let bare = || vec![AuthMethod::OauthIssuer(issuer.to_string())];

        let Ok(issuer_url) = Url::parse(issuer) else {
            return bare();
        };
        let Some(metadata) = self.oauth_server(&issuer_url) else {
            debug!("skip unresolvable OAuth issuer");
            trace!("{issuer}");
            return bare();
        };

        let mut methods = Vec::new();

        if let (Some(authorization), Some(token)) =
            (&metadata.authorization_endpoint, &metadata.token_endpoint)
        {
            methods.push(AuthMethod::OauthAuthorizationCodeGrant {
                authorization_endpoint: authorization.to_string(),
                token_endpoint: token.to_string(),
                scope: None,
            });
        }

        if let (Some(device), Some(token)) = (
            &metadata.device_authorization_endpoint,
            &metadata.token_endpoint,
        ) {
            methods.push(AuthMethod::OauthDeviceAuthorizationGrant {
                device_authorization_endpoint: device.to_string(),
                token_endpoint: token.to_string(),
                scope: None,
            });
        }

        if methods.is_empty() { bare() } else { methods }
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
    #[cfg(feature = "rfc8620")]
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

    /// No-op when the auth probe (RFC 9110, behind `rfc8620`) is not
    /// compiled in: configs keep the auth methods their mechanism
    /// reported.
    #[cfg(not(feature = "rfc8620"))]
    fn probe(&self, _configs: &mut [ServiceConfig]) {}

    /// Detects the fixed provider hosting `email`: the domain rule
    /// first, then MX-based detection. `None` when neither matches.
    fn detect_provider(&self, email: &str) -> Option<Provider> {
        let domain = domain_part(email);
        Provider::from_domain(&domain).or_else(|| self.provider_from_mx(&domain))
    }

    /// Looks up `domain`'s MX records and returns the first fixed
    /// provider (Google Workspace, Microsoft 365) they match.
    #[cfg(feature = "autoconfig")]
    fn provider_from_mx(&self, domain: &str) -> Option<Provider> {
        let mx = DiscoveryDnsMx::new(domain, self.dns.clone());

        let records = match run(&mut self.pool(), mx) {
            Ok(records) => records,
            Err(err) => {
                debug!("skip MX provider detection");
                trace!("{err:?}");
                return None;
            }
        };

        for record in records {
            let exchange = record.data().exchange().to_string();

            if let Some(provider) = Provider::from_mx(&exchange) {
                debug!("MX record matched a fixed provider rule");
                trace!("{exchange} -> {provider:?}");
                return Some(provider);
            }
        }

        None
    }

    /// The fixed configs of the provider hosting `domain` per its MX
    /// records, or empty.
    #[cfg(feature = "autoconfig")]
    fn run_mx(&self, domain: &str, email: &str) -> Vec<ServiceConfig> {
        self.provider_from_mx(domain)
            .map(|provider| provider.configs(email))
            .unwrap_or_default()
    }

    /// No-op stubs when `autoconfig` (which owns the MX coroutine) is
    /// off: provider detection falls back to the pure domain rule.
    #[cfg(not(feature = "autoconfig"))]
    fn provider_from_mx(&self, _domain: &str) -> Option<Provider> {
        None
    }

    #[cfg(not(feature = "autoconfig"))]
    fn run_mx(&self, _domain: &str, _email: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }

    #[cfg(feature = "pacc")]
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

    #[cfg(not(feature = "pacc"))]
    fn run_pacc(&self, _domain: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }

    #[cfg(feature = "autoconfig")]
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

    #[cfg(feature = "autoconfig")]
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

    #[cfg(feature = "autoconfig")]
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
    #[cfg(feature = "autoconfig")]
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

    #[cfg(feature = "autoconfig")]
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

    /// No-op autoconfig stubs when `autoconfig` is off, so the
    /// orchestrator calls them without a cfg at each site.
    #[cfg(not(feature = "autoconfig"))]
    fn run_isp_main(&self, _local: &str, _domain: &str, _email: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }

    #[cfg(not(feature = "autoconfig"))]
    fn run_isp_fallback(&self, _domain: &str, _email: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }

    #[cfg(not(feature = "autoconfig"))]
    fn run_ispdb(&self, _domain: &str, _email: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }

    #[cfg(not(feature = "autoconfig"))]
    fn run_mailconf(&self, _domain: &str, _email: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }

    #[cfg(feature = "rfc6186")]
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

    #[cfg(not(feature = "rfc6186"))]
    fn run_srv(&self, _domain: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }

    #[cfg(feature = "rfc6764")]
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

    #[cfg(feature = "rfc8620")]
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

    #[cfg(not(feature = "rfc8620"))]
    fn run_jmap(&self, _domain: &str) -> Vec<ServiceConfig> {
        Vec::new()
    }
}

/// The lowercased, dot-trimmed domain part of an email address, or the
/// whole input when it carries no `@`.
fn domain_part(email: &str) -> String {
    let domain = email
        .split_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or(email);
    normalize_domain(domain)
}

/// Lowercases and trims surrounding whitespace and dots from a domain.
fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_matches('.').to_ascii_lowercase()
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
                        debug!("compose read failed, signal EOF");
                        trace!("{url}: {err:?}");
                        arg = Some(&[]);
                    }
                }
            }
            DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite { url, bytes }) => {
                match pool.get(&url).and_then(|s| Ok(s.write_all(&bytes)?)) {
                    Ok(()) => {}
                    Err(err) => {
                        debug!("compose write failed, signal EOF");
                        trace!("{url}: {err:?}");
                        arg = Some(&[]);
                    }
                }
            }
        }
    }
}
