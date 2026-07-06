//! # Search-all coroutine
//!
//! [`SearchAll`] turns one email address into every [`ServiceConfig`]
//! the known mechanisms can produce, in order: fixed provider rules
//! (domain match, then MX-based detection for custom domains hosted
//! on Google Workspace or Microsoft 365), PACC, the Mozilla
//! autoconfig locations (ISP main, ISP fallback, the mailconf TXT
//! redirect, ISPDB), RFC 6186 SRV records, the RFC 6764
//! CalDAV/CardDAV resolve and the RFC 8620 JMAP resolve.
//!
//! Mechanism failures are logged and skipped: only an invalid email
//! address fails the whole search. Mechanisms irrelevant to the
//! requested services are skipped entirely, and configs for the same
//! service, endpoint and username merge their authentication methods
//! instead of duplicating (the first mechanism keeps the source tag).

use core::mem;

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

use log::{debug, trace};
use thiserror::Error;
use url::Url;

use crate::{
    autoconfig::{isp::DiscoveryIsp, mailconf::DiscoveryMailconf, mx::DiscoveryDnsMx},
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    pacc::discover::DiscoveryPacc,
    rfc6186::discover::DiscoverySrv,
    rfc6764::{resolve::ResolveDav, types::DavService},
    rfc8620::resolve::ResolveJmap,
    search::{
        providers::Provider,
        types::{ConfigSource, Service, ServiceConfig},
    },
};

/// Errors emitted by the search coroutines.
#[derive(Debug, Error)]
pub enum SearchError {
    /// The input is not a valid `local@domain` email address.
    #[error("Search email `{0}` is missing the `@` separator")]
    InvalidEmail(String),
}

/// I/O-free coroutine that collects every service config the known
/// mechanisms produce for one email address.
pub struct SearchAll {
    email: String,
    domain: String,
    services: BTreeSet<Service>,
    resolver: Url,
    first: bool,
    provider_matched: bool,
    configs: Vec<ServiceConfig>,
    state: State,
}

impl SearchAll {
    /// Builds a search for `email`, restricted to `services` (empty
    /// means all services). `resolver` must be a `tcp://host:port`
    /// DNS-over-TCP resolver URL.
    pub fn new(
        email: impl AsRef<str>,
        services: BTreeSet<Service>,
        resolver: Url,
    ) -> Result<Self, SearchError> {
        Self::build(email, services, resolver, false)
    }

    pub(crate) fn build(
        email: impl AsRef<str>,
        services: BTreeSet<Service>,
        resolver: Url,
        first: bool,
    ) -> Result<Self, SearchError> {
        let email = email.as_ref().trim();

        let Some((_, domain)) = email.split_once('@') else {
            return Err(SearchError::InvalidEmail(email.to_string()));
        };

        debug!("begin config search");
        trace!("email {email}, first: {first}, services: {services:?}");

        Ok(Self {
            email: email.to_string(),
            domain: domain.trim_matches('.').to_ascii_lowercase(),
            services,
            resolver,
            first,
            provider_matched: false,
            configs: Vec::new(),
            state: State::Start,
        })
    }

    fn wants(&self, service: Service) -> bool {
        self.services.is_empty() || self.services.contains(&service)
    }

    fn wants_mail(&self) -> bool {
        [Service::Imap, Service::Pop3, Service::Smtp]
            .iter()
            .any(|s| self.wants(*s))
    }

    /// Keeps the configs matching the requested services. A config
    /// whose service, endpoint and username were already collected by
    /// an earlier mechanism merges its authentication methods into the
    /// existing config instead of duplicating it.
    fn collect(&mut self, configs: Vec<ServiceConfig>) {
        for config in configs {
            if !self.wants(config.service) {
                continue;
            }

            let existing = self.configs.iter_mut().find(|c| {
                c.service == config.service
                    && c.endpoint == config.endpoint
                    && c.username == config.username
            });

            match existing {
                Some(existing) => {
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

    /// Enters the first applicable mechanism at or after `step`, or
    /// completes when none is left. In first mode, completes as soon
    /// as any config has been collected.
    fn advance(
        &mut self,
        mut step: Step,
    ) -> DiscoveryCoroutineState<DiscoveryYield, Result<Vec<ServiceConfig>, SearchError>> {
        if self.first && !self.configs.is_empty() {
            debug!("stop search at first mechanism yielding configs");
            trace!("{:?}", self.configs);
            return DiscoveryCoroutineState::Complete(Ok(mem::take(&mut self.configs)));
        }

        loop {
            match step {
                Step::Mx => {
                    if !self.provider_matched {
                        let mx = DiscoveryDnsMx::new(&self.domain, self.resolver.clone());
                        self.state = State::Mx(mx);
                        return self.resume(None);
                    }
                    step = Step::Pacc;
                }
                Step::Pacc => match DiscoveryPacc::new(&self.domain, self.resolver.clone()) {
                    Ok(pacc) => {
                        self.state = State::Pacc(pacc);
                        return self.resume(None);
                    }
                    Err(err) => {
                        debug!("skip PACC discovery");
                        trace!("{err:?}");
                        step = Step::IspMain;
                    }
                },
                Step::IspMain => {
                    if self.wants_mail() {
                        let local_part = self.email.split_once('@').map(|(l, _)| l);
                        let url = DiscoveryIsp::main_url(
                            local_part.unwrap_or_default(),
                            &self.domain,
                            true,
                        );

                        match url {
                            Ok(url) => {
                                self.state = State::IspMain(DiscoveryIsp::new(url));
                                return self.resume(None);
                            }
                            Err(err) => {
                                debug!("skip autoconfig ISP main URL");
                                trace!("{err:?}");
                            }
                        }
                    }
                    step = Step::IspFallback;
                }
                Step::IspFallback => {
                    if self.wants_mail() {
                        match DiscoveryIsp::fallback_url(&self.domain, true) {
                            Ok(url) => {
                                self.state = State::IspFallback(DiscoveryIsp::new(url));
                                return self.resume(None);
                            }
                            Err(err) => {
                                debug!("skip autoconfig ISP fallback URL");
                                trace!("{err:?}");
                            }
                        }
                    }
                    step = Step::Mailconf;
                }
                Step::Mailconf => {
                    if self.wants_mail() {
                        let mailconf = DiscoveryMailconf::new(&self.domain, self.resolver.clone());
                        self.state = State::Mailconf(mailconf);
                        return self.resume(None);
                    }
                    step = Step::Ispdb;
                }
                Step::Ispdb => {
                    if self.wants_mail() {
                        match DiscoveryIsp::db_url(&self.domain, true) {
                            Ok(url) => {
                                self.state = State::Ispdb(DiscoveryIsp::new(url));
                                return self.resume(None);
                            }
                            Err(err) => {
                                debug!("skip autoconfig ISPDB URL");
                                trace!("{err:?}");
                            }
                        }
                    }
                    step = Step::Srv;
                }
                Step::Srv => {
                    if self.wants(Service::Imap) || self.wants(Service::Smtp) {
                        let srv = DiscoverySrv::new(&self.domain, self.resolver.clone());
                        self.state = State::Srv(srv);
                        return self.resume(None);
                    }
                    step = Step::Caldav;
                }
                Step::Caldav => {
                    if self.wants(Service::Caldav) {
                        let resolve = ResolveDav::new(
                            &self.domain,
                            DavService::Caldav,
                            self.resolver.clone(),
                        );
                        self.state = State::Caldav(resolve);
                        return self.resume(None);
                    }
                    step = Step::Carddav;
                }
                Step::Carddav => {
                    if self.wants(Service::Carddav) {
                        let resolve = ResolveDav::new(
                            &self.domain,
                            DavService::Carddav,
                            self.resolver.clone(),
                        );
                        self.state = State::Carddav(resolve);
                        return self.resume(None);
                    }
                    step = Step::Jmap;
                }
                Step::Jmap => {
                    if self.wants(Service::Jmap) {
                        let resolve = ResolveJmap::new(&self.domain, self.resolver.clone());
                        self.state = State::Jmap(resolve);
                        return self.resume(None);
                    }
                    step = Step::End;
                }
                Step::End => {
                    debug!("end of config search");
                    trace!("{:?}", self.configs);
                    return DiscoveryCoroutineState::Complete(Ok(mem::take(&mut self.configs)));
                }
            }
        }
    }
}

impl DiscoveryCoroutine for SearchAll {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<ServiceConfig>, SearchError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::Start => {
                if let Some(provider) = Provider::from_domain(&self.domain) {
                    debug!("email domain matched a fixed provider rule");
                    trace!("{} -> {provider:?}", self.domain);
                    self.provider_matched = true;
                    let configs = provider.configs(&self.email);
                    self.collect(configs);
                }
                self.advance(Step::Mx)
            }
            State::Mx(mut mx) => match mx.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Mx(mx);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(records) => {
                            for record in records {
                                let exchange = record.data().exchange().to_string();

                                if let Some(provider) = Provider::from_mx(&exchange) {
                                    debug!("MX record matched a fixed provider rule");
                                    trace!("{exchange} -> {provider:?}");
                                    let configs = provider.configs(&self.email);
                                    self.collect(configs);
                                    break;
                                }
                            }
                        }
                        Err(err) => {
                            debug!("skip MX provider detection");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::Pacc)
                }
            },
            State::Pacc(mut pacc) => match pacc.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Pacc(pacc);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(config) => self.collect(ServiceConfig::from_pacc(&config)),
                        Err(err) => {
                            debug!("skip PACC discovery");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::IspMain)
                }
            },
            State::IspMain(mut isp) => match isp.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::IspMain(isp);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(config) => self.collect(ServiceConfig::from_autoconfig(
                            &config,
                            &self.email,
                            ConfigSource::IspMain,
                        )),
                        Err(err) => {
                            debug!("skip autoconfig ISP main URL");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::IspFallback)
                }
            },
            State::IspFallback(mut isp) => match isp.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::IspFallback(isp);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(config) => self.collect(ServiceConfig::from_autoconfig(
                            &config,
                            &self.email,
                            ConfigSource::IspFallback,
                        )),
                        Err(err) => {
                            debug!("skip autoconfig ISP fallback URL");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::Mailconf)
                }
            },
            State::Mailconf(mut mailconf) => match mailconf.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Mailconf(mailconf);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Ok(url)) => {
                    debug!("follow mailconf TXT redirect");
                    trace!("{url}");
                    self.state = State::MailconfIsp(DiscoveryIsp::new(url));
                    self.resume(None)
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    debug!("skip mailconf TXT redirect");
                    trace!("{err:?}");
                    self.advance(Step::Ispdb)
                }
            },
            State::MailconfIsp(mut isp) => match isp.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::MailconfIsp(isp);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(config) => self.collect(ServiceConfig::from_autoconfig(
                            &config,
                            &self.email,
                            ConfigSource::Mailconf,
                        )),
                        Err(err) => {
                            debug!("skip mailconf autoconfig document");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::Ispdb)
                }
            },
            State::Ispdb(mut isp) => match isp.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Ispdb(isp);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(config) => self.collect(ServiceConfig::from_autoconfig(
                            &config,
                            &self.email,
                            ConfigSource::Ispdb,
                        )),
                        Err(err) => {
                            debug!("skip autoconfig ISPDB");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::Srv)
                }
            },
            State::Srv(mut srv) => match srv.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Srv(srv);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(report) => self.collect(ServiceConfig::from_srv(&report)),
                        Err(err) => {
                            debug!("skip RFC 6186 SRV discovery");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::Caldav)
                }
            },
            State::Caldav(mut resolve) => match resolve.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Caldav(resolve);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(url) => {
                            self.collect(vec![ServiceConfig::from_dav(Service::Caldav, url)])
                        }
                        Err(err) => {
                            debug!("skip RFC 6764 CalDAV resolve");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::Carddav)
                }
            },
            State::Carddav(mut resolve) => match resolve.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Carddav(resolve);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(url) => {
                            self.collect(vec![ServiceConfig::from_dav(Service::Carddav, url)])
                        }
                        Err(err) => {
                            debug!("skip RFC 6764 CardDAV resolve");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::Jmap)
                }
            },
            State::Jmap(mut resolve) => match resolve.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Jmap(resolve);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(res) => {
                    match res {
                        Ok(session) => self.collect(vec![ServiceConfig::from_jmap(
                            session.url,
                            &session.auth_schemes,
                        )]),
                        Err(err) => {
                            debug!("skip RFC 8620 JMAP resolve");
                            trace!("{err:?}");
                        }
                    }
                    self.advance(Step::End)
                }
            },
            State::Done => panic!("SearchAll::resume called after completion"),
        }
    }
}

/// The ordered mechanism chain; [`SearchAll::advance`] walks it from
/// a given step, skipping mechanisms irrelevant to the requested
/// services.
#[derive(Clone, Copy)]
enum Step {
    Mx,
    Pacc,
    IspMain,
    IspFallback,
    Mailconf,
    Ispdb,
    Srv,
    Caldav,
    Carddav,
    Jmap,
    End,
}

#[derive(Default)]
enum State {
    Start,
    Mx(DiscoveryDnsMx),
    Pacc(DiscoveryPacc),
    IspMain(DiscoveryIsp),
    IspFallback(DiscoveryIsp),
    Mailconf(DiscoveryMailconf),
    MailconfIsp(DiscoveryIsp),
    Ispdb(DiscoveryIsp),
    Srv(DiscoverySrv),
    Caldav(ResolveDav),
    Carddav(ResolveDav),
    Jmap(ResolveJmap),
    #[default]
    Done,
}
