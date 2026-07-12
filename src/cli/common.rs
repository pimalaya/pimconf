//! Shared CLI helpers: the DNS resolver flag, the per-domain service
//! sets, and the service-config table output.

use std::{
    fmt,
    string::{String, ToString},
    vec::Vec,
};

use anyhow::Result;
use clap::Args;
use pimalaya_cli::table::{Cell, ContentArrangement, Table, presets::UTF8_FULL};
use pimalaya_stream::tls::Tls;

use crate::{
    compose::{
        client::ComposeClientStd,
        providers::Provider,
        types::{AuthMethod, ConfigSource, Endpoint, Security, Service, ServiceConfig},
    },
    shared::dns::{DNS_SERVER, resolver_url},
};

/// Services of the email domain (JMAP included: it serves mail too;
/// ManageSieve manages server-side mail filters).
pub const EMAIL: &[Service] = &[
    Service::Imap,
    Service::Pop3,
    Service::Smtp,
    Service::Jmap,
    Service::Managesieve,
];

/// Services of the calendar domain (JMAP reused across domains).
pub const CALENDAR: &[Service] = &[Service::Caldav, Service::Jmap];

/// Services of the contact domain (JMAP reused across domains).
pub const CONTACT: &[Service] = &[Service::Carddav, Service::Jmap];

/// Services of the file domain (generic WebDAV file storage).
pub const FILE: &[Service] = &[Service::Webdav];

/// DNS resolver flag shared by every discovery command.
#[derive(Debug, Args)]
pub struct ServerArg {
    /// DNS resolver: `host:port`, or an RFC 8484 resolver URL such as
    /// `https://cloudflare-dns.com/dns-query`.
    #[arg(long, default_value = DNS_SERVER)]
    pub server: String,
}

impl ServerArg {
    /// Builds a compose client resolving DNS through the flag and
    /// running the HTTPS mechanisms over `tls`.
    pub fn client(&self, tls: &Tls) -> Result<ComposeClientStd> {
        Ok(ComposeClientStd::new(
            resolver_url(&self.server)?,
            tls.clone(),
        ))
    }
}

/// Keeps only the configs whose service belongs to `services`.
pub fn only(configs: Vec<ServiceConfig>, services: &[Service]) -> Vec<ServiceConfig> {
    configs
        .into_iter()
        .filter(|config| services.contains(&config.service))
        .collect()
}

/// The service-config table output, wrapping a raw (unmerged) config
/// list.
#[derive(serde::Serialize)]
#[serde(transparent)]
pub struct ConfigsOutput(pub Vec<ServiceConfig>);

impl fmt::Display for ConfigsOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", table(&self.0))
    }
}

/// Renders a service-config table: SERVICE, ENDPOINT, USERNAME, AUTH
/// and the SOURCE mechanism that produced each row.
pub fn table(configs: &[ServiceConfig]) -> Table {
    let mut table = Table::new();

    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("SERVICE"),
            Cell::new("ENDPOINT"),
            Cell::new("USERNAME"),
            Cell::new("AUTH"),
            Cell::new("SOURCE"),
        ]);

    for config in configs {
        table.add_row(vec![
            Cell::new(service_name(config.service)),
            Cell::new(endpoint_label(&config.endpoint)),
            Cell::new(config.username.as_deref().unwrap_or("-")),
            Cell::new(auth_label(&config.auth)),
            Cell::new(source_name(config.source)),
        ]);
    }

    table
}

/// Lowercase wire name of a service.
pub fn service_name(service: Service) -> &'static str {
    match service {
        Service::Imap => "imap",
        Service::Pop3 => "pop3",
        Service::Smtp => "smtp",
        Service::Jmap => "jmap",
        Service::Caldav => "caldav",
        Service::Carddav => "carddav",
        Service::Webdav => "webdav",
        Service::Managesieve => "managesieve",
    }
}

fn endpoint_label(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Tcp {
            host,
            port,
            security,
        } => {
            let security = match security {
                Security::Plain => "plain",
                Security::Starttls => "STARTTLS",
                Security::Tls => "SSL",
            };
            format!("{host}:{port} ({security})")
        }
        Endpoint::Http(url) => url.clone(),
    }
}

fn auth_label(methods: &[AuthMethod]) -> String {
    if methods.is_empty() {
        return "-".to_string();
    }

    methods
        .iter()
        .map(|method| match method {
            AuthMethod::Password => "password".to_string(),
            AuthMethod::Bearer => "bearer".to_string(),
            AuthMethod::OauthAuthorizationCodeGrant { .. } => {
                "oauth2:authorization-code".to_string()
            }
            AuthMethod::OauthDeviceAuthorizationGrant { .. } => "oauth2:device".to_string(),
            AuthMethod::OauthIssuer(issuer) => format!("oauth2:{issuer}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn source_name(source: ConfigSource) -> &'static str {
    match source {
        ConfigSource::Provider(Provider::Google) => "provider:google",
        ConfigSource::Provider(Provider::Microsoft) => "provider:microsoft",
        ConfigSource::Pacc => "pacc",
        ConfigSource::IspMain => "isp",
        ConfigSource::IspFallback => "isp-fallback",
        ConfigSource::Mailconf => "mailconf",
        ConfigSource::Ispdb => "ispdb",
        ConfigSource::Srv => "srv",
        ConfigSource::Dav => "dav",
        ConfigSource::Jmap => "jmap",
    }
}
