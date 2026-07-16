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
        client::DiscoveryComposeClientStd,
        config::{
            DiscoveryAuthMethod, DiscoveryConfigSource, DiscoveryEndpoint, DiscoverySecurity,
            DiscoveryService, DiscoveryServiceConfig,
        },
        providers::DiscoveryKnownProvider,
    },
    shared::dns::{DNS_SERVER, resolver_url},
};

/// Services of the email domain (JMAP included: it serves mail too;
/// ManageSieve manages server-side mail filters).
pub const EMAIL: &[DiscoveryService] = &[
    DiscoveryService::Imap,
    DiscoveryService::Pop3,
    DiscoveryService::Smtp,
    DiscoveryService::Jmap,
    DiscoveryService::Managesieve,
];

/// Services of the calendar domain (JMAP reused across domains).
pub const CALENDAR: &[DiscoveryService] = &[DiscoveryService::Caldav, DiscoveryService::Jmap];

/// Services of the contact domain (JMAP reused across domains).
pub const CONTACT: &[DiscoveryService] = &[DiscoveryService::Carddav, DiscoveryService::Jmap];

/// Services of the file domain (generic WebDAV file storage).
pub const FILE: &[DiscoveryService] = &[DiscoveryService::Webdav];

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
    pub fn client(&self, tls: &Tls) -> Result<DiscoveryComposeClientStd> {
        Ok(DiscoveryComposeClientStd::new(
            resolver_url(&self.server)?,
            tls.clone(),
        ))
    }
}

/// Keeps only the configs whose service belongs to `services`.
pub fn only(
    configs: Vec<DiscoveryServiceConfig>,
    services: &[DiscoveryService],
) -> Vec<DiscoveryServiceConfig> {
    configs
        .into_iter()
        .filter(|config| services.contains(&config.service))
        .collect()
}

/// The service-config table output, wrapping a raw (unmerged) config
/// list.
#[derive(serde::Serialize)]
#[serde(transparent)]
pub struct ConfigsOutput(pub Vec<DiscoveryServiceConfig>);

impl fmt::Display for ConfigsOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", table(&self.0))
    }
}

/// Renders a service-config table: SERVICE, ENDPOINT, USERNAME, AUTH
/// and the SOURCE mechanism that produced each row.
pub fn table(configs: &[DiscoveryServiceConfig]) -> Table {
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
pub fn service_name(service: DiscoveryService) -> &'static str {
    match service {
        DiscoveryService::Imap => "imap",
        DiscoveryService::Pop3 => "pop3",
        DiscoveryService::Smtp => "smtp",
        DiscoveryService::Jmap => "jmap",
        DiscoveryService::Caldav => "caldav",
        DiscoveryService::Carddav => "carddav",
        DiscoveryService::Webdav => "webdav",
        DiscoveryService::Managesieve => "managesieve",
    }
}

fn endpoint_label(endpoint: &DiscoveryEndpoint) -> String {
    match endpoint {
        DiscoveryEndpoint::Tcp {
            host,
            port,
            security,
        } => {
            let security = match security {
                DiscoverySecurity::Plain => "plain",
                DiscoverySecurity::Starttls => "STARTTLS",
                DiscoverySecurity::Tls => "SSL",
            };
            format!("{host}:{port} ({security})")
        }
        DiscoveryEndpoint::Http(url) => url.clone(),
    }
}

fn auth_label(methods: &[DiscoveryAuthMethod]) -> String {
    if methods.is_empty() {
        return "-".to_string();
    }

    methods
        .iter()
        .map(|method| match method {
            DiscoveryAuthMethod::Password => "password".to_string(),
            DiscoveryAuthMethod::Bearer => "bearer".to_string(),
            DiscoveryAuthMethod::OauthAuthorizationCodeGrant { .. } => {
                "oauth2:authorization-code".to_string()
            }
            DiscoveryAuthMethod::OauthDeviceAuthorizationGrant { .. } => {
                "oauth2:device".to_string()
            }
            DiscoveryAuthMethod::OauthIssuer(issuer) => format!("oauth2:{issuer}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn source_name(source: DiscoveryConfigSource) -> &'static str {
    match source {
        DiscoveryConfigSource::Provider(DiscoveryKnownProvider::Google) => "provider:google",
        DiscoveryConfigSource::Provider(DiscoveryKnownProvider::Microsoft) => "provider:microsoft",
        DiscoveryConfigSource::Pacc => "pacc",
        DiscoveryConfigSource::IspMain => "isp",
        DiscoveryConfigSource::IspFallback => "isp-fallback",
        DiscoveryConfigSource::Mailconf => "mailconf",
        DiscoveryConfigSource::Ispdb => "ispdb",
        DiscoveryConfigSource::Srv => "srv",
        DiscoveryConfigSource::Dav => "dav",
        DiscoveryConfigSource::Jmap => "jmap",
    }
}
