use std::{
    collections::BTreeSet,
    fmt,
    string::{String, ToString},
    vec::Vec,
};

use anyhow::Result;
use clap::{Args, ValueEnum};
use pimalaya_cli::{
    printer::Printer,
    table::{Cell, ContentArrangement, Table, presets::UTF8_FULL},
};
use pimalaya_stream::tls::Tls;

use crate::{
    search::{
        client::SearchClientStd,
        providers::Provider,
        types::{AuthMethod, ConfigSource, Endpoint, Security, Service, ServiceConfig},
    },
    shared::dns::{DNS_SERVER, resolver_url},
};

/// Search service configs for an email address.
///
/// Chains fixed provider rules (domain match, then MX-based
/// detection), PACC, Mozilla autoconfig (ISP main, ISP fallback,
/// mailconf, ISPDB), RFC 6186 SRV records and the RFC 6764
/// CalDAV/CardDAV resolve, and reduces everything to one list of
/// service configs with their authentication methods.
#[derive(Debug, Args)]
pub struct SearchCommand {
    /// Email address to search configs for.
    pub email: String,
    /// Stop at the first mechanism yielding at least one config.
    #[arg(long)]
    pub first: bool,
    /// Restrict the search to the given services.
    #[arg(long = "service", value_enum, value_name = "SERVICE")]
    pub services: Vec<ServiceArg>,
    /// DNS resolver: `host:port`, or an RFC 8484 resolver URL such
    /// as `https://cloudflare-dns.com/dns-query`.
    #[arg(long, default_value = DNS_SERVER)]
    pub server: String,
}

impl SearchCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        let resolver = resolver_url(&self.server)?;
        let client = SearchClientStd::new(resolver, tls.clone());
        let services: BTreeSet<Service> = self.services.into_iter().map(Into::into).collect();

        let configs = if self.first {
            client.search_first(&self.email, services)?
        } else {
            client.search_all(&self.email, services)?
        };

        printer.out(SearchOutput(configs))
    }
}

/// CLI flavor of [`Service`] for the `--service` flag.
#[derive(Clone, Debug, ValueEnum)]
pub enum ServiceArg {
    Imap,
    Pop3,
    Smtp,
    Jmap,
    Caldav,
    Carddav,
    Webdav,
    Managesieve,
}

impl From<ServiceArg> for Service {
    fn from(arg: ServiceArg) -> Self {
        match arg {
            ServiceArg::Imap => Self::Imap,
            ServiceArg::Pop3 => Self::Pop3,
            ServiceArg::Smtp => Self::Smtp,
            ServiceArg::Jmap => Self::Jmap,
            ServiceArg::Caldav => Self::Caldav,
            ServiceArg::Carddav => Self::Carddav,
            ServiceArg::Webdav => Self::Webdav,
            ServiceArg::Managesieve => Self::Managesieve,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct SearchOutput(Vec<ServiceConfig>);

impl fmt::Display for SearchOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

        for config in &self.0 {
            let service = match config.service {
                Service::Imap => "imap",
                Service::Pop3 => "pop3",
                Service::Smtp => "smtp",
                Service::Jmap => "jmap",
                Service::Caldav => "caldav",
                Service::Carddav => "carddav",
                Service::Webdav => "webdav",
                Service::Managesieve => "managesieve",
            };

            let endpoint = match &config.endpoint {
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
            };

            let auth = config
                .auth
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
                .join(", ");

            let source = match config.source {
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
            };

            table.add_row(vec![
                Cell::new(service),
                Cell::new(endpoint),
                Cell::new(config.username.as_deref().unwrap_or("-")),
                Cell::new(if auth.is_empty() {
                    "-".to_string()
                } else {
                    auth
                }),
                Cell::new(source),
            ]);
        }

        write!(f, "{table}")
    }
}
