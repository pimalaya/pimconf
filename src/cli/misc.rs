//! Top-level discovery commands not tied to a single domain: `all`
//! (everything, grouped by domain) and `auth` (authentication
//! discovery: scheme probe plus OAuth server/resource metadata).

use std::{
    collections::BTreeSet,
    fmt,
    string::{String, ToString},
    vec::Vec,
};

use anyhow::Result;
use clap::{Args, Subcommand};
use pimalaya_cli::printer::Printer;
use pimalaya_stream::tls::Tls;
use serde::Serialize;
use url::Url;

use crate::{
    cli::common::{ServerArg, table},
    compose::types::{DiscoveryService, DiscoveryServiceConfig},
    rfc8414::DiscoveryOauthServerMetadata,
    rfc9728::DiscoveryOauthResourceMetadata,
};

/// Discover every service for an email address across all domains.
///
/// Runs every mechanism in parallel and lists the results grouped by
/// domain, without merging: each mechanism's output stays independent
/// (the SOURCE column tells them apart).
#[derive(Debug, Args)]
pub struct AllCommand {
    /// Email address to discover configs for.
    pub email: String,
    #[command(flatten)]
    pub server: ServerArg,
}

impl AllCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        let client = self.server.client(tls)?;
        let configs = client.compose_raw(&self.email, BTreeSet::new())?;
        printer.out(AllOutput(configs))
    }
}

/// Discover how and where to authenticate against an endpoint.
///
/// `http` probes a live endpoint's `WWW-Authenticate` schemes on a
/// 401; `server` and `resource` fetch OAuth 2.0 metadata documents.
/// Text-protocol probes (IMAP/SMTP SASL) can join as siblings later.
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Probe an HTTP endpoint's `WWW-Authenticate` schemes on a 401.
    Http(AuthArgs),
    /// Fetch an OAuth 2.0 authorization server's metadata (RFC 8414).
    Server(AuthArgs),
    /// Fetch an OAuth 2.0 protected resource's metadata (RFC 9728).
    Resource(AuthArgs),
}

#[derive(Debug, Args)]
pub struct AuthArgs {
    /// URL to probe: an HTTP endpoint (`http`), an OAuth issuer
    /// (`server`), or a protected resource (`resource`).
    pub url: Url,
    #[command(flatten)]
    pub server: ServerArg,
}

impl AuthCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        match self {
            Self::Http(args) => {
                let client = args.server.client(tls)?;
                let schemes = client.auth(args.url.clone()).unwrap_or_default();

                printer.out(AuthOutput {
                    url: args.url.to_string(),
                    schemes,
                })
            }
            Self::Server(args) => {
                let client = args.server.client(tls)?;
                let metadata = client.oauth_server(&args.url);

                printer.out(ServerOutput {
                    issuer: args.url.to_string(),
                    metadata,
                })
            }
            Self::Resource(args) => {
                let client = args.server.client(tls)?;
                let metadata = client.oauth_resource(&args.url);

                printer.out(ResourceOutput {
                    resource: args.url.to_string(),
                    metadata,
                })
            }
        }
    }
}

/// The `all` output: configs grouped into domain sections, each
/// rendered as its own table.
#[derive(Serialize)]
#[serde(transparent)]
struct AllOutput(Vec<DiscoveryServiceConfig>);

impl fmt::Display for AllOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // JMAP is listed under EMAIL to avoid repeating one session
        // under every domain; the per-domain `jmap` subcommands still
        // resolve it explicitly for calendars and contacts.
        let sections: [(&str, &[DiscoveryService]); 4] = [
            (
                "EMAIL",
                &[
                    DiscoveryService::Imap,
                    DiscoveryService::Pop3,
                    DiscoveryService::Smtp,
                    DiscoveryService::Jmap,
                    DiscoveryService::Managesieve,
                ],
            ),
            ("CALENDAR", &[DiscoveryService::Caldav]),
            ("CONTACT", &[DiscoveryService::Carddav]),
            ("FILE", &[DiscoveryService::Webdav]),
        ];

        let mut first = true;

        for (label, services) in sections {
            let configs: Vec<DiscoveryServiceConfig> = self
                .0
                .iter()
                .filter(|config| services.contains(&config.service))
                .cloned()
                .collect();

            if configs.is_empty() {
                continue;
            }

            if !first {
                writeln!(f)?;
            }
            first = false;

            writeln!(f, "{label}")?;
            writeln!(f, "{}", table(&configs))?;
        }

        Ok(())
    }
}

/// The `auth` output: the probed URL and the schemes it advertised.
#[derive(Serialize)]
struct AuthOutput {
    url: String,
    schemes: Vec<String>,
}

impl fmt::Display for AuthOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.schemes.is_empty() {
            return write!(f, "No authentication scheme advertised by {}", self.url);
        }

        writeln!(f, "Authentication schemes advertised by {}:", self.url)?;

        for scheme in &self.schemes {
            writeln!(f, " - {scheme}")?;
        }

        Ok(())
    }
}

/// The `auth server` output: the issuer and its RFC 8414 metadata.
#[derive(Serialize)]
struct ServerOutput {
    issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<DiscoveryOauthServerMetadata>,
}

impl fmt::Display for ServerOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(metadata) = &self.metadata else {
            return write!(
                f,
                "No authorization server metadata found for {}",
                self.issuer
            );
        };

        writeln!(f, "Authorization server metadata for {}:", self.issuer)?;

        if let Some(endpoint) = &metadata.authorization_endpoint {
            writeln!(f, " - authorization endpoint: {endpoint}")?;
        }
        if let Some(endpoint) = &metadata.token_endpoint {
            writeln!(f, " - token endpoint: {endpoint}")?;
        }
        if let Some(endpoint) = &metadata.device_authorization_endpoint {
            writeln!(f, " - device authorization endpoint: {endpoint}")?;
        }
        if let Some(endpoint) = &metadata.registration_endpoint {
            writeln!(f, " - registration endpoint: {endpoint}")?;
        }
        if !metadata.grant_types_supported.is_empty() {
            writeln!(
                f,
                " - grant types: {}",
                metadata.grant_types_supported.join(", ")
            )?;
        }
        if !metadata.scopes_supported.is_empty() {
            writeln!(f, " - scopes: {}", metadata.scopes_supported.join(", "))?;
        }

        Ok(())
    }
}

/// The `auth resource` output: the resource and its RFC 9728 metadata.
#[derive(Serialize)]
struct ResourceOutput {
    resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<DiscoveryOauthResourceMetadata>,
}

impl fmt::Display for ResourceOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(metadata) = &self.metadata else {
            return write!(
                f,
                "No protected resource metadata found for {}",
                self.resource
            );
        };

        writeln!(f, "Protected resource metadata for {}:", self.resource)?;

        if !metadata.authorization_servers.is_empty() {
            writeln!(f, " - authorization servers:")?;
            for server in &metadata.authorization_servers {
                writeln!(f, "   - {server}")?;
            }
        }
        if !metadata.bearer_methods_supported.is_empty() {
            writeln!(
                f,
                " - bearer methods: {}",
                metadata.bearer_methods_supported.join(", ")
            )?;
        }
        if !metadata.scopes_supported.is_empty() {
            writeln!(f, " - scopes: {}", metadata.scopes_supported.join(", "))?;
        }

        Ok(())
    }
}
