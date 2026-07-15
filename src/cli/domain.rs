//! Domain-organised discovery commands: `email`, `calendar`,
//! `contact`. Each groups the mechanisms relevant to its PIM domain
//! and presents their raw, per-mechanism output (no merging).

use std::{string::String, vec::Vec};

use anyhow::Result;
use clap::{Args, Subcommand};
use pimalaya_cli::printer::Printer;
use pimalaya_stream::tls::Tls;

use crate::{
    cli::common::{CALENDAR, CONTACT, ConfigsOutput, EMAIL, FILE, ServerArg, only},
    compose::{
        client::DiscoveryComposeClientStd,
        types::{DiscoveryService, DiscoveryServiceConfig},
    },
    rfc6764::types::DiscoveryDavService,
};

/// Discover email services (IMAP, POP3, SMTP, JMAP, ManageSieve).
#[derive(Debug, Subcommand)]
pub enum EmailCommand {
    /// First mechanism, in priority order, that yields an email config.
    First(EmailArgs),
    /// Fixed Google configs, when the address is Google-hosted.
    IsGoogle(EmailArgs),
    /// Fixed Microsoft configs, when the address is Microsoft-hosted.
    IsMicrosoft(EmailArgs),
    /// Mozilla/Thunderbird autoconfig (ISP URLs, ISPDB, mailconf).
    Autoconfig(EmailArgs),
    /// RFC 6186 SRV records (`_imap(s)`, `_submission`).
    Srv(EmailArgs),
    /// PACC configuration document.
    Pacc(EmailArgs),
    /// RFC 8620 JMAP session resolution.
    Jmap(EmailArgs),
}

/// Discover file-storage services (WebDAV) for a domain.
#[derive(Debug, Subcommand)]
pub enum FileCommand {
    /// First mechanism, in priority order, that yields a file config.
    First(DomainArgs),
    /// PACC configuration document.
    Pacc(DomainArgs),
}

/// Discover calendar services (CalDAV, JMAP) for a domain.
#[derive(Debug, Subcommand)]
pub enum CalendarCommand {
    /// First mechanism, in priority order, that yields a calendar config.
    First(DomainArgs),
    /// RFC 6764 CalDAV resolution.
    Dav(DomainArgs),
    /// PACC configuration document.
    Pacc(DomainArgs),
    /// RFC 8620 JMAP session resolution.
    Jmap(DomainArgs),
}

/// Discover contact services (CardDAV, JMAP) for a domain.
#[derive(Debug, Subcommand)]
pub enum ContactCommand {
    /// First mechanism, in priority order, that yields a contact config.
    First(DomainArgs),
    /// RFC 6764 CardDAV resolution.
    Dav(DomainArgs),
    /// PACC configuration document.
    Pacc(DomainArgs),
    /// RFC 8620 JMAP session resolution.
    Jmap(DomainArgs),
}

/// An email address plus the shared DNS resolver flag.
#[derive(Debug, Args)]
pub struct EmailArgs {
    /// Email address to discover configs for.
    pub email: String,
    #[command(flatten)]
    pub server: ServerArg,
}

/// A bare domain plus the shared DNS resolver flag.
#[derive(Debug, Args)]
pub struct DomainArgs {
    /// Domain to discover configs for.
    pub domain: String,
    #[command(flatten)]
    pub server: ServerArg,
}

impl EmailCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        let configs = match self {
            Self::First(args) => {
                let client = args.server.client(tls)?;
                first_email(&client, &args.email)
            }
            Self::IsGoogle(args) => {
                let client = args.server.client(tls)?;
                only(client.is_google(&args.email), EMAIL)
            }
            Self::IsMicrosoft(args) => {
                let client = args.server.client(tls)?;
                only(client.is_microsoft(&args.email), EMAIL)
            }
            Self::Autoconfig(args) => {
                let client = args.server.client(tls)?;
                only(client.autoconfig(&args.email), EMAIL)
            }
            Self::Srv(args) => {
                let client = args.server.client(tls)?;
                only(client.srv(&args.email), EMAIL)
            }
            Self::Pacc(args) => {
                let client = args.server.client(tls)?;
                only(client.pacc(&args.email), EMAIL)
            }
            Self::Jmap(args) => {
                let client = args.server.client(tls)?;
                only(client.jmap(&args.email), EMAIL)
            }
        };

        printer.out(ConfigsOutput(configs))
    }
}

impl FileCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        let configs = match self {
            // PACC is the only mechanism advertising WebDAV, so `first`
            // and `pacc` coincide for now.
            Self::First(args) | Self::Pacc(args) => {
                let client = args.server.client(tls)?;
                only(client.pacc(&args.domain), FILE)
            }
        };

        printer.out(ConfigsOutput(configs))
    }
}

impl CalendarCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        let configs = match self {
            Self::First(args) => {
                let client = args.server.client(tls)?;
                first_dav(&client, &args.domain, DiscoveryDavService::Caldav, CALENDAR)
            }
            Self::Dav(args) => {
                let client = args.server.client(tls)?;
                only(
                    client.dav(&args.domain, DiscoveryDavService::Caldav),
                    CALENDAR,
                )
            }
            Self::Pacc(args) => {
                let client = args.server.client(tls)?;
                only(client.pacc(&args.domain), CALENDAR)
            }
            Self::Jmap(args) => {
                let client = args.server.client(tls)?;
                only(client.jmap(&args.domain), CALENDAR)
            }
        };

        printer.out(ConfigsOutput(configs))
    }
}

impl ContactCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        let configs = match self {
            Self::First(args) => {
                let client = args.server.client(tls)?;
                first_dav(&client, &args.domain, DiscoveryDavService::Carddav, CONTACT)
            }
            Self::Dav(args) => {
                let client = args.server.client(tls)?;
                only(
                    client.dav(&args.domain, DiscoveryDavService::Carddav),
                    CONTACT,
                )
            }
            Self::Pacc(args) => {
                let client = args.server.client(tls)?;
                only(client.pacc(&args.domain), CONTACT)
            }
            Self::Jmap(args) => {
                let client = args.server.client(tls)?;
                only(client.jmap(&args.domain), CONTACT)
            }
        };

        printer.out(ConfigsOutput(configs))
    }
}

/// Runs the email mechanisms in priority order and returns the first
/// non-empty result: provider rules, then autoconfig, PACC, SRV and
/// finally JMAP. Lazy: nothing runs past the first hit.
fn first_email(client: &DiscoveryComposeClientStd, email: &str) -> Vec<DiscoveryServiceConfig> {
    let mut configs = only(client.provider(email), EMAIL);

    if configs.is_empty() {
        configs = only(client.autoconfig(email), EMAIL);
    }
    if configs.is_empty() {
        configs = only(client.pacc(email), EMAIL);
    }
    if configs.is_empty() {
        configs = only(client.srv(email), EMAIL);
    }
    if configs.is_empty() {
        configs = only(client.jmap(email), EMAIL);
    }

    configs
}

/// Runs the DAV-domain mechanisms in priority order and returns the
/// first non-empty result: the DAV resolve, then PACC, then JMAP.
fn first_dav(
    client: &DiscoveryComposeClientStd,
    domain: &str,
    service: DiscoveryDavService,
    services: &[DiscoveryService],
) -> Vec<DiscoveryServiceConfig> {
    let mut configs = only(client.dav(domain, service), services);

    if configs.is_empty() {
        configs = only(client.pacc(domain), services);
    }
    if configs.is_empty() {
        configs = only(client.jmap(domain), services);
    }

    configs
}
