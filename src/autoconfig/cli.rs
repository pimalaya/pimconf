use std::{
    fmt,
    string::{String, ToString},
    vec::Vec,
};

use anyhow::{Result, anyhow, bail};
use clap::{Args, Subcommand};
use log::trace;
use pimalaya_cli::{
    printer::Printer,
    table::{Cell, ContentArrangement, Table, presets::UTF8_FULL},
};
use pimalaya_stream::tls::Tls;
use url::Url;

use crate::{
    autoconfig::{client::DiscoveryAutoconfigClientStd, mx::mx_parent_domain, types::Autoconfig},
    shared::dns::DNS_SERVER,
};

/// Thunderbird Autoconfiguration discovery.
///
/// With no subcommand, runs the five-URL ISP iteration on
/// `<LOCAL_PART> <DOMAIN>`, then re-runs it against the MX parent
/// when the original domain failed, then `mailconf` as a last
/// resort. The SRV step (RFC 6186) is intentionally not included:
/// use the `srv` top-level subcommand for that.
///
/// Each subcommand corresponds to one Mozilla [Autoconfiguration]
/// primitive and runs exactly one coroutine.
///
/// [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(arg_required_else_help = true)]
pub struct AutoconfigCommand {
    /// Local part of the email address (default-mode positional).
    /// Required when no subcommand is given; ignored otherwise.
    local_part: Option<String>,
    /// Domain of the email address (default-mode positional).
    /// Required when no subcommand is given; ignored otherwise.
    domain: Option<String>,
    /// DNS resolver (`host:port`).
    #[arg(long, default_value = DNS_SERVER)]
    server: String,

    #[command(subcommand)]
    command: Option<AutoconfigSubcommand>,
}

impl AutoconfigCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        if let Some(sub) = self.command {
            return sub.execute(printer, tls);
        }

        // Default mode: both positionals must be supplied. Clap declares
        // them `Option` to coexist with the subcommand variants, so the
        // emptiness check belongs here rather than in the parser.
        let (Some(local_part), Some(domain)) = (self.local_part, self.domain) else {
            bail!(
                "Autoconfig default mode requires both <LOCAL_PART> and <DOMAIN>; \
                 see `pimconf autoconfig --help` or pick a subcommand"
            );
        };

        let resolver = parse_resolver(&self.server)?;
        let mut client = DiscoveryAutoconfigClientStd::new(resolver).with_tls(tls.clone());

        if let Some(config) = try_isps(&mut client, &local_part, &domain) {
            return printer.out(config);
        }

        if let Some(parent) = mx_parent(&mut client, &domain) {
            if parent != domain {
                trace!("re-trying ISPs against MX parent {parent}");
                if let Some(config) = try_isps(&mut client, &local_part, &parent) {
                    return printer.out(config);
                }
            }
        }

        if let Ok(url) = client.mailconf(&domain) {
            trace!("mailconf redirect to {url} not followed by this CLI; use `isp` against {url}");
        }

        Err(anyhow!(
            "Autoconfig: no provider configuration found for `{domain}`"
        ))
    }
}

fn try_isps(
    client: &mut DiscoveryAutoconfigClientStd,
    local_part: &str,
    domain: &str,
) -> Option<Autoconfig> {
    for secure in [true, false] {
        if let Ok(ac) = client.isp(local_part, domain, secure) {
            return Some(ac);
        }
    }
    for secure in [true, false] {
        if let Ok(ac) = client.isp_fallback(domain, secure) {
            return Some(ac);
        }
    }
    if let Ok(ac) = client.ispdb(domain, true) {
        return Some(ac);
    }
    None
}

fn mx_parent(client: &mut DiscoveryAutoconfigClientStd, domain: &str) -> Option<String> {
    let records = client.mx(domain).ok()?;
    let target = records.first().map(|r| r.rdata.exchange.to_string())?;
    mx_parent_domain(&target)
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum AutoconfigSubcommand {
    /// Fetch the ISP main URL
    /// (`http[s]://autoconfig.<domain>/mail/config-v1.1.xml?emailaddress=…`).
    Isp {
        local_part: String,
        domain: String,
        /// Use HTTPS instead of plain HTTP.
        #[arg(short, long)]
        secure: bool,
        /// DNS resolver (`host:port`).
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },

    /// Fetch the ISP alternative
    /// (`http[s]://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`).
    IspFallback {
        domain: String,
        /// Use HTTPS instead of plain HTTP.
        #[arg(short, long)]
        secure: bool,
        /// DNS resolver (`host:port`).
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },

    /// Fetch the Thunderbird ISPDB
    /// (`http[s]://autoconfig.thunderbird.net/v1.1/<domain>`).
    Ispdb {
        domain: String,
        /// Use HTTPS instead of plain HTTP.
        #[arg(short, long)]
        secure: bool,
        /// DNS resolver (`host:port`).
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },

    /// Look up MX records for the given domain.
    Mx {
        domain: String,
        /// DNS resolver (`host:port`).
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },

    /// Look up the mailconf URL declared by a TXT record on the
    /// domain.
    Mailconf {
        domain: String,
        /// DNS resolver (`host:port`).
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },
}

impl AutoconfigSubcommand {
    fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        match self {
            Self::Isp {
                local_part,
                domain,
                secure,
                server,
            } => {
                let resolver = parse_resolver(&server)?;
                let mut client = DiscoveryAutoconfigClientStd::new(resolver).with_tls(tls.clone());
                printer.out(client.isp(&local_part, &domain, secure)?)
            }

            Self::IspFallback {
                domain,
                secure,
                server,
            } => {
                let resolver = parse_resolver(&server)?;
                let mut client = DiscoveryAutoconfigClientStd::new(resolver).with_tls(tls.clone());
                printer.out(client.isp_fallback(&domain, secure)?)
            }

            Self::Ispdb {
                domain,
                secure,
                server,
            } => {
                let resolver = parse_resolver(&server)?;
                let mut client = DiscoveryAutoconfigClientStd::new(resolver).with_tls(tls.clone());
                printer.out(client.ispdb(&domain, secure)?)
            }

            Self::Mx { domain, server } => {
                let resolver = parse_resolver(&server)?;
                let mut client = DiscoveryAutoconfigClientStd::new(resolver).with_tls(tls.clone());
                let records = client
                    .mx(&domain)?
                    .into_iter()
                    .map(|record| DnsMxRecordOutput {
                        preference: record.rdata.preference.get(),
                        exchange: record.rdata.exchange.to_string(),
                    })
                    .collect();
                printer.out(DnsMxOutput { records })
            }

            Self::Mailconf { domain, server } => {
                let resolver = parse_resolver(&server)?;
                let mut client = DiscoveryAutoconfigClientStd::new(resolver).with_tls(tls.clone());
                let url = client.mailconf(&domain)?;
                printer.out(MailconfOutput {
                    url: url.to_string(),
                })
            }
        }
    }
}

fn parse_resolver(server: &str) -> Result<Url> {
    Ok(Url::parse(&format!("tcp://{server}"))?)
}

#[derive(serde::Serialize)]
struct DnsMxOutput {
    records: Vec<DnsMxRecordOutput>,
}

#[derive(serde::Serialize)]
struct DnsMxRecordOutput {
    preference: u16,
    exchange: String,
}

impl fmt::Display for DnsMxOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![Cell::new("PREFERENCE"), Cell::new("EXCHANGE")]);

        for record in &self.records {
            table.add_row(vec![
                Cell::new(record.preference),
                Cell::new(&record.exchange),
            ]);
        }

        write!(f, "{table}")
    }
}

#[derive(serde::Serialize)]
struct MailconfOutput {
    url: String,
}

impl fmt::Display for MailconfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
