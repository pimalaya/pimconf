use std::{fmt, string::String};

use anyhow::Result;
use clap::Args;
use pimalaya_cli::{
    printer::Printer,
    table::{Cell, ContentArrangement, Table, presets::UTF8_FULL},
};

use crate::{
    rfc6764::{client::DiscoveryWebdavClientStd, types::WebdavSrvReport},
    shared::dns::{DNS_SERVER, resolver_url},
};

/// RFC 6764 §3 DNS SRV lookup for CalDAV/CardDAV services.
///
/// Looks up `_caldav._tcp.<domain>`, `_caldavs._tcp.<domain>`,
/// `_carddav._tcp.<domain>` and `_carddavs._tcp.<domain>` over
/// DNS-over-TCP and reports the best record per service. The TXT,
/// `.well-known` and resolve mechanisms are library-only.
#[derive(Debug, Args)]
pub struct WebdavCommand {
    /// Domain to look up SRV records for.
    pub domain: String,
    /// DNS resolver: `host:port`, or an RFC 8484 resolver URL such
    /// as `https://cloudflare-dns.com/dns-query`.
    #[arg(long, default_value = DNS_SERVER)]
    pub dns_server: String,
}

impl WebdavCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        let resolver = resolver_url(&self.dns_server)?;
        let mut client = DiscoveryWebdavClientStd::new(resolver);
        let report = client.discover(&self.domain)?;
        printer.out(WebdavSrvReportOutput(report))
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct WebdavSrvReportOutput(WebdavSrvReport);

impl fmt::Display for WebdavSrvReportOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("SERVICE"),
                Cell::new("HOST"),
                Cell::new("PORT"),
                Cell::new("PRIORITY"),
                Cell::new("WEIGHT"),
            ]);

        let r = &self.0;
        for (name, service) in [
            ("caldav", &r.caldav),
            ("caldavs", &r.caldavs),
            ("carddav", &r.carddav),
            ("carddavs", &r.carddavs),
        ] {
            match service {
                Some(s) => table.add_row(vec![
                    Cell::new(name),
                    Cell::new(&s.host),
                    Cell::new(s.port),
                    Cell::new(s.priority),
                    Cell::new(s.weight),
                ]),
                None => table.add_row(vec![
                    Cell::new(name),
                    Cell::new("-"),
                    Cell::new("-"),
                    Cell::new("-"),
                    Cell::new("-"),
                ]),
            };
        }

        write!(f, "{table}")
    }
}
