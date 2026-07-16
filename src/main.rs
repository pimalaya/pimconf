//! # pim-discovery
//!
//! Command-line front-end to the io-pim-discovery library: given an
//! email address or a domain, it runs the enabled discovery mechanisms
//! and prints where a user's mail, calendar, contacts and files live and
//! how to authenticate.
//!
//! Commands are grouped by PIM domain (email, calendar, contact, file),
//! next to the top-level `all` and `auth` commands; the command structs
//! live in the library's cli module, this binary only wires them to the
//! clap parser, the logger and the printer.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use io_pim_discovery::cli::{
    domain::{CalendarCommand, ContactCommand, EmailCommand, FileCommand},
    misc::{AllCommand, AuthCommand},
};
use pimalaya_cli::{
    clap::{
        args::{JsonFlag, LogFlags},
        commands::{CompletionCommand, ManualCommand},
    },
    error::ErrorReport,
    log::Logger,
    long_version,
    printer::{Printer, StdoutPrinter},
};
use pimalaya_stream::tls::{Rustls, RustlsCrypto, Tls, TlsProvider};

fn main() {
    let cli = Cli::parse();

    Logger::try_init(&cli.log).expect("init logger");
    let mut printer = StdoutPrinter::new(&cli.json);
    let tls = cli.tls.into();

    let result = cli.command.execute(&mut printer, &tls);
    ErrorReport::eval(&mut printer, result)
}

#[derive(Parser, Debug)]
#[command(name = env!("CARGO_BIN_NAME"))]
#[command(about = "CLI to discover PIM-related services")]
#[command(author, version, long_version = long_version!())]
#[command(propagate_version = true, infer_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[command(flatten)]
    pub tls: TlsFlags,
    #[command(flatten)]
    pub log: LogFlags,
    #[command(flatten)]
    pub json: JsonFlag,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover every service for an email address, grouped by domain.
    All(AllCommand),
    /// Discover email services (IMAP, POP3, SMTP, JMAP).
    #[command(subcommand)]
    Email(EmailCommand),
    /// Discover calendar services (CalDAV, JMAP).
    #[command(subcommand)]
    Calendar(CalendarCommand),
    /// Discover contact services (CardDAV, JMAP).
    #[command(subcommand)]
    Contact(ContactCommand),
    /// Discover file-storage services (WebDAV).
    #[command(subcommand)]
    File(FileCommand),
    /// Probe an endpoint for the authentication methods it advertises.
    #[command(subcommand)]
    Auth(AuthCommand),
    Completions(CompletionCommand),
    Manuals(ManualCommand),
}

impl Command {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        match self {
            Self::All(cmd) => cmd.execute(printer, tls),
            Self::Email(cmd) => cmd.execute(printer, tls),
            Self::Calendar(cmd) => cmd.execute(printer, tls),
            Self::Contact(cmd) => cmd.execute(printer, tls),
            Self::File(cmd) => cmd.execute(printer, tls),
            Self::Auth(cmd) => cmd.execute(printer, tls),
            Self::Completions(cmd) => cmd.execute(printer, Cli::command()),
            Self::Manuals(cmd) => cmd.execute(printer, Cli::command()),
        }
    }
}

#[derive(Args, Debug)]
struct TlsFlags {
    /// TLS provider implementation used for HTTPS connections.
    #[arg(long, global = true)]
    #[arg(value_enum, value_name = "PROVIDER")]
    pub tls: Option<TlsProviderArg>,
    /// Additional TLS root certificate (PEM file).
    #[arg(long, global = true, value_name = "PATH")]
    pub tls_cert: Option<PathBuf>,
    /// Rustls crypto provider.
    #[arg(long, global = true)]
    #[arg(value_enum, value_name = "PROVIDER")]
    pub rustls_crypto: Option<RustlsCryptoArg>,
}

impl From<TlsFlags> for Tls {
    fn from(flags: TlsFlags) -> Self {
        Self {
            provider: flags.tls.map(Into::into),
            rustls: Rustls {
                crypto: flags.rustls_crypto.map(Into::into),
                alpn: vec!["http/1.1".into()],
            },
            cert: flags.tls_cert,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum TlsProviderArg {
    Rustls,
    NativeTls,
}

impl From<TlsProviderArg> for TlsProvider {
    fn from(arg: TlsProviderArg) -> Self {
        match arg {
            TlsProviderArg::Rustls => Self::Rustls,
            TlsProviderArg::NativeTls => Self::NativeTls,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum RustlsCryptoArg {
    Aws,
    Ring,
}

impl From<RustlsCryptoArg> for RustlsCrypto {
    fn from(arg: RustlsCryptoArg) -> Self {
        match arg {
            RustlsCryptoArg::Aws => Self::Aws,
            RustlsCryptoArg::Ring => Self::Ring,
        }
    }
}
