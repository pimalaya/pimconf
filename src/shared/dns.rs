//! # Shared DNS module
//!
//! [`DiscoveryDnsTxt`] sends one DNS TXT question over TCP and parses
//! the response into TXT answer records in the order the resolver
//! delivered them (RFC 1035 imposes no priority for TXT).
//!
//! TCP framing (RFC 1035 §4.2.2: 2-byte big-endian length prefix) is
//! handled inside the coroutine. Each yielded
//! [`DiscoveryYield::WantsRead`] / [`DiscoveryYield::WantsWrite`]
//! carries the `resolver` URL so the runtime can route the bytes to
//! the correct DNS-over-TCP stream.

use core::mem;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "client")]
use std::net::IpAddr;

use domain::{
    new::{
        base::{
            HeaderFlags, MessageItem, QClass, QType, Question, Record,
            build::{MessageBuildError, MessageBuilder},
            name::{NameCompressor, NameParseError, RevNameBuf},
            parse::MessageParser,
            wire::{AsBytes, U16},
        },
        rdata::{RecordData, Txt},
    },
    utils::dst::UnsizedCopy,
};
use thiserror::Error;
use url::Url;

use crate::coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield};

/// Default DNS resolver (`host:port`) used by every CLI subcommand
/// when `--server` is not given.
#[cfg(feature = "cli")]
pub(crate) const DNS_SERVER: &str = "1.1.1.1:53";

/// Maximum query buffer (in bytes) every DNS coroutine reserves for
/// building the outgoing message, including the 2-byte TCP length
/// prefix (RFC 1035 §4.2.2).
pub(crate) const DNS_QUERY_BUF_SIZE: usize = 4 * 1024;

/// Errors that can occur during a single DNS TXT exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsTxtError {
    #[error("DNS TXT domain `{1}` is not a valid name")]
    InvalidDomain(#[source] NameParseError, String),
    #[error("DNS TXT query did not fit in the {DNS_QUERY_BUF_SIZE}-byte buffer")]
    QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS TXT response could not be parsed")]
    InvalidResponse(String),
}

/// Internal state of the [`DiscoveryDnsTxt`] coroutine.
#[derive(Debug, Default)]
enum State {
    /// First step: the coroutine still has to build the query message.
    BuildQuery,
    /// The query has been emitted; the coroutine is buffering response
    /// bytes until the 2-byte length prefix and full body are present.
    ParseResponse,
    /// `Complete` has already been returned.
    #[default]
    Done,
}

/// I/O-free coroutine that exchanges one DNS TXT query/response pair
/// over TCP.
#[derive(Debug)]
pub struct DiscoveryDnsTxt {
    domain: String,
    resolver: Url,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    response: Vec<u8>,
}

impl DiscoveryDnsTxt {
    /// Returns a coroutine ready to build and emit a DNS TXT query
    /// for `domain` on the first [`resume`]. `resolver` must be a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver; it
    /// is yielded back on every `WantsRead` / `WantsWrite` so the
    /// runtime can route the bytes to the correct stream.
    ///
    /// [`resume`]: DiscoveryDnsTxt::resume
    pub fn new(domain: impl ToString, resolver: Url) -> Self {
        Self {
            domain: domain.to_string(),
            resolver,
            state: State::BuildQuery,
            wants_read: false,
            wants_write: None,
            response: Vec::new(),
        }
    }
}

impl DiscoveryCoroutine for DiscoveryDnsTxt {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<Record<RevNameBuf, Box<Txt>>>, DiscoveryDnsTxtError>;

    fn resume(
        &mut self,
        mut arg: Option<&[u8]>,
    ) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                    url: self.resolver.clone(),
                    bytes,
                });
            }

            if mem::take(&mut self.wants_read) {
                return DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                    url: self.resolver.clone(),
                });
            }

            match mem::take(&mut self.state) {
                State::BuildQuery => {
                    let qname = match self.domain.parse::<RevNameBuf>() {
                        Ok(qname) => qname,
                        Err(err) => {
                            let domain = mem::take(&mut self.domain);
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsTxtError::InvalidDomain(err, domain),
                            ));
                        }
                    };

                    let mut buf = vec![0u8; DNS_QUERY_BUF_SIZE];
                    let mut compressor = NameCompressor::default();
                    let mut builder = MessageBuilder::new(
                        &mut buf[2..],
                        &mut compressor,
                        U16::new(1),
                        *HeaderFlags::default().set_rd(true),
                    );

                    let q = Question {
                        qname,
                        qtype: QType::TXT,
                        qclass: QClass::IN,
                    };

                    if let Err(err) = builder.push_question(&q) {
                        return DiscoveryCoroutineState::Complete(Err(
                            DiscoveryDnsTxtError::QueryTooLarge(err),
                        ));
                    }

                    let msg_len = builder.finish().as_bytes().len();
                    buf[0..2].copy_from_slice(&(msg_len as u16).to_be_bytes());
                    buf.truncate(msg_len + 2);

                    self.wants_write = Some(buf);
                    self.wants_read = true;
                    self.state = State::ParseResponse;
                }

                State::ParseResponse => {
                    if let Some(bytes) = arg.take() {
                        self.response.extend_from_slice(bytes);
                    }

                    if self.response.len() < 2 {
                        self.wants_read = true;
                        self.state = State::ParseResponse;
                        continue;
                    }

                    let body_len =
                        u16::from_be_bytes([self.response[0], self.response[1]]) as usize;

                    if self.response.len() < 2 + body_len {
                        self.wants_read = true;
                        self.state = State::ParseResponse;
                        continue;
                    }

                    let parser = match MessageParser::new(&self.response[2..2 + body_len]) {
                        Ok(parser) => parser,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsTxtError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let mut records: Vec<Record<RevNameBuf, Box<Txt>>> = Vec::new();

                    for item in parser {
                        let Ok(MessageItem::Answer(record)) = item else {
                            continue;
                        };

                        let RecordData::Txt(txt) = record.rdata else {
                            continue;
                        };

                        records.push(Record {
                            rname: record.rname,
                            rtype: record.rtype,
                            rclass: record.rclass,
                            ttl: record.ttl,
                            rdata: txt.unsized_copy_into(),
                        });
                    }

                    return DiscoveryCoroutineState::Complete(Ok(records));
                }

                State::Done => {
                    panic!("DiscoveryDnsTxt::resume called after completion")
                }
            }
        }
    }
}

/// Best-effort system DNS resolver as a `tcp://<ip>:53` URL, read from
/// `/etc/resolv.conf` on unix and from the network adapters on windows.
/// Returns `None` when no nameserver can be determined; callers fall
/// back to a default resolver.
#[cfg(feature = "client")]
pub fn system_resolver() -> Option<Url> {
    use alloc::format;

    let host = match system_nameserver()? {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };

    format!("tcp://{host}:53").parse().ok()
}

/// First nameserver listed in `/etc/resolv.conf`.
#[cfg(all(feature = "client", unix))]
fn system_nameserver() -> Option<IpAddr> {
    use std::fs;

    use resolv_conf::{Config, ScopedIp};

    let raw = fs::read_to_string("/etc/resolv.conf").ok()?;
    let config = Config::parse(&raw).ok()?;

    config
        .nameservers
        .into_iter()
        .next()
        .map(|scoped| match scoped {
            ScopedIp::V4(ip) => IpAddr::V4(ip),
            ScopedIp::V6(ip, _) => IpAddr::V6(ip),
        })
}

/// First DNS server reported by the system network adapters.
#[cfg(all(feature = "client", windows))]
fn system_nameserver() -> Option<IpAddr> {
    let adapters = ipconfig::get_adapters().ok()?;

    adapters
        .iter()
        .flat_map(|adapter| adapter.dns_servers())
        .copied()
        .next()
}
