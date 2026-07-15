//! # Shared DNS module
//!
//! [`DnsExchange`] carries one DNS message to the resolver and back,
//! picking the transport from the resolver URL scheme: RFC 1035
//! §4.2.2 length-prefixed framing over a `tcp://host:port` resolver,
//! or an RFC 8484 DNS-over-HTTPS POST against an
//! `https://…/dns-query` resolver (the wire format that always works,
//! e.g. on mobile networks that block outbound DNS).
//!
//! [`DiscoveryDnsTxt`] builds one DNS TXT question on top of it and
//! parses the response into TXT answer records in the order the
//! resolver delivered them (RFC 1035 imposes no priority for TXT).
//!
//! Each yielded [`DiscoveryYield::WantsRead`] /
//! [`DiscoveryYield::WantsWrite`] carries the `resolver` URL so the
//! runtime can route the bytes to the correct stream.

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
use io_http::{
    coroutine::{HttpCoroutine, HttpCoroutineState},
    rfc9110::{request::HttpRequest, send::HttpSendYield},
    rfc9112::send::{Http11Send, Http11SendError},
};
use thiserror::Error;
use url::Url;

use crate::coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield};

/// Default DNS resolver (`host:port`) used by every CLI subcommand
/// when `--server` is not given.
#[cfg(feature = "cli")]
pub(crate) const DNS_SERVER: &str = "1.1.1.1:53";

/// Turns a CLI `--server` value into a resolver URL: values carrying
/// a scheme pass through (e.g. an RFC 8484 `https://…/dns-query`
/// resolver), bare `host:port` values become `tcp://host:port`.
#[cfg(feature = "cli")]
pub(crate) fn resolver_url(server: &str) -> Result<Url, url::ParseError> {
    use alloc::format;

    if server.contains("://") {
        server.parse()
    } else {
        format!("tcp://{server}").parse()
    }
}

/// Maximum query buffer (in bytes) every DNS coroutine reserves
/// for building the outgoing message.
pub(crate) const DNS_QUERY_BUF_SIZE: usize = 4 * 1024;

/// Errors that can occur during a single DNS message exchange.
#[derive(Debug, Error)]
pub enum DnsExchangeError {
    #[error("DNS stream reached EOF before a full response")]
    Eof,
    #[error("DNS-over-HTTPS exchange failed")]
    Http(#[source] Http11SendError),
    #[error("DNS-over-HTTPS resolver answered HTTP {0}")]
    HttpStatus(u16),
}

/// I/O-free coroutine carrying one bare DNS message to the resolver
/// and back. A `tcp://host:port` resolver speaks RFC 1035 §4.2.2
/// length-prefixed framing (added and stripped here); an `http(s)://`
/// resolver speaks RFC 8484 DNS-over-HTTPS (one POST of the message
/// as `application/dns-message`). Completes with the bare response
/// message bytes.
#[derive(Debug)]
pub struct DnsExchange {
    resolver: Url,
    state: ExchangeState,
}

#[derive(Debug, Default)]
enum ExchangeState {
    /// TCP transport: the framed query still has to be written.
    TcpWrite(Vec<u8>),
    /// TCP transport: buffering response bytes until the 2-byte length
    /// prefix and full body are present.
    TcpRead(Vec<u8>),
    /// DNS-over-HTTPS transport: one POST exchange.
    Http(Http11Send),
    /// `Complete` has already been returned.
    #[default]
    Done,
}

impl DnsExchange {
    /// Builds an exchange of the bare DNS query `message` (no TCP
    /// length prefix) against `resolver`.
    pub fn new(message: Vec<u8>, resolver: Url) -> Self {
        let state = match resolver.scheme() {
            "http" | "https" => {
                let request = HttpRequest {
                    method: "POST".into(),
                    url: resolver.clone(),
                    headers: Vec::new(),
                    body: message,
                }
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message");

                ExchangeState::Http(Http11Send::new(request))
            }
            _ => {
                let mut framed = Vec::with_capacity(2 + message.len());
                framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
                framed.extend_from_slice(&message);

                ExchangeState::TcpWrite(framed)
            }
        };

        Self { resolver, state }
    }
}

impl DiscoveryCoroutine for DnsExchange {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<u8>, DnsExchangeError>;

    fn resume(
        &mut self,
        mut arg: Option<&[u8]>,
    ) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            ExchangeState::TcpWrite(bytes) => {
                self.state = ExchangeState::TcpRead(Vec::new());
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                    url: self.resolver.clone(),
                    bytes,
                })
            }
            ExchangeState::TcpRead(mut response) => {
                if let Some(bytes) = arg.take() {
                    if bytes.is_empty() {
                        return DiscoveryCoroutineState::Complete(Err(DnsExchangeError::Eof));
                    }

                    response.extend_from_slice(bytes);
                }

                if response.len() >= 2 {
                    let body_len = u16::from_be_bytes([response[0], response[1]]) as usize;

                    if response.len() >= 2 + body_len {
                        let mut body = response.split_off(2);
                        body.truncate(body_len);
                        return DiscoveryCoroutineState::Complete(Ok(body));
                    }
                }

                self.state = ExchangeState::TcpRead(response);
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                    url: self.resolver.clone(),
                })
            }
            ExchangeState::Http(mut send) => match send.resume(arg) {
                HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                    self.state = ExchangeState::Http(send);
                    DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                        url: self.resolver.clone(),
                    })
                }
                HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                    self.state = ExchangeState::Http(send);
                    DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                        url: self.resolver.clone(),
                        bytes,
                    })
                }
                // NOTE: a DoH endpoint has no business redirecting a
                // POSTed query; surface the status instead of chasing.
                HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { response, .. }) => {
                    DiscoveryCoroutineState::Complete(Err(DnsExchangeError::HttpStatus(
                        *response.status,
                    )))
                }
                HttpCoroutineState::Complete(Ok(out)) => {
                    if !out.response.status.is_success() {
                        return DiscoveryCoroutineState::Complete(Err(
                            DnsExchangeError::HttpStatus(*out.response.status),
                        ));
                    }

                    DiscoveryCoroutineState::Complete(Ok(out.response.body))
                }
                HttpCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DnsExchangeError::Http(err)))
                }
            },
            ExchangeState::Done => panic!("DnsExchange::resume called after completion"),
        }
    }
}

/// Owned DNS TXT answer record returned by [`DiscoveryDnsTxt`].
pub type TxtRecord = Record<RevNameBuf, Box<Txt>>;

/// Errors that can occur during a single DNS TXT exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsTxtError {
    #[error("DNS TXT domain `{1}` is not a valid name")]
    InvalidDomain(#[source] NameParseError, String),
    #[error("DNS TXT query did not fit in the {DNS_QUERY_BUF_SIZE}-byte buffer")]
    QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS TXT response could not be parsed")]
    InvalidResponse(String),
    #[error("DNS TXT stream reached EOF before a full response")]
    Eof,
    #[error("DNS TXT exchange failed")]
    Exchange(#[source] DnsExchangeError),
}

/// Internal state of the [`DiscoveryDnsTxt`] coroutine.
#[derive(Debug, Default)]
enum State {
    /// First step: the coroutine still has to build the query message.
    BuildQuery,
    /// The query is travelling to the resolver and back.
    Exchange(DnsExchange),
    /// `Complete` has already been returned.
    #[default]
    Done,
}

/// I/O-free coroutine that exchanges one DNS TXT query/response pair
/// with the resolver.
#[derive(Debug)]
pub struct DiscoveryDnsTxt {
    domain: String,
    resolver: Url,
    state: State,
}

impl DiscoveryDnsTxt {
    /// Returns a coroutine ready to build and emit a DNS TXT query
    /// for `domain` on the first [`resume`]. `resolver` is a
    /// `tcp://host:port` DNS-over-TCP resolver or an RFC 8484
    /// `https://…/dns-query` one; it is yielded back on every
    /// `WantsRead` / `WantsWrite` so the runtime can route the bytes
    /// to the correct stream.
    ///
    /// [`resume`]: DiscoveryDnsTxt::resume
    pub fn new(domain: impl ToString, resolver: Url) -> Self {
        Self {
            domain: domain.to_string(),
            resolver,
            state: State::BuildQuery,
        }
    }
}

impl DiscoveryCoroutine for DiscoveryDnsTxt {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<TxtRecord>, DiscoveryDnsTxtError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
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
                    &mut buf,
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

                let message = builder.finish().as_bytes().to_vec();
                let exchange = DnsExchange::new(message, self.resolver.clone());

                self.state = State::Exchange(exchange);
                self.resume(None)
            }

            State::Exchange(mut exchange) => match exchange.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Exchange(exchange);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(DnsExchangeError::Eof)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsTxtError::Eof))
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsTxtError::Exchange(err)))
                }
                DiscoveryCoroutineState::Complete(Ok(response)) => {
                    let parser = match MessageParser::new(&response) {
                        Ok(parser) => parser,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsTxtError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let mut records: Vec<TxtRecord> = Vec::new();

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

                    DiscoveryCoroutineState::Complete(Ok(records))
                }
            },

            State::Done => {
                panic!("DiscoveryDnsTxt::resume called after completion")
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

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::*;

    fn resume_write(exchange: &mut DnsExchange) -> Vec<u8> {
        match exchange.resume(None) {
            DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite { bytes, .. }) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    #[test]
    fn tcp_resolver_frames_with_length_prefix() {
        let resolver = "tcp://1.1.1.1:53".parse().unwrap();
        let mut exchange = DnsExchange::new(vec![0xAB; 5], resolver);

        let bytes = resume_write(&mut exchange);
        assert_eq!(bytes[..2], [0, 5]);
        assert_eq!(bytes[2..], [0xAB; 5]);
    }

    #[test]
    fn tcp_response_prefix_is_stripped() {
        let resolver = "tcp://1.1.1.1:53".parse().unwrap();
        let mut exchange = DnsExchange::new(vec![0xAB; 5], resolver);

        resume_write(&mut exchange);
        let reply = [&[0u8, 3][..], &[1, 2, 3][..]].concat();
        match exchange.resume(Some(&reply)) {
            DiscoveryCoroutineState::Complete(Ok(body)) => assert_eq!(body, vec![1, 2, 3]),
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn https_resolver_posts_rfc8484_message() {
        let resolver = "https://cloudflare-dns.com/dns-query".parse().unwrap();
        let mut exchange = DnsExchange::new(vec![0xAB; 5], resolver);

        let bytes = resume_write(&mut exchange);
        let request = String::from_utf8_lossy(&bytes);
        assert!(
            request.starts_with("POST /dns-query HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request.contains("Content-Type: application/dns-message"),
            "{request}"
        );
        assert!(request.contains("content-length: 5"), "{request}");
    }
}
