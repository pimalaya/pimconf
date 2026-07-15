//! # DNS MX query coroutine
//!
//! [`DiscoveryDnsMx`] sends one DNS MX question through the shared
//! [`DnsExchange`] transport (DNS-over-TCP or RFC 8484
//! DNS-over-HTTPS, picked from the resolver URL scheme) and parses
//! the response into MX answer records sorted by ascending preference
//! (best first, per RFC 5321 §5.1).
//!
//! Each yielded [`DiscoveryYield::WantsRead`] /
//! [`DiscoveryYield::WantsWrite`] carries the `resolver` URL so the
//! runtime can route bytes to the correct stream.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use domain::new::{
    base::{
        HeaderFlags, MessageItem, QClass, QType, Question, Record,
        build::{MessageBuildError, MessageBuilder},
        name::{NameBuf, NameCompressor, NameParseError, RevNameBuf},
        parse::MessageParser,
        wire::{AsBytes, U16},
    },
    rdata::{Mx, RecordData},
};
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::dns::{DNS_QUERY_BUF_SIZE, DnsExchange, DnsExchangeError},
};

/// Owned DNS MX answer record returned by [`DiscoveryDnsMx`].
pub type MxRecord = Record<RevNameBuf, Mx<NameBuf>>;

/// Errors that can occur during a single DNS MX exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsMxError {
    #[error("DNS MX domain `{1}` is not a valid name")]
    InvalidDomain(#[source] NameParseError, String),
    #[error("DNS MX query did not fit in the {DNS_QUERY_BUF_SIZE}-byte buffer")]
    QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS MX response could not be parsed")]
    InvalidResponse(String),
    #[error("DNS MX stream reached EOF before a full response")]
    Eof,
    #[error("DNS MX exchange failed")]
    Exchange(#[source] DnsExchangeError),
}

/// Internal state of the [`DiscoveryDnsMx`] coroutine.
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

/// I/O-free coroutine that exchanges one DNS MX query/response pair
/// with the resolver.
#[derive(Debug)]
pub struct DiscoveryDnsMx {
    domain: String,
    resolver: Url,
    state: State,
}

impl DiscoveryDnsMx {
    /// Returns a coroutine ready to build and emit a DNS MX query for
    /// `domain` on the first [`resume`]. `resolver` is a
    /// `tcp://host:port` DNS-over-TCP resolver or an RFC 8484
    /// `https://…/dns-query` one.
    ///
    /// [`resume`]: DiscoveryDnsMx::resume
    pub fn new(domain: impl ToString, resolver: Url) -> Self {
        Self {
            domain: domain.to_string(),
            resolver,
            state: State::BuildQuery,
        }
    }
}

impl DiscoveryCoroutine for DiscoveryDnsMx {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<MxRecord>, DiscoveryDnsMxError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::BuildQuery => {
                let qname = match self.domain.parse::<RevNameBuf>() {
                    Ok(qname) => qname,
                    Err(err) => {
                        let domain = mem::take(&mut self.domain);
                        return DiscoveryCoroutineState::Complete(Err(
                            DiscoveryDnsMxError::InvalidDomain(err, domain),
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
                    qtype: QType::MX,
                    qclass: QClass::IN,
                };

                if let Err(err) = builder.push_question(&q) {
                    return DiscoveryCoroutineState::Complete(Err(
                        DiscoveryDnsMxError::QueryTooLarge(err),
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
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsMxError::Eof))
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsMxError::Exchange(err)))
                }
                DiscoveryCoroutineState::Complete(Ok(response)) => {
                    let parser = match MessageParser::new(&response) {
                        Ok(parser) => parser,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsMxError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let mut records: Vec<MxRecord> = Vec::new();

                    for item in parser {
                        let Ok(MessageItem::Answer(record)) = item else {
                            continue;
                        };

                        let RecordData::Mx(mx) = record.rdata else {
                            continue;
                        };

                        records.push(Record {
                            rname: record.rname,
                            rtype: record.rtype,
                            rclass: record.rclass,
                            ttl: record.ttl,
                            rdata: mx,
                        });
                    }

                    records.sort_by(|a, b| a.rdata.cmp(&b.rdata));

                    DiscoveryCoroutineState::Complete(Ok(records))
                }
            },

            State::Done => {
                panic!("DiscoveryDnsMx::resume called after completion")
            }
        }
    }
}

/// Strips the leftmost label of an MX target so that ISP autoconfig
/// URLs can be retried against the registrable parent
/// (`mx.example.com` → `example.com`). Returns `None` for inputs with
/// fewer than two dots after trailing-dot trimming.
pub fn mx_parent_domain(target: &str) -> Option<String> {
    let target = target.trim_end_matches('.');

    let mut first_dot = None;

    for (i, b) in target.bytes().enumerate() {
        if b != b'.' {
            continue;
        }

        if let Some(start) = first_dot {
            return Some(target[start + 1..].to_string());
        }

        first_dot = Some(i);
    }

    None
}
