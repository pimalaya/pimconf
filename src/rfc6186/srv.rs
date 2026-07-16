//! # DNS SRV query coroutine
//!
//! [`DiscoveryDnsSrv`] sends one DNS SRV question through the shared
//! [`DiscoveryDnsExchange`] transport (DNS-over-TCP or RFC 8484
//! DNS-over-HTTPS, picked from the resolver URL scheme) and parses
//! the response into [`Srv`] records sorted per RFC 2782 (ascending
//! priority, then descending weight). Records whose target is the root
//! name (RFC 2782 §3, "service not available") are dropped.
//!
//! Each yielded [`DiscoveryYield::WantsRead`] /
//! [`DiscoveryYield::WantsWrite`] carries the `resolver` URL so the
//! runtime can route bytes to the correct stream.

use core::mem;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};

use domain::{
    new::{
        base::{
            HeaderFlags, MessageItem, QClass, QType, Question, Record,
            build::{MessageBuildError, MessageBuilder},
            name::{NameCompressor, NameParseError, RevNameBuf},
            parse::MessageParser,
            wire::{AsBytes, U16},
        },
        rdata::{RecordData, Srv},
    },
    utils::dst::UnsizedCopy,
};
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::dns::{DNS_QUERY_BUF_SIZE, DiscoveryDnsExchange, DiscoveryDnsExchangeError},
};

/// Owned DNS SRV answer record returned by [`DiscoveryDnsSrv`].
pub type SrvRecord = Record<RevNameBuf, Box<Srv>>;

/// Errors that can occur during a single DNS SRV exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsSrvError {
    /// The fully-qualified query name is not a valid DNS name.
    #[error("DNS SRV qname `{1}` is not a valid name")]
    InvalidQname(#[source] NameParseError, String),
    /// The serialised DNS query exceeded the fixed query buffer.
    #[error("DNS SRV query did not fit in the {DNS_QUERY_BUF_SIZE}-byte buffer")]
    QueryTooLarge(#[source] MessageBuildError),
    /// The DNS response message could not be parsed.
    #[error("DNS SRV response could not be parsed")]
    InvalidResponse(String),
    /// The DNS stream closed before a complete response was received.
    #[error("DNS SRV stream reached EOF before a full response")]
    Eof,
    /// The underlying DNS exchange coroutine failed.
    #[error("DNS SRV exchange failed")]
    Exchange(#[source] DiscoveryDnsExchangeError),
}

/// Internal state of the [`DiscoveryDnsSrv`] coroutine.
#[derive(Debug, Default)]
enum State {
    /// First step: the coroutine still has to build the query message.
    BuildQuery,
    /// The query is travelling to the resolver and back.
    Exchange(DiscoveryDnsExchange),
    /// `Complete` has already been returned.
    #[default]
    Done,
}

/// I/O-free coroutine that exchanges one DNS SRV query/response pair
/// with the resolver.
#[derive(Debug)]
pub struct DiscoveryDnsSrv {
    qname: String,
    resolver: Url,
    state: State,
}

impl DiscoveryDnsSrv {
    /// Returns a coroutine ready to build and emit a DNS SRV query
    /// for the fully-formed `qname` (e.g. `_imap._tcp.example.org`)
    /// on the first [`resume`]. `resolver` is a `tcp://host:port`
    /// DNS-over-TCP resolver or an RFC 8484 `https://…/dns-query` one.
    ///
    /// [`resume`]: DiscoveryDnsSrv::resume
    pub fn new(qname: impl ToString, resolver: Url) -> Self {
        Self {
            qname: qname.to_string(),
            resolver,
            state: State::BuildQuery,
        }
    }
}

impl DiscoveryCoroutine for DiscoveryDnsSrv {
    type Yield = DiscoveryYield;
    type Return = Result<Vec<SrvRecord>, DiscoveryDnsSrvError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match mem::take(&mut self.state) {
            State::BuildQuery => {
                let qname = match self.qname.parse::<RevNameBuf>() {
                    Ok(qname) => qname,
                    Err(err) => {
                        let raw = mem::take(&mut self.qname);
                        return DiscoveryCoroutineState::Complete(Err(
                            DiscoveryDnsSrvError::InvalidQname(err, raw),
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
                    qtype: QType::SRV,
                    qclass: QClass::IN,
                };

                if let Err(err) = builder.push_question(&q) {
                    return DiscoveryCoroutineState::Complete(Err(
                        DiscoveryDnsSrvError::QueryTooLarge(err),
                    ));
                }

                let message = builder.finish().as_bytes().to_vec();
                let exchange = DiscoveryDnsExchange::new(message, self.resolver.clone());

                self.state = State::Exchange(exchange);
                self.resume(None)
            }

            State::Exchange(mut exchange) => match exchange.resume(arg) {
                DiscoveryCoroutineState::Yielded(y) => {
                    self.state = State::Exchange(exchange);
                    DiscoveryCoroutineState::Yielded(y)
                }
                DiscoveryCoroutineState::Complete(Err(DiscoveryDnsExchangeError::Eof)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsSrvError::Eof))
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsSrvError::Exchange(err)))
                }
                DiscoveryCoroutineState::Complete(Ok(response)) => {
                    let parser = match MessageParser::new(&response) {
                        Ok(parser) => parser,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsSrvError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let mut records: Vec<SrvRecord> = Vec::new();

                    for item in parser {
                        let Ok(MessageItem::Answer(record)) = item else {
                            continue;
                        };

                        let RecordData::Srv(srv) = record.rdata else {
                            continue;
                        };

                        if srv.name.is_root() {
                            continue;
                        }

                        records.push(Record {
                            rname: record.rname,
                            rtype: record.rtype,
                            rclass: record.rclass,
                            ttl: record.ttl,
                            rdata: srv.unsized_copy_into(),
                        });
                    }

                    records.sort_by(|a, b| {
                        a.rdata
                            .priority
                            .cmp(&b.rdata.priority)
                            .then_with(|| b.rdata.weight.cmp(&a.rdata.weight))
                    });

                    DiscoveryCoroutineState::Complete(Ok(records))
                }
            },

            State::Done => {
                panic!("DiscoveryDnsSrv::resume called after completion")
            }
        }
    }
}
