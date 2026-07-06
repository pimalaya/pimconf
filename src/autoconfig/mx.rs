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

// TODO: restore when the domain new API is released:
// use domain::new::{
//     base::{
//         HeaderFlags, MessageItem, QClass, QType, Question, Record,
//         build::{MessageBuildError, MessageBuilder},
//         name::{NameBuf, NameCompressor, NameParseError, RevNameBuf},
//         parse::MessageParser,
//         wire::{AsBytes, U16},
//     },
//     rdata::{Mx, RecordData},
// };
use domain::{
    base::{
        Message, MessageBuilder, Record, Rtype,
        message_builder::PushError,
        name::{FlattenInto, FromStrError, Name},
    },
    rdata::Mx,
};
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    shared::dns::{DnsExchange, DnsExchangeError},
};

// TODO: restore when the domain new API is released, together with
// the fixed-size query buffer it bounds:
//
// const QUERY_BUF_SIZE: usize = 4 * 1024;

/// Owned DNS MX answer record returned by [`DiscoveryDnsMx`].
// TODO: point back to the domain new API record type (RevNameBuf,
// NameBuf) when released.
pub type MxRecord = Record<Name<Vec<u8>>, Mx<Name<Vec<u8>>>>;

/// Errors that can occur during a single DNS MX exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsMxError {
    // TODO: restore when the domain new API is released:
    // InvalidDomain(#[source] NameParseError, String),
    // QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS MX domain `{1}` is not a valid name")]
    InvalidDomain(#[source] FromStrError, String),
    #[error("DNS MX query could not be built")]
    QueryTooLarge(#[source] PushError),
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
                // TODO: restore when the domain new API is released:
                //
                // let qname = match self.domain.parse::<RevNameBuf>() { ... };
                //
                // let mut buf = [0u8; QUERY_BUF_SIZE];
                // let mut compressor = NameCompressor::default();
                // let mut builder = MessageBuilder::new(
                //     &mut buf,
                //     &mut compressor,
                //     U16::new(1),
                //     *HeaderFlags::default().set_rd(true),
                // );
                //
                // let q = Question {
                //     qname,
                //     qtype: QType::MX,
                //     qclass: QClass::IN,
                // };
                //
                // if let Err(err) = builder.push_question(&q) { ... }
                let qname = match self.domain.parse::<Name<Vec<u8>>>() {
                    Ok(qname) => qname,
                    Err(err) => {
                        let domain = mem::take(&mut self.domain);
                        return DiscoveryCoroutineState::Complete(Err(
                            DiscoveryDnsMxError::InvalidDomain(err, domain),
                        ));
                    }
                };

                let mut builder = MessageBuilder::new_vec();
                builder.header_mut().set_id(1);
                builder.header_mut().set_rd(true);

                let mut question = builder.question();

                if let Err(err) = question.push((&qname, Rtype::MX)) {
                    return DiscoveryCoroutineState::Complete(Err(
                        DiscoveryDnsMxError::QueryTooLarge(err),
                    ));
                }

                let message = question.into_message();
                let exchange = DnsExchange::new(message.as_slice().to_vec(), self.resolver.clone());

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
                    // TODO: restore when the domain new API is
                    // released:
                    //
                    // let parser = match MessageParser::new(&response) { ... };
                    //
                    // let mut records: Vec<Record<RevNameBuf, Mx<NameBuf>>> = Vec::new();
                    //
                    // for item in parser {
                    //     let Ok(MessageItem::Answer(record)) = item else {
                    //         continue;
                    //     };
                    //
                    //     let RecordData::Mx(mx) = record.rdata else {
                    //         continue;
                    //     };
                    //
                    //     records.push(Record {
                    //         rname: record.rname,
                    //         rtype: record.rtype,
                    //         rclass: record.rclass,
                    //         ttl: record.ttl,
                    //         rdata: mx,
                    //     });
                    // }
                    //
                    // records.sort_by(|a, b| a.rdata.cmp(&b.rdata));
                    let message = match Message::from_octets(&response) {
                        Ok(message) => message,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsMxError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let answer = match message.answer() {
                        Ok(answer) => answer,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsMxError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let mut records: Vec<MxRecord> = Vec::new();

                    for record in answer.limit_to::<Mx<_>>() {
                        let Ok(record) = record else {
                            continue;
                        };

                        records.push(record.flatten_into());
                    }

                    records.sort_by(|a, b| a.data().cmp(b.data()));

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
