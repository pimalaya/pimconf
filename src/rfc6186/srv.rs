//! # DNS SRV query coroutine
//!
//! [`DiscoveryDnsSrv`] sends one DNS SRV question through the shared
//! [`DnsExchange`] transport (DNS-over-TCP or RFC 8484
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
//     rdata::{RecordData, Srv},
// };
use domain::{
    base::{
        Message, MessageBuilder, Record, Rtype,
        message_builder::PushError,
        name::{FlattenInto, FromStrError, Name},
    },
    rdata::Srv,
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
//
// /// SRV is not exposed by `domain::new::base::QType`, so we build it
// /// from its IANA-assigned code (RFC 2782).
// const QTYPE_SRV: QType = QType { code: U16::new(33) };

/// Owned DNS SRV answer record returned by [`DiscoveryDnsSrv`].
// TODO: point back to the domain new API record type (RevNameBuf,
// NameBuf) when released.
pub type SrvRecord = Record<Name<Vec<u8>>, Srv<Name<Vec<u8>>>>;

/// Errors that can occur during a single DNS SRV exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsSrvError {
    // TODO: restore when the domain new API is released:
    // InvalidQname(#[source] NameParseError, String),
    // QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS SRV qname `{1}` is not a valid name")]
    InvalidQname(#[source] FromStrError, String),
    #[error("DNS SRV query could not be built")]
    QueryTooLarge(#[source] PushError),
    #[error("DNS SRV response could not be parsed")]
    InvalidResponse(String),
    #[error("DNS SRV stream reached EOF before a full response")]
    Eof,
    #[error("DNS SRV exchange failed")]
    Exchange(#[source] DnsExchangeError),
}

/// Internal state of the [`DiscoveryDnsSrv`] coroutine.
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
                // TODO: restore when the domain new API is released:
                //
                // let qname = match self.qname.parse::<RevNameBuf>() { ... };
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
                //     qtype: QTYPE_SRV,
                //     qclass: QClass::IN,
                // };
                //
                // if let Err(err) = builder.push_question(&q) { ... }
                let qname = match self.qname.parse::<Name<Vec<u8>>>() {
                    Ok(qname) => qname,
                    Err(err) => {
                        let raw = mem::take(&mut self.qname);
                        return DiscoveryCoroutineState::Complete(Err(
                            DiscoveryDnsSrvError::InvalidQname(err, raw),
                        ));
                    }
                };

                let mut builder = MessageBuilder::new_vec();
                builder.header_mut().set_id(1);
                builder.header_mut().set_rd(true);

                let mut question = builder.question();

                if let Err(err) = question.push((&qname, Rtype::SRV)) {
                    return DiscoveryCoroutineState::Complete(Err(
                        DiscoveryDnsSrvError::QueryTooLarge(err),
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
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsSrvError::Eof))
                }
                DiscoveryCoroutineState::Complete(Err(err)) => {
                    DiscoveryCoroutineState::Complete(Err(DiscoveryDnsSrvError::Exchange(err)))
                }
                DiscoveryCoroutineState::Complete(Ok(response)) => {
                    // TODO: restore when the domain new API is
                    // released:
                    //
                    // let parser = match MessageParser::new(&response) { ... };
                    //
                    // let mut records: Vec<Record<RevNameBuf, Srv<NameBuf>>> = Vec::new();
                    //
                    // for item in parser {
                    //     let Ok(MessageItem::Answer(record)) = item else {
                    //         continue;
                    //     };
                    //
                    //     let RecordData::Srv(srv) = record.rdata else {
                    //         continue;
                    //     };
                    //
                    //     if srv.target.is_root() {
                    //         continue;
                    //     }
                    //
                    //     records.push(Record {
                    //         rname: record.rname,
                    //         rtype: record.rtype,
                    //         rclass: record.rclass,
                    //         ttl: record.ttl,
                    //         rdata: srv,
                    //     });
                    // }
                    //
                    // records.sort_by(|a, b| {
                    //     a.rdata
                    //         .priority
                    //         .cmp(&b.rdata.priority)
                    //         .then_with(|| b.rdata.weight.cmp(&a.rdata.weight))
                    // });
                    let message = match Message::from_octets(&response) {
                        Ok(message) => message,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsSrvError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let answer = match message.answer() {
                        Ok(answer) => answer,
                        Err(err) => {
                            return DiscoveryCoroutineState::Complete(Err(
                                DiscoveryDnsSrvError::InvalidResponse(err.to_string()),
                            ));
                        }
                    };

                    let mut records: Vec<SrvRecord> = Vec::new();

                    for record in answer.limit_to::<Srv<_>>() {
                        let Ok(record) = record else {
                            continue;
                        };

                        if record.data().target().is_root() {
                            continue;
                        }

                        records.push(record.flatten_into());
                    }

                    records.sort_by(|a, b| {
                        a.data()
                            .priority()
                            .cmp(&b.data().priority())
                            .then_with(|| b.data().weight().cmp(&a.data().weight()))
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
