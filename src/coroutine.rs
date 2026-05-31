//! # Generator-shape coroutine driver
//!
//! Mirrors the shape of `core::ops::Coroutine`: a `Yield` associated
//! type for intermediate progress, a `Return` associated type for
//! terminal output, and a two-variant [`DiscoveryCoroutineState`]
//! (`Yielded` / `Complete`).
//!
//! Naming and structure mirror io-http's [`HttpCoroutine`] /
//! [`HttpCoroutineState`] / [`HttpYield`] triad so the two crates
//! compose without an adapter shim per call site (HTTP-side
//! coroutines, like [`crate::shared::http::HttpGet`], simply translate
//! io-http's [`HttpSendYield`] into [`DiscoveryYield`]).
//!
//! Every pimconf coroutine yields the same [`DiscoveryYield`]
//! shape: each yielded step carries the [`Url`] of the endpoint the
//! coroutine wants to talk to, so the std client driver can route the
//! bytes to the correct stream via [`crate::shared::pool::StreamPool`].
//!
//! [`HttpCoroutine`]: io_http::coroutine::HttpCoroutine
//! [`HttpCoroutineState`]: io_http::coroutine::HttpCoroutineState
//! [`HttpYield`]: io_http::coroutine::HttpYield
//! [`HttpSendYield`]: io_http::rfc9110::send::HttpSendYield

use alloc::vec::Vec;

use url::Url;

/// State yielded by a [`DiscoveryCoroutine::resume`] step.
///
/// Two-variant by design (matches std's `core::ops::CoroutineState`):
/// any further variation lives inside the per-coroutine `Yield` type.
#[derive(Debug)]
pub enum DiscoveryCoroutineState<Y, R> {
    /// Intermediate yield. The driver reacts to `Y` (do I/O, …) and
    /// resumes the coroutine again.
    Yielded(Y),
    /// Terminal yield. By convention `R = Result<Output, Error>`.
    Complete(R),
}

/// Standard-shape pimconf coroutine.
///
/// Implementors own their internal state machine and declare their
/// per-step `Yield` plus a terminal `Return`. The driver pumps I/O
/// based on the `Yield` variant and resumes until `Complete`.
pub trait DiscoveryCoroutine {
    /// Intermediate value handed back on every step. One-shot
    /// coroutines pick [`DiscoveryYield`] directly; coroutines that
    /// need extra variants (e.g. domain events) declare their own.
    type Yield;
    /// Terminal value. By convention `Result<Output, Error>`; the
    /// `Ok` arm carries the operation's final output, the `Err` arm
    /// carries the cause.
    type Return;

    /// Advances the coroutine one step.
    ///
    /// Pass [`None`] when there is no data to provide (initial call
    /// or after the previous yield was [`DiscoveryYield::WantsWrite`]).
    /// Pass `Some(data)` with bytes read from the stream after a
    /// [`DiscoveryYield::WantsRead`]. Pass `Some(&[])` to signal EOF.
    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return>;
}

/// Standard I/O Yield for pimconf coroutines.
///
/// Both variants carry the [`Url`] of the endpoint the coroutine wants
/// to talk to so the driver can route bytes to the matching stream
/// (DNS resolver, HTTPS origin, …) via
/// [`crate::shared::pool::StreamPool`]. Pick `type Yield = DiscoveryYield`
/// for any coroutine that only needs to read or write socket bytes.
#[derive(Debug)]
pub enum DiscoveryYield {
    /// Driver should read more bytes from the stream open on `url`
    /// and feed them back on the next resume.
    WantsRead { url: Url },
    /// Driver should write `bytes` to the stream open on `url`; the
    /// next resume typically takes `None`.
    WantsWrite { url: Url, bytes: Vec<u8> },
}
