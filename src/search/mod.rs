//! Unified email address to service configs search.
//!
//! The module exposes bricks, not a fixed pipeline: the per-mechanism
//! discovery coroutines live in their own modules (autoconfig, pacc,
//! rfc6186, rfc6764, rfc8620), the fixed provider rules in
//! [`providers`], and the pure reduction of mechanism outputs into
//! one deduplicated config list in [`collect`]. Consumers orchestrate
//! the bricks however they want (typically in parallel, each on its
//! own transport); [`client`] is the std-blocking reference
//! orchestrator backing the CLI.

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "stream")]
pub mod client;
pub mod collect;
pub mod providers;
pub mod types;
