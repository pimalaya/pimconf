# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Switched the DNS coroutines back to the `domain` new API, pinned to the git commit that added the SRV record type (`QType::SRV` and the unsized `Srv` record data). The owned answer aliases changed accordingly: `TxtRecord` and `SrvRecord` are `Record<RevNameBuf, Box<Txt>>` / `Record<RevNameBuf, Box<Srv>>`, `MxRecord` is `Record<RevNameBuf, Mx<NameBuf>>`, all with public fields instead of accessor methods.

## [0.2.0] - 2026-07-13

### Added

- Added the unified `compose` orchestrator (`ComposeClientStd`): one email or domain into a `ServiceConfig` list, chaining provider rules, PACC, autoconfig, RFC 6186 SRV, RFC 6764 DAV and RFC 8620 JMAP; `compose_all` merges across mechanisms, `compose_first` keeps the highest-priority hit, `compose_raw` returns them unmerged.
- Added RFC 8620 JMAP autodiscovery (`rfc8620` feature): `ResolveJmap` chains a `_jmap._tcp` SRV lookup and a `/.well-known/jmap` probe, following redirects and judging the terminal 2xx/401.
- Added RFC 8484 DNS-over-HTTPS: `DnsExchange` picks `tcp://` length-framing or an `https://…/dns-query` POST from the resolver URL, so every DNS mechanism accepts a DoH resolver; the CLI `--server` flags take a URL too.
- Added a per-endpoint authentication probe (`rfc9110` module, `ProbeAuth`): reads `WWW-Authenticate` on an unauthenticated 401 to refine each config's `password`/`bearer` methods (OAuth methods untouched).
- Added the `Bearer` authentication method, detected from the JMAP session probe.
- Added the OAuth 2.0 metadata modules `rfc8414` (authorization server) and `rfc9728` (protected resource), moved from io-oauth: the `ResolveOauthServer` / `ResolveOauthResource` coroutines, `ComposeClientStd::oauth_server` / `oauth_resource`, and the CLI `auth server` / `auth resource` commands.
- Added automatic OAuth issuer resolution: `compose` fetches a discovered `OauthIssuer`'s RFC 8414 metadata and upgrades it to a concrete `OauthAuthorizationCodeGrant` (plus device grant when advertised).

### Changed

- Renamed the crate from `pimconf` to `io-pim-discovery` (library path `io_pim_discovery`); the CLI binary is `pim-discovery`.
- Gated the CLI behind a non-default `cli` feature.
- Made `compose` plain library code instead of a feature: it lives behind `stream` plus at least one discovery mechanism, and composes whichever mechanisms are enabled, skipping the rest.
- Organised the CLI by PIM domain (`all`, `email` / `calendar` / `contact` / `file`, `auth`) instead of by mechanism, dropping RFC-numbered command names; provider detection is `email is-google` / `email is-microsoft`, and mechanisms are shown independently (the CLI never merges). The old flat `autoconfig` / `pacc` / `srv` / `webdav` / `search` commands are gone.
- Replaced the serial `SearchAll` / `SearchFirst` coroutines with bricks (the pure `ConfigCollector` plus the per-mechanism coroutines) orchestrated by `ComposeClientStd`, one thread per mechanism and one probe per config.
- Switched the DNS coroutines from the unreleased `domain` new API to the stable release, dropping the git patch and unblocking releases.
- Made the DNS coroutines honor the EOF convention: an empty resume slice ends them with an `Eof` error instead of yielding reads forever on a dead stream.
- Made the RFC 6764 resolve fall back to the `.well-known` probe when the SRV lookup fails.

### Fixed

- Deduplicated a service reached under two names: HTTP endpoints compare as normalized URLs, and a subdomain host merges into its parent (fastmail's rotated CardDAV shards).
- Fixed the assumed JMAP authentication order when the endpoint advertises no scheme: bearer first, password second.
- Fixed the PACC `oauth-public` / `content-type` keys not deserializing from their wire names, which silently dropped a provider's OAuth issuer.

## [0.1.0] - 2026-06-06

### Added

- Added Thunderbird Autoconfig support (requires `autoconfig` feature).

- Added [PACC] support (requires `pacc` feature).

  [PACC]: https://www.ietf.org/archive/id/draft-ietf-mailmaint-pacc-02.html

- Added [RFC 6186] SRV-based mail service discovery (requires `rfc6186` feature).

  [RFC 6186]: https://datatracker.ietf.org/doc/html/rfc6186

- Added [RFC 6764] SRV-based CalDAV/CardDAV discovery (requires `rfc6764` feature).

  [RFC 6764]: https://datatracker.ietf.org/doc/html/rfc6764

- Added CLI (requires `cli` feature).

[unreleased]: https://github.com/pimalaya/io-pim-discovery/compare/v0.2.0..HEAD
[0.2.0]: https://github.com/pimalaya/io-pim-discovery/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-pim-discovery/compare/root..v0.1.0
