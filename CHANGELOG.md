# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Corrected the Microsoft IMAP/POP/SMTP OAuth scopes to use the `https://outlook.office.com/` resource instead of `https://outlook.office365.com/`. The latter is the server host, not a valid scope resource, so Microsoft's authorize endpoint rejected it with `invalid_scope` ("The provided resource value for the input parameter 'scope' is not valid"). The server hosts (`outlook.office365.com`, `smtp.office365.com`) are unchanged.

## [0.3.2] - 2026-07-16

### Fixed

- Restored all DNS-based discovery (RFC 6186/6764/8620 SRV lookups, MX provider detection and the PACC DNS-TXT digest verification), broken since 0.3.0 by the move to the `domain` 0.12.2 `unstable-new` API. Its `RevNameBuf` parser rejects relative names, but every query name was built without a trailing dot, so each lookup failed with `NameParseError::Relative` and its mechanism was silently skipped. Query names are now made absolute before parsing. This notably restores OAuth issuer discovery for providers that advertise it only through PACC, such as Fastmail.

## [0.3.1] - 2026-07-16

### Fixed

- Release builds in CI.

## [0.3.0] - 2026-07-16

### Changed

- Renamed every public coroutine, client, error and data type to carry the strict `Discovery` prefix, aligning with the Pimalaya naming guidelines.

  For example `ComposeClientStd` became `DiscoveryComposeClientStd`; `ResolveDav`, `ResolveJmap`, `ResolveOauthServer` and `ResolveOauthResource` became `DiscoveryDavResolve`, `DiscoveryJmapResolve`, `DiscoveryOauthServerResolve` and `DiscoveryOauthResourceResolve`; `WellKnown` became `DiscoveryWellKnown`; `ProbeAuth` became `DiscoveryProbeAuth`; `ConfigCollector` became `DiscoveryConfigCollector`; and the shared data types `Service`, `ServiceConfig`, `AuthMethod`, `DavService`, `OauthServerMetadata` and `OauthResourceMetadata` gained the same prefix. The wire-format schema types were prefixed too: the autoconfig XML structs (`DiscoveryAutoconfig`, `DiscoveryEmailProvider`, `DiscoveryServer`, `DiscoveryServerType`, `DiscoverySecurityType`, `DiscoveryAuthenticationType`, …), the PACC JSON structs (`DiscoveryPaccConfig`, `DiscoveryProtocols`, `DiscoveryAuthentication`, `DiscoveryProvider`, …), and `DiscoverySrvReport`, `DiscoverySrvService`, `DiscoveryWebdavSrvReport` and `DiscoveryJmapSessionResource`. The compose config model was prefixed as well (`Endpoint`, `Security`, `ConfigSource` became `DiscoveryEndpoint`, `DiscoverySecurity`, `DiscoveryConfigSource`), the stream-pool trait `Stream` became `DiscoveryStream`, and the known-provider enum `Provider` became `DiscoveryKnownProvider` (kept distinct from the PACC `DiscoveryProvider`). Only the CLI command types keep their unprefixed names.

- Moved each mechanism's data types out of a `types` catch-all module into a named public module, path-visible with no re-export: the autoconfig, PACC and composed-config schemas now live in `autoconfig::config`, `pacc::config` and `compose::config`, and the SRV and DAV service types in `rfc6186::service` and `rfc6764::service` (so e.g. `autoconfig::types::EmailProvider` is now `autoconfig::config::EmailProvider`).

- Switched the DNS coroutines to the `domain` 0.12.2 `unstable-new` SRV API. The owned answer aliases are now `TxtRecord` and `SrvRecord` (`Record<RevNameBuf, Box<Txt>>` / `Record<RevNameBuf, Box<Srv>>`) and `MxRecord` (`Record<RevNameBuf, Mx<NameBuf>>`), all with public fields instead of accessor methods; the git patch that pinned the unreleased revision is gone.

- Bumped io-http to 0.3, pimalaya-stream to 0.1 and pimalaya-cli to 0.1.

- Documented every public item and aligned the crate with the Pimalaya documentation guidelines: the src/lib.rs architecture header replaced the README include, the README dropped its inline code, and docs.rs now builds with all features.

### Fixed

- Boxed the oversized HTTP coroutines held by the DNS-over-HTTPS and JMAP well-known state machines, clearing the `clippy::large_enum_variant` warnings.

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

[unreleased]: https://github.com/pimalaya/io-pim-discovery/compare/v0.3.1..HEAD
[0.3.1]: https://github.com/pimalaya/io-pim-discovery/compare/v0.3.0..v0.3.1
[0.3.0]: https://github.com/pimalaya/io-pim-discovery/compare/v0.2.0..v0.3.0
[0.2.0]: https://github.com/pimalaya/io-pim-discovery/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-pim-discovery/compare/root..v0.1.0
