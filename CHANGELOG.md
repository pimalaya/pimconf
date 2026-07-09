# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Replaced the serial `SearchAll`/`SearchFirst` coroutines with bricks plus orchestration: the search module now exposes the pure `ConfigCollector` (per-mechanism outputs fed in priority order, filtered against the requested services and merged) and `ServiceConfig::probe_urls` (the endpoints whose unauthenticated 401 may advertise the config's schemes), while the per-mechanism discovery coroutines stay where they were; consumers orchestrate the bricks however they want, typically in parallel on their own transports. `SearchClientStd` became that reference orchestrator: one thread per mechanism (each on its own stream pool) and one probe thread per config, constructed with `new(dns, tls)` (the `with_tls`/`with_factory` builders are gone, and the module moved behind the `stream` feature). `search_first` keeps its output shape but no longer stops early: every mechanism runs in parallel and only the highest-priority one that produced configs is kept.

### Added

- Added a per-endpoint authentication probe to the search: after the mechanisms run, every collected HTTP config (JMAP, CalDAV, CardDAV) is asked which schemes it actually accepts through its unauthenticated 401 `WWW-Authenticate` (per PACC §5.4.2 and RFC 9110 §11.6.1, probing the endpoint then the service's well-known walk), and its password and bearer methods are refined accordingly, OAuth methods untouched. Account-level configuration documents cannot express per-service schemes: fastmail's PACC claims password support account-wide, while its JMAP session endpoint only advertises `Bearer` and its CardDAV root advertises `Basic` and `Bearer`; the probe now makes each config say exactly that. The probe lives in the new `rfc9110` module (the `WWW-Authenticate` parser moved there from the RFC 8620 probe), and first mode probes its configs before completing.

- Added the `Bearer` authentication method to search configs, detected from the JMAP session probe.

  The RFC 8620 well-known probe now reads the authentication schemes the session endpoint advertises through `WWW-Authenticate` on its unauthenticated 401, and the resulting config's methods derive from them: `basic` means password login, `bearer` a bearer token such as a provider-issued API token (fastmail's JMAP API only accepts the latter; a valid token sent as Basic credentials 401s). Configs for the same service, endpoint and username now merge their authentication methods across mechanisms instead of duplicating the entry, so a PACC-advertised endpoint gains the probe-detected schemes.

- Added RFC 8484 DNS-over-HTTPS as a DNS transport.

  A new `DnsExchange` coroutine carries one bare DNS message to the resolver and back, picking the transport from the resolver URL scheme: RFC 1035 §4.2.2 length-prefixed framing over a `tcp://host:port` resolver, or one `application/dns-message` POST against an RFC 8484 `https://…/dns-query` resolver. The MX, TXT and SRV coroutines now build their query on top of it, so every discovery mechanism (autoconfig MX, PACC digest verification, RFC 6186, RFC 6764, RFC 8620 and the unified search) accepts a DoH resolver transparently; DoH rides the same HTTPS streams as the other coroutines, so it works on mobile networks that block outbound DNS over TCP. The CLI `--server` flags accept a resolver URL next to the bare `host:port` form.

- Added the `rfc8620` feature: JMAP service autodiscovery (RFC 8620 §2.2).

  The new rfc8620 module chains an SRV lookup on `_jmap._tcp.<domain>` (falling back to the domain itself when no record is published or the resolver is unreachable) and a `/.well-known/jmap` probe on the resulting origin into a `ResolveJmap` coroutine completing with the JMAP Session resource URL. The probe follows any redirect chain (capped at 5 hops; RFC 8620 locates the session resource "following any redirects", and apex domains routinely bounce through marketing hosts that serve no JMAP) and judges the terminal response: a 2xx or 401 resolves to the final URL, any other status means the origin serves no JMAP and the resolve completes with a `NotFound` error. The search chain runs it as its last mechanism, so JMAP-capable domains without a PACC document (which already advertises JMAP) still surface a `jmap` service config.

- Added the `search` feature: a unified email address to service configs search.

  The new search module chains fixed provider rules (Google and Microsoft, matched by email domain then by MX records for Google Workspace and Microsoft 365 custom domains), PACC, the Mozilla autoconfig locations (ISP main, ISP fallback, the mailconf TXT redirect, ISPDB), RFC 6186 SRV records and the RFC 6764 CalDAV/CardDAV resolve, and reduces everything to one list of `ServiceConfig` (service, endpoint, username, authentication methods: password, OAuth 2.0 authorization code grant, OAuth 2.0 device authorization grant, or an OAuth 2.0 issuer to resolve via RFC 8414 metadata). The `SearchAll` coroutine collects configs from every mechanism; `SearchFirst` completes at the first mechanism yielding one. `SearchClientStd` exposes both over a stream pool, treating per-endpoint I/O failures as EOF so a broken mechanism is skipped instead of failing the search; the `pimconf search <EMAIL> [--first] [--service <SERVICE>]` command exposes them on the CLI.

### Changed

- Switched DNS coroutines from the unreleased domain new API (git-pinned, unstable-new feature) to the stable API of the latest domain release, unblocking releases.

  DNS records are now returned as base-module `Record<Name<Vec<u8>>, …>` types instead of the new-API `Record<RevNameBuf, …>` ones, and the git patch on the domain crate is gone. The new-API code is kept commented and will be restored once it ships on crates.io.

- Changed DNS coroutines (MX, TXT, SRV) to honor the documented EOF convention: an empty resume slice now terminates them with a dedicated `Eof` error instead of yielding reads forever on a dead stream.

- Changed the RFC 6764 resolve coroutine to survive failed SRV lookups: an unreachable resolver now falls back to the `.well-known` probe on the domain itself instead of failing the whole resolve.

### Fixed

- Fixed the search duplicating one service reached under two names: HTTP endpoints now compare as normalized URLs across mechanisms (a trailing slash or an explicit default port no longer splits an entry), and an endpoint whose host is a subdomain of an already collected one merges into it as a rotated backend name, the parent host keeping the entry (fastmail's SRV records answer with dNNNNNN.carddav.fastmail.com shards under the carddav.fastmail.com its PACC document advertises, so the search listed both).

- Fixed the assumed JMAP authentication order when the session endpoint advertises no scheme on its 401: the bearer token now comes first, password second (the JMAP ecosystem is token-first; a wrongly assumed method fails visibly at the connection check while a missing one is a dead end).

- Fixed the PACC kebab-case keys being renamed on serialization only: `oauth-public` and `content-type` now also deserialize from their wire names, so a provider's public OAuth issuer (e.g. fastmail's) reaches the parsed document and the search configs instead of being silently dropped.

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

[unreleased]: https://github.com/pimalaya/pimconf/compare/v0.1.0..HEAD
[0.1.0]: https://github.com/pimalaya/pimconf/compare/root..v0.1.0
