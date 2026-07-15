# io-pim-discovery [![Documentation](https://img.shields.io/docsrs/io-pim-discovery?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-pim-discovery/latest/io_pim_discovery) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

PIM discovery CLI and client library for Rust

This project is composed of 3 feature-gated layers:

- Low-level **I/O-free** coroutines: no_std state machines containing the whole discovery logic, usable anywhere
- Mid-level **clients**, based on coroutines (standard, blocking)
- High-level **CLI**, based on the std clients

## Table of contents

- [Features](#features)
- [Coverage](#coverage)
- [Installation](#installation)
- [Usage](#usage)
- [FAQ](#faq)
- [AI disclosure](#ai-disclosure)
- [License](#license)
- [Social](#social)
- [Contributing](#contributing)
- [Sponsoring](#sponsoring)

## Features

- **Email discovery**: find a domain's incoming and outgoing mail servers through Mozilla autoconfig, the Thunderbird ISPDB, DNS SRV records, DNS TXT redirects and PACC well-known configuration.
- **Calendar and contacts discovery**: locate a domain's CalDAV and CardDAV home through DNS SRV, DNS TXT context lookups and well-known probes.
- **JMAP discovery**: resolve a domain to its JMAP session URL through DNS SRV and the well-known session probe.
- **Authentication discovery**: probe a URL's authentication schemes and fetch a provider's OAuth 2.0 authorization-server and protected-resource metadata to learn where and how to obtain tokens.
- **Unified compose**: from a single email address, chain the known-provider rules and every enabled mechanism into one ranked list of service configurations, either collecting all of them or stopping at the first match.
- **DNS over HTTPS**: every DNS lookup accepts an `https` resolver so discovery works on networks that block plain DNS.
- **JSON output**: machine-readable results from the CLI with a single flag.
- **TLS** support:
  - [Rustls](https://crates.io/crates/rustls) with ring crypto (requires `rustls-ring` feature, enabled by default)
  - [Rustls](https://crates.io/crates/rustls) with aws crypto (requires `rustls-aws` feature)
  - [Native TLS](https://crates.io/crates/native-tls) (requires `native-tls` feature)

> [!TIP]
> io-pim-discovery is written in [Rust](https://www.rust-lang.org/) and uses [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) to gate each mechanism. The default feature set is declared in [Cargo.toml](./Cargo.toml) or on [docs.rs](https://docs.rs/crate/io-pim-discovery/latest/features).

## Coverage

| Spec | What is covered |
|------|-----------------|
| [Autoconfig] | Mozilla Thunderbird autoconfiguration: ISP main and well-known lookups, ISPDB, DNS MX retry and DNS TXT `mailconf` redirect (requires `autoconfig`) |
| [PACC] | Provider-authenticated client configuration: well-known JSON fetch with SHA-256 digest verification against the `_ua-auto-config` TXT record (requires `pacc`) |
| [6186] | DNS SRV mail discovery: `_imap`, `_imaps`, `_submission` assembled into one report (requires `rfc6186`) |
| [6764] | CalDAV and CardDAV discovery: DNS SRV, DNS TXT context and well-known probe, chained into a context-root resolve (requires `rfc6764`) |
| [8484] | DNS over HTTPS: every lookup accepts an `https://…/dns-query` resolver next to plain `tcp://host:port` |
| [8620] | JMAP autodiscovery: DNS SRV origin lookup and well-known session probe, chained into a session-URL resolve (requires `rfc8620`) |
| [8414] | OAuth 2.0 authorization server metadata: resolve an issuer into its authorization, token and registration endpoints (requires `rfc8414`) |
| [9728] | OAuth 2.0 protected resource metadata: resolve a resource into the authorization servers that can issue tokens for it (requires `rfc9728`) |

[Autoconfig]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration
[PACC]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02
[6186]: https://datatracker.ietf.org/doc/html/rfc6186
[6764]: https://datatracker.ietf.org/doc/html/rfc6764
[8484]: https://datatracker.ietf.org/doc/html/rfc8484
[8620]: https://datatracker.ietf.org/doc/html/rfc8620
[8414]: https://datatracker.ietf.org/doc/html/rfc8414
[9728]: https://datatracker.ietf.org/doc/html/rfc9728

## Installation

The CLI binary `pim-discovery` has not been officially released yet. Pre-built binaries from the `master` branch are attached to the [releases](https://github.com/pimalaya/io-pim-discovery/actions/workflows/releases.yml) workflow, under its *Artifacts* section, built with the default features plus `cli`.

Install from [crates.io](https://crates.io/crates/io-pim-discovery) with cargo:

```sh
cargo install io-pim-discovery --locked --features cli
```

Or with [Nix](https://nixos.wiki/wiki/Flakes):

```sh
nix profile install github:pimalaya/io-pim-discovery
```

To use io-pim-discovery as a library, add it to your `Cargo.toml` and pick the mechanisms you need; the API is documented on [docs.rs](https://docs.rs/io-pim-discovery/latest/io_pim_discovery).

## Usage

The CLI is organised by PIM domain (`email`, `calendar`, `contact`, `file`), plus `all` and `auth`; each mechanism is exposed independently and the source column tells the rows apart. A few real-world invocations:

```sh
pim-discovery all user@fastmail.com
pim-discovery email first user@fastmail.com
pim-discovery calendar dav fastmail.com
pim-discovery auth server https://api.fastmail.com
pim-discovery --json all user@fastmail.com
```

Run `pim-discovery --help` for the full command tree, flags and TLS options. The library API, including every coroutine and client, is documented on [docs.rs](https://docs.rs/io-pim-discovery/latest/io_pim_discovery).

## FAQ

<details>
  <summary>How to debug the CLI?</summary>

  Use `--log <level>` where `<level>` is one of `off`, `error`, `warn`, `info`, `debug`, `trace`. The `RUST_LOG` environment variable, when set, overrides `--log` and supports per-target filters (see the [env_logger](https://docs.rs/env_logger/latest/env_logger/#enabling-logging) documentation), and `RUST_BACKTRACE=1` enables full error backtraces. Logs are written to stderr, so they can be redirected to a file.
</details>

## AI disclosure

This project is developed with AI assistance. This section documents how, so users and downstream packagers can make informed decisions.

- **Tools**: Claude Code (Anthropic), invoked locally with a persistent project-scoped memory and a small set of repo-specific rules.
- **Used for**: Refactors, mechanical multi-file edits, boilerplate (feature gates, error enums, derive macros, trait impls), test scaffolding, doc polish, exploratory design conversations.
- **Not used for**: Engineering, critical code, git manipulation (commit, merge, rebase…), real-world tests.
- **Verification**: Every AI-assisted change is read, compiled, tested, and formatted before commit. Behavioural correctness is verified against the relevant RFC or upstream spec, not assumed from the model output. Tests are never adjusted to fit AI-generated code; the code is adjusted to fit correct behaviour.
- **Limitations**: AI models occasionally produce code that compiles and passes tests but is subtly wrong. The verification workflow catches most of this; it does not catch all of it. Bug reports are welcome and taken seriously.
- **Last reviewed**: 15/07/2026

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Social

- Chat on [Matrix](https://matrix.to/#/#pimalaya:matrix.org)
- News on [Mastodon](https://fosstodon.org/@pimalaya) or [RSS](https://fosstodon.org/@pimalaya.rss)
- Mail at [pimalaya.org@posteo.net](mailto:pimalaya.org@posteo.net)

## Contributing

Contributions are welcome: start with [CONTRIBUTING.md](./CONTRIBUTING.md), which opens with the Pimalaya-wide guides to read first.

## Sponsoring

[![nlnet](https://nlnet.nl/logo/banner-160x60.png)](https://nlnet.nl/)

Special thanks to the [NLnet foundation](https://nlnet.nl/) and the [European Commission](https://www.ngi.eu/) that have been financially supporting the project for years:

- 2022 → 2023: [NGI Assure](https://nlnet.nl/project/Himalaya/)
- 2023 → 2024: [NGI Zero Entrust](https://nlnet.nl/project/Pimalaya/)
- 2024 → 2026: [NGI Zero Core](https://nlnet.nl/project/Pimalaya-PIM/)
- *2027 in preparation…*

If you appreciate the project, feel free to donate using one of the following providers:

[![GitHub](https://img.shields.io/badge/-GitHub%20Sponsors-fafbfc?logo=GitHub%20Sponsors)](https://github.com/sponsors/soywod)
[![Ko-fi](https://img.shields.io/badge/-Ko--fi-ff5e5a?logo=Ko-fi&logoColor=ffffff)](https://ko-fi.com/soywod)
[![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-ffdd00?logo=Buy%20Me%20A%20Coffee&logoColor=000000)](https://www.buymeacoffee.com/soywod)
[![Liberapay](https://img.shields.io/badge/-Liberapay-f6c915?logo=Liberapay&logoColor=222222)](https://liberapay.com/soywod)
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0Ni0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODktMi43NzQuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
