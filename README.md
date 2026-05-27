# I/O Discovery [![Documentation](https://img.shields.io/docsrs/io-discovery?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-discovery/latest/io_discovery) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

Client library and CLI to discover PIM-related services, written in Rust.

This repository ships three things:

- Low-level **I/O-free** coroutines (no_std state machines that emit read/write requests)
- Mid-level clients, based on coroutines (standard, blocking)
- High-level CLI, based on std clients

## Table of contents

- [Features](#features)
- [Installation](#installation)
  - [Pre-built binary](#pre-built-binary)
  - [Cargo](#cargo)
  - [Nix](#nix)
  - [Sources](#sources)
- [Usage](#usage)
  - [Library](#library)
  - [CLI](#cli)
- [FAQ](#faq)
- [License](#license)
- [Social](#social)
- [Sponsoring](#sponsoring)

## Features

- **Mozilla Thunderbird Autoconfiguration** support <sup>[wiki](https://wiki.mozilla.org/Thunderbird:Autoconfiguration)</sup> (requires `autoconfig` feature):
  - ISP main and `/.well-known/` URL lookups
  - Thunderbird ISPDB lookup
  - DNS MX-based retry against the MX target's parent domain
  - DNS TXT `mailconf=<URL>` redirect
- **RFC 6186 SRV** discovery support (requires `rfc6186` feature):
  - `_imap._tcp`, `_imaps._tcp`, `_submission._tcp` assembly into a single report
- **PACC** discovery support <sup>[draft-ietf-mailmaint-pacc-02](https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02)</sup> (requires `pacc` feature):
  - Well-known JSON configuration fetch
  - SHA-256 digest verification against the `_ua-auto-config` TXT record
- **TLS** support:
  - [Rustls](https://crates.io/crates/rustls) with ring crypto (requires `rustls-ring` feature)
  - [Rustls](https://crates.io/crates/rustls) with aws crypto (requires `rustls-aws` feature)
  - [Native TLS](https://crates.io/crates/native-tls) (requires `native-tls` feature)
- **JSON** output via `--json`

> [!TIP]
> io-discovery is written in [Rust](https://www.rust-lang.org/) and uses [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) to gate functionality. The default feature set is declared in [Cargo.toml](./Cargo.toml).

## Installation

### Pre-built binary

The CLI binary `discover` has not been officially released yet. Check the [releases](https://github.com/pimalaya/io-discovery/actions/workflows/releases.yml) GitHub workflow and look for the *Artifacts* section. These pre-built binaries are built from the `master` branch.

> [!NOTE]
> Pre-built binaries are built with the default cargo features, plus `cli`. If you need more features, please use another installation method.

### Cargo

```sh
cargo install io-discovery --locked
```

You can also use the git repository for a more up-to-date (but less stable) version:

```sh
cargo install --locked --git https://github.com/pimalaya/io-discovery.git
```

To use io-discovery as a library, add it to your Cargo.toml:

```toml
[dependencies]
io-discovery = { version = "0.0.1", default-features = false, features = ["autoconfig", "pacc", "rfc6186", "client"] }
```

The `client` feature pulls in the `std`-blocking helpers. Drop it (and pick any combination of `autoconfig` / `pacc` / `rfc6186`) for a `no_std`-friendly, pure-coroutine build.

### Nix

If you have the [Flakes](https://nixos.wiki/wiki/Flakes) feature enabled:

```sh
nix profile install github:pimalaya/io-discovery
```

Or run without installing:

```sh
nix run github:pimalaya/io-discovery -- autoconfig <local-part> <domain>
```

### Sources

```sh
git clone https://github.com/pimalaya/io-discovery
cd io-discovery
nix run
```

## Usage

### Library

Using a low-level DNS MX I/O-free coroutine:

```rust,ignore
use std::{io::{Read, Write}, net::TcpStream};
use io_discovery::autoconfig::mx::{DiscoveryDnsMx, DiscoveryDnsMxResult};
use url::Url;

let resolver = Url::parse("tcp://1.1.1.1:53").unwrap();
let mut stream = TcpStream::connect("1.1.1.1:53").unwrap();
let mut coroutine = DiscoveryDnsMx::new("fastmail.com", resolver);
let mut buf = [0u8; 4096];
let mut arg: Option<&[u8]> = None;

let records = loop {
    match coroutine.resume(arg.take()) {
        DiscoveryDnsMxResult::Ok(records) => break records,
        DiscoveryDnsMxResult::WantsWrite { bytes, .. } => {
            stream.write_all(&bytes).unwrap();
        }
        DiscoveryDnsMxResult::WantsRead { .. } => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        DiscoveryDnsMxResult::Err(err) => panic!("{err}"),
    }
};

for record in records {
    println!("- {} {}", record.rdata.preference.get(), record.rdata.exchange);
}
```

Using a mid-level std PACC client:

```rust,ignore
use io_discovery::pacc::client::DiscoveryPaccClientStd;
use pimalaya_stream::tls::Tls;
use url::Url;

let dns = Url::parse("tcp://1.1.1.1:53").unwrap();
let mut client = DiscoveryPaccClientStd::new(dns).with_tls(Tls::default());

let config = client.discover("fastmail.com").unwrap();
println!("{config:#?}");
```

### CLI

Run the full Thunderbird Autoconfiguration chain on `<local_part> <domain>`:

```sh
discover autoconfig user fastmail.com
```

The chain tries, in order: every ISP main URL (secure then plain), every `/.well-known/` URL (secure then plain), the Thunderbird ISPDB, then re-tries the same against the MX target's parent domain, then logs the `mailconf=<URL>` TXT redirect if one is published.

Run a single primitive instead:

```sh
discover autoconfig user fastmail.com isp --secure
discover autoconfig user fastmail.com isp-fallback --secure
discover autoconfig user fastmail.com ispdb --secure
discover autoconfig user fastmail.com mx
discover autoconfig user fastmail.com mailconf
```

Run RFC 6186 SRV discovery (top-level subcommand):

```sh
discover srv fastmail.com
```

Run PACC discovery:

```sh
discover pacc fastmail.com
```

JSON output:

```sh
discover --json autoconfig user fastmail.com
```

Pick a specific TLS stack and crypto provider:

```sh
discover --tls rustls --rustls-crypto ring autoconfig user fastmail.com
discover --tls native-tls pacc fastmail.com
discover --tls-cert /path/to/extra-root.pem autoconfig user fastmail.com
```

## FAQ

<details>
  <summary>How to debug the CLI?</summary>

  Use `--log <level>` where `<level>` is one of `off`, `error`, `warn`, `info`, `debug`, `trace`:

  ```sh
  discover --log trace autoconfig user fastmail.com
  ```

  The `RUST_LOG` environment variable, when set, overrides `--log` and supports per-target filters (see the [`env_logger` documentation](https://docs.rs/env_logger/latest/env_logger/#enabling-logging)). `RUST_BACKTRACE=1` enables full error backtraces.

  Logs are written to `stderr`, so they can be redirected easily to a file:

  ```sh
  discover --log trace autoconfig user fastmail.com 2>/tmp/discover.log
  ```
</details>

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Social

- Chat on [Matrix](https://matrix.to/#/#pimalaya:matrix.org)
- News on [Mastodon](https://fosstodon.org/@pimalaya) or [RSS](https://fosstodon.org/@pimalaya.rss)
- Mail at [pimalaya.org@posteo.net](mailto:pimalaya.org@posteo.net)

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
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0NS0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODktMi43NzQuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
