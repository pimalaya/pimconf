# Contributing guide

Thank you for investing your time in contributing to io-pim-discovery.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/lib.rs (or src/main.rs): it is the architecture document of this crate;
4. the docs/ folder for the development history and living plans.

Everything below documents only what differs from the Pimalaya standards.

## Library and binary

io-pim-discovery is both a library and a CLI: the coroutines and clients are the library, and the `cli` feature adds the `pim-discovery` binary on top. The library targets no_std; the binary is std, as usual.

## Feature matrix

Every mechanism sits behind its own feature; the `cli` feature turns on the ones the binary exposes:

```sh
cargo build --no-default-features --features autoconfig     # one mechanism, pure coroutines
cargo build --no-default-features --features rfc6764,client # a mechanism plus the light client
cargo build --features cli                                  # the full CLI binary
cargo build --all-features                                  # everything
```

## Vendored domain patch

The `domain` DNS crate is pinned to a git revision through `[patch.crates-io]` until its new API is released on crates.io; do not drop that patch. The same section path-patches `pimalaya-cli` until its 0.1 release.
