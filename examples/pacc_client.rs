//! Drives [`DiscoveryPaccClientStd`] end-to-end. The client opens
//! HTTPS and DNS streams lazily and reuses them across the
//! coroutine; the caller only configures the resolver (and
//! optionally the TLS profile via `with_tls`).
//!
//! ```sh
//! DOMAIN=fastmail.com DNS=1.1.1.1:53 \
//!   cargo run --example pacc-client --features pacc,client
//! ```

use std::env;

use pimconf::pacc::client::DiscoveryPaccClientStd;
use url::Url;

fn main() {
    env_logger::init();

    let domain = env::var("DOMAIN").expect("DOMAIN env var");
    let dns = env::var("DNS").unwrap_or_else(|_| String::from("1.1.1.1:53"));
    let resolver = Url::parse(&format!("tcp://{dns}")).expect("DNS must be `host:port`");

    let mut client = DiscoveryPaccClientStd::new(resolver);
    let config = client.discover(&domain).unwrap();
    println!("{config:#?}");
}
