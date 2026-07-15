//! Runs the autoconfig DNS MX coroutine directly against a plain
//! `TcpStream` to a DNS resolver: no client wrapper, no
//! `pimalaya-stream`. The coroutine yields the resolver URL on every
//! `WantsRead` / `WantsWrite`; in this single-endpoint example we
//! ignore it and just use the one open stream.
//!
//! ```sh
//! DOMAIN=posteo.net DNS=1.1.1.1:53 \
//!   cargo run --example autoconfig-mx --features autoconfig
//! ```

use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
};

use io_pim_discovery::{
    autoconfig::mx::DiscoveryDnsMx,
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
};
use url::Url;

fn main() {
    env_logger::init();

    let domain = env::var("DOMAIN").expect("DOMAIN env var");
    let dns = env::var("DNS").unwrap_or_else(|_| String::from("1.1.1.1:53"));
    let resolver = Url::parse(&format!("tcp://{dns}")).expect("DNS must be `host:port`");

    let mut stream = TcpStream::connect(&dns).unwrap();
    let mut coroutine = DiscoveryDnsMx::new(&domain, resolver);
    let mut buf = [0u8; 4096];
    let mut arg: Option<&[u8]> = None;

    let records = loop {
        match coroutine.resume(arg.take()) {
            DiscoveryCoroutineState::Complete(Ok(records)) => break records,
            DiscoveryCoroutineState::Complete(Err(err)) => panic!("{err}"),
            DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite { bytes, .. }) => {
                stream.write_all(&bytes).unwrap();
            }
            DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead { .. }) => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
        }
    };

    for record in records {
        println!(
            "{} {}",
            record.rdata.preference.get(),
            record.rdata.exchange
        );
    }
}
