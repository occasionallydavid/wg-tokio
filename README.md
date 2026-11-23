# wg-tokio

A small `tokio::net`-style TCP API over [BoringTun](https://github.com/cloudflare/boringtun)
and [smoltcp](https://github.com/smoltcp-rs/smoltcp).

The purpose of this is to give some middleground that is:

* Compatible - can connect to an endpoint with a standard Wireguard and TCP/IP client
* Compact - does not pull in megabytes of code to get secure communication
* Simplistic - manage a bunch of public keys rather than PKI certs (like Quic)
* Relatively efficient - HTTP over Wireguard is more round-trip heavy than
  Quic, but trades ideal networking for much smaller dependencies. For example
  there is no need to link Rustls or OpenSSL
* Easy to use - lives entirely in userspace
* Extensible - can be swapped out for a real Wireguard+HTTP setup with no
  protocol changes, or extended to act like a real networking gateway, or
  include multiple services over one connection
* Defensible - involves no new custom protocols or cryptography, just solid
  implementations of existing ones fused together

A `Context` owns one UDP socket, one WireGuard identity, one smoltcp TCP/IP
stack, and any number of WireGuard peers. A single `TcpListener` accepts
connections from all peers. Streams implement tokio's `AsyncRead` and
`AsyncWrite`, so they can be used by hyper or another async socket consumer.

## Client

```rust,no_run
use wg_tokio::{AllowedIp, Context, ContextConfig, PublicKey, StaticSecret};

# async fn example(private: StaticSecret, public: PublicKey) -> std::io::Result<()> {
let context = Context::new(
    ContextConfig::new(
        private,
        "10.7.0.2".parse().unwrap(),
        "0.0.0.0:51820".parse().unwrap(),
    )
    .with_peer(public, "198.51.100.10:51820".parse().unwrap())
    .with_peer_verifier(move |key| async move {
        (key == public).then(|| vec!["10.7.0.1/32".parse::<AllowedIp>().unwrap()])
    }),
)
.await?;

let mut socket = context.connect(("10.7.0.1", 8080)).await?;
assert_eq!(socket.peer_public_key(), public);
context.finalise().await?;
# Ok(())
# }
```

## Server

The verifier identifies new WireGuard peers from BoringTun's anonymous
handshake parser. It can perform async work and returns `Some(allowed_cidrs)` to
admit the peer or `None` to reject it.

```rust,no_run
# use wg_tokio::{AllowedIp, Context, ContextConfig, PublicKey, StaticSecret};
# async fn example(private: StaticSecret, client_public: PublicKey) -> std::io::Result<()> {
let context = Context::new(
    ContextConfig::new(
        private,
        "10.7.0.1".parse().unwrap(),
        "0.0.0.0:51820".parse().unwrap(),
    )
    .with_peer_verifier(move |key| async move {
        if key == client_public {
            Some(vec!["10.7.0.2/32".parse::<AllowedIp>().unwrap()])
        } else {
            None
        }
    }),
)
.await?;

let listener = context.listen(("10.7.0.1", 8080)).await?;
# let _ = listener;
# Ok(())
# }
```

Authorized address ranges must not overlap between peers. The listener can
accept concurrent connections from peers with distinct tunnel addresses while
sharing one smoltcp TCP/IP stack.

## Lifecycle

Call `Context::finalise().await` to close and drain all sockets before dropping
a context. The server example uses
`with_peer_idle_timeout(Duration::from_secs(5))`; inactive peers are forgotten
without stopping the listener or Context. Dropping an unfinalised context
panics.

## Crypto backend

The default `crypto-rust` feature uses the smaller pure-Rust
`nordisk-boringtun` backend:

```text
cargo build
```

To use Cloudflare BoringTun with `ring` instead:

```text
cargo build --no-default-features --features crypto-ring
```

The two crypto features are mutually exclusive. `crypto-rust` uses a
third-party pure-Rust fork with the same public API and wire format.

## Examples

Run in separate terminals:

```text
cargo run --example server
cargo run --example client
```

Set `WG_PORT` on both commands to use a UDP port other than `51820`.

The examples use fixed keys and loopback UDP addresses. Fixed keys are for
demonstration only; generate and protect real WireGuard keys in applications.
