# wg-tokio

A small, point-to-point `tokio::net`-style TCP API over
[BoringTun](https://github.com/cloudflare/boringtun) and
[smoltcp](https://github.com/smoltcp-rs/smoltcp).

Each [`Context`](src/lib.rs) uses one local private key and one remote public
key. Its TCP streams and listener implement tokio's `AsyncRead`/`AsyncWrite`
traits, so they can be handed to hyper or another async socket consumer.

```rust,no_run
use wg_tokio::{Context, ContextConfig};

# async fn example(private: wg_tokio::StaticSecret, public: wg_tokio::PublicKey) -> std::io::Result<()> {
let context = Context::new(ContextConfig::new(
    private,
    public,
    "10.7.0.2".parse().unwrap(),
    "10.7.0.1".parse().unwrap(),
    "0.0.0.0:51820".parse().unwrap(),
).with_peer_addr("198.51.100.10:51820".parse().unwrap())).await?;

let mut socket = context.connect(("10.7.0.1", 8080)).await?;
assert_eq!(socket.peer_public_key(), public);
context.finalise().await?;
# Ok(())
# }
```

Clients normally set `with_peer_addr(...)`. A server can omit it and learns the
peer's UDP endpoint from the first valid WireGuard packet.

Call `Context::finalise().await` to close and drain all sockets before dropping
a client context. The server example sets
`with_peer_idle_timeout(Duration::from_secs(5))`; after five seconds without
authenticated traffic it forgets the peer endpoint and closes that peer's active
streams while its listener and context remain alive. Dropping an unfinalised
context panics.

An async peer verifier can authorize either side of a context before it is
created:

```rust,no_run
# use wg_tokio::{ContextConfig, PeerVerifierFuture, PublicKey, StaticSecret};
# fn example(private: StaticSecret, public: PublicKey) {
# fn verifier(_: wg_tokio::PublicKey) -> PeerVerifierFuture {
#     Box::pin(async { true })
# }
let config = ContextConfig::new(
    private,
    public,
    "10.7.0.2".parse().unwrap(),
    "10.7.0.1".parse().unwrap(),
    "0.0.0.0:51820".parse().unwrap(),
)
.with_peer_verifier(verifier);
# }
```

Run the examples in separate terminals:

```text
cargo run --example server
cargo run --example client
```

Set `WG_PORT` on both commands to use a UDP port other than `51820`.

The examples use fixed keys and loopback UDP addresses so they can be run
directly. Fixed keys are for demonstration only; generate and protect real
WireGuard keys in actual applications.
