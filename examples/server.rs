use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wg_tokio::{Context, ContextConfig, PublicKey, StaticSecret};

const SERVER_PRIVATE: [u8; 32] = [2; 32];
const CLIENT_PRIVATE: [u8; 32] = [1; 32];
const BODY_LEN: usize = 1024;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let local_ip = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1));
    let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2));
    let udp_port = std::env::var("WG_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(51820);
    let client_public = PublicKey::from(&StaticSecret::from(CLIENT_PRIVATE));
    let allowed_client = client_public;
    let config = ContextConfig::new(
        StaticSecret::from(SERVER_PRIVATE),
        client_public,
        local_ip,
        peer_ip,
        SocketAddr::from(([127, 0, 0, 1], udp_port)),
    )
    .with_peer_verifier(move |key| async move {
        // Replace this with any async database or policy lookup.
        tokio::task::yield_now().await;
        key == allowed_client
    })
    .with_peer_idle_timeout(Duration::from_secs(5));

    let context = Context::new(config).await?;
    let listener = context.listen((local_ip, 8080)).await?;
    println!("listening on http://{local_ip}:8080 over WireGuard");

    loop {
        let (mut stream, remote) = listener.accept().await?;
        println!("accepted {remote}");
        tokio::spawn(async move {
            let mut request = Vec::new();
            match stream.read_to_end(&mut request).await {
                Ok(n) if n > 0 => {
                    println!("request: {n} bytes");
                    let body = [b'S'; BODY_LEN];
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {BODY_LEN}\r\nconnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                }
                Ok(_) => {}
                Err(err) => eprintln!("read error: {err}"),
            }
        });
    }
}
