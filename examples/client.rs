use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wg_tokio::{Context, ContextConfig, PublicKey, StaticSecret};

const CLIENT_PRIVATE: [u8; 32] = [1; 32];
const SERVER_PRIVATE: [u8; 32] = [2; 32];
const BODY_LEN: usize = 1024;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let local_ip = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2));
    let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1));
    let udp_port = std::env::var("WG_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(51820);
    let server_udp = SocketAddr::from(([127, 0, 0, 1], udp_port));
    let server_public = PublicKey::from(&StaticSecret::from(SERVER_PRIVATE));
    let config = ContextConfig::new(
        StaticSecret::from(CLIENT_PRIVATE),
        server_public,
        local_ip,
        peer_ip,
        SocketAddr::from(([127, 0, 0, 1], 0)),
    )
    .with_peer_addr(server_udp);

    let context = Context::new(config).await?;
    let exchange = run_exchange(&context, peer_ip).await;
    let finalise = context.finalise().await;
    let response = exchange?;
    finalise?;

    let response = String::from_utf8_lossy(&response);
    let headers = response.split("\r\n\r\n").next().unwrap_or_default();
    println!("{headers}");
    println!(
        "response body: {} bytes",
        response.len().saturating_sub(headers.len() + 4)
    );
    Ok(())
}

async fn run_exchange(context: &Context, peer_ip: IpAddr) -> std::io::Result<Vec<u8>> {
    let mut stream = context.connect((peer_ip, 8080)).await?;

    let body = [b'R'; BODY_LEN];
    let request = format!(
        "POST / HTTP/1.1\r\nhost: tunnel\r\ncontent-length: {BODY_LEN}\r\nconnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}
