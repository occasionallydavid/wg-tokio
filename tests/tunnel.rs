use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wg_tokio::{Context, ContextConfig, PublicKey, StaticSecret};

fn assert_tokio_socket<T>()
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_round_trip_over_two_contexts() {
    assert_tokio_socket::<wg_tokio::TcpStream>();

    let server_secret = StaticSecret::from([2; 32]);
    let client_secret = StaticSecret::from([1; 32]);
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(&client_secret);
    let allowed_client = client_public;

    let server_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1));
    let client_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 0, 2));
    let server = Context::new(
        ContextConfig::new(
            server_secret,
            client_public,
            server_ip,
            client_ip,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer_verifier(move |key| async move {
            tokio::task::yield_now().await;
            key == allowed_client
        })
        .with_peer_idle_timeout(std::time::Duration::from_millis(100)),
    )
    .await
    .unwrap();
    let listener = server.listen((server_ip, 8080)).await.unwrap();

    let echo = tokio::spawn(async move {
        // Let the client finish its request first, so the listener accepts from
        // CLOSE-WAIT rather than ESTABLISHED.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(stream.peer_public_key(), client_public);
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert!(request.ends_with(&[b'R'; 1024]));
            let body = [b'S'; 1024];
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1024\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });

    for attempt in 0..2 {
        let client = Context::new(
            ContextConfig::new(
                client_secret.clone(),
                server_public,
                client_ip,
                server_ip,
                SocketAddr::from(([127, 0, 0, 1], 0)),
            )
            .with_peer_addr(server.udp_local_addr().unwrap()),
        )
        .await
        .unwrap();

        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.connect((server_ip, 8080)),
        )
        .await
        .expect("connect timed out")
        .unwrap();
        assert_eq!(stream.peer_public_key(), server_public);
        stream
            .write_all(b"POST / HTTP/1.1\r\ncontent-length: 1024\r\n\r\n")
            .await
            .unwrap();
        stream.write_all(&[b'R'; 1024]).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(&[b'S'; 1024]));
        client.finalise().await.unwrap();
        if attempt == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }

    echo.await.unwrap();
    server.finalise().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn async_peer_verifier_rejects_context() {
    let secret = StaticSecret::from([1; 32]);
    let peer = PublicKey::from(&StaticSecret::from([2; 32]));
    let result = Context::new(
        ContextConfig::new(
            secret,
            peer,
            IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer_verifier(|_| async {
            tokio::task::yield_now().await;
            false
        }),
    )
    .await;

    let error = match result {
        Ok(_) => panic!("rejected peer created a context"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}
