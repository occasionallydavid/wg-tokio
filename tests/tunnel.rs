use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wg_tokio::{AllowedIp, Context, ContextConfig, PublicKey, StaticSecret};

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
    let client_cidr: AllowedIp = "10.10.0.2/32".parse().unwrap();
    let server_cidr: AllowedIp = "10.10.0.1/32".parse().unwrap();
    let server = Context::new(
        ContextConfig::new(
            server_secret,
            server_ip,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer_verifier(move |key| async move {
            tokio::task::yield_now().await;
            (key == allowed_client).then(|| vec![client_cidr])
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
                client_ip,
                SocketAddr::from(([127, 0, 0, 1], 0)),
            )
            .with_peer(server_public, server.udp_local_addr().unwrap())
            .with_peer_verifier(move |key| async move {
                (key == server_public).then(|| vec![server_cidr])
            }),
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
            IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer(peer, SocketAddr::from(([127, 0, 0, 1], 51820)))
        .with_peer_verifier(|_| async {
            tokio::task::yield_now().await;
            None
        }),
    )
    .await;

    let error = match result {
        Ok(_) => panic!("rejected peer created a context"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test(flavor = "current_thread")]
async fn peers_with_distinct_addresses_share_one_listener() {
    let server_secret = StaticSecret::from([2; 32]);
    let client_a_secret = StaticSecret::from([3; 32]);
    let client_b_secret = StaticSecret::from([4; 32]);
    let server_public = PublicKey::from(&server_secret);
    let client_a_public = PublicKey::from(&client_a_secret);
    let client_b_public = PublicKey::from(&client_b_secret);
    let server_ip = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 1));
    let client_a_ip = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 2));
    let client_b_ip = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 3));
    let server_cidr: AllowedIp = "10.30.0.1/32".parse().unwrap();
    let client_a_cidr: AllowedIp = "10.30.0.2/32".parse().unwrap();
    let client_b_cidr: AllowedIp = "10.30.0.3/32".parse().unwrap();

    let server = Context::new(
        ContextConfig::new(
            server_secret,
            server_ip,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer_verifier(move |key| async move {
            if key == client_a_public {
                Some(vec![client_a_cidr])
            } else if key == client_b_public {
                Some(vec![client_b_cidr])
            } else {
                None
            }
        }),
    )
    .await
    .unwrap();
    let listener = server.listen((server_ip, 8080)).await.unwrap();
    let server_udp = server.udp_local_addr().unwrap();

    let echo = tokio::spawn(async move {
        let mut peer_ips = Vec::new();
        for _ in 0..2 {
            let (mut stream, remote) = listener.accept().await.unwrap();
            peer_ips.push(remote.ip());
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream.write_all(&request).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        peer_ips
    });

    async fn connect_and_echo(
        secret: StaticSecret,
        server_public: PublicKey,
        server_udp: SocketAddr,
        local_ip: IpAddr,
        server_ip: IpAddr,
        server_cidr: AllowedIp,
        byte: u8,
    ) -> PublicKey {
        let client = Context::new(
            ContextConfig::new(secret, local_ip, SocketAddr::from(([127, 0, 0, 1], 0)))
                .with_peer(server_public, server_udp)
                .with_peer_verifier(move |key| async move {
                    (key == server_public).then(|| vec![server_cidr])
                }),
        )
        .await
        .unwrap();
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.connect((server_ip, 8080)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                client.finalise().await.unwrap();
                panic!("same-address connect failed: {error}");
            }
            Err(_) => {
                eprintln!("connect timed out for {byte}; finalising");
                client.finalise().await.unwrap();
                eprintln!("finalise complete for {byte}");
                panic!("same-address connect timed out for {byte}");
            }
        };
        let peer_key = stream.peer_public_key();
        let payload = [byte; 1024];
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        if tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_to_end(&mut response),
        )
        .await
        .is_err()
        {
            client.finalise().await.unwrap();
            panic!("same-address response timed out for {byte}");
        }
        assert_eq!(response, payload);
        client.finalise().await.unwrap();
        peer_key
    }

    let (a, b) = tokio::join!(
        connect_and_echo(
            client_a_secret,
            server_public,
            server_udp,
            client_a_ip,
            server_ip,
            server_cidr,
            b'A',
        ),
        connect_and_echo(
            client_b_secret,
            server_public,
            server_udp,
            client_b_ip,
            server_ip,
            server_cidr,
            b'B',
        ),
    );
    assert_eq!(a, server_public);
    assert_eq!(b, server_public);

    let peer_ips = echo.await.unwrap();
    assert_eq!(peer_ips.len(), 2);
    assert!(peer_ips.contains(&client_a_ip));
    assert!(peer_ips.contains(&client_b_ip));
    server.finalise().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn cookie_reply_retries_handshake_immediately() {
    let server_secret = StaticSecret::from([2; 32]);
    let client_secret = StaticSecret::from([1; 32]);
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(&client_secret);
    let server_ip = IpAddr::V4(Ipv4Addr::new(10, 40, 0, 1));
    let client_ip = IpAddr::V4(Ipv4Addr::new(10, 40, 0, 2));
    let server_cidr: AllowedIp = "10.40.0.1/32".parse().unwrap();
    let client_cidr: AllowedIp = "10.40.0.2/32".parse().unwrap();

    let server = Context::new(
        ContextConfig::new(
            server_secret,
            server_ip,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer_verifier(
            move |key| async move { (key == client_public).then(|| vec![client_cidr]) },
        )
        .with_handshake_rate_limit(0),
    )
    .await
    .unwrap();
    let listener = server.listen((server_ip, 8080)).await.unwrap();
    let server_udp = server.udp_local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
        stream
    });

    async fn connect_once(
        client_secret: StaticSecret,
        client_ip: IpAddr,
        server_public: PublicKey,
        server_udp: SocketAddr,
        server_ip: IpAddr,
        server_cidr: AllowedIp,
    ) -> (Context, wg_tokio::TcpStream) {
        let client = Context::new(
            ContextConfig::new(
                client_secret,
                client_ip,
                SocketAddr::from(([127, 0, 0, 1], 0)),
            )
            .with_peer(server_public, server_udp)
            .with_peer_verifier(move |key| async move {
                (key == server_public).then(|| vec![server_cidr])
            }),
        )
        .await
        .unwrap();
        let stream =
            tokio::time::timeout(Duration::from_secs(2), client.connect((server_ip, 8080)))
                .await
                .expect("hidden cookie retry delayed the handshake")
                .unwrap();
        (client, stream)
    }

    let (client, stream) = connect_once(
        client_secret,
        client_ip,
        server_public,
        server_udp,
        server_ip,
        server_cidr,
    )
    .await;
    let server_stream = accept.await.unwrap();
    drop(stream);
    drop(server_stream);
    client.finalise().await.unwrap();

    server.finalise().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn expired_peer_aborts_its_tcp_sessions() {
    let server_secret = StaticSecret::from([2; 32]);
    let client_secret = StaticSecret::from([1; 32]);
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(&client_secret);
    let server_ip = IpAddr::V4(Ipv4Addr::new(10, 50, 0, 1));
    let client_ip = IpAddr::V4(Ipv4Addr::new(10, 50, 0, 2));
    let server_cidr: AllowedIp = "10.50.0.1/32".parse().unwrap();
    let client_cidr: AllowedIp = "10.50.0.2/32".parse().unwrap();

    let server = Context::new(
        ContextConfig::new(
            server_secret,
            server_ip,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer_verifier(
            move |key| async move { (key == client_public).then(|| vec![client_cidr]) },
        )
        .with_peer_idle_timeout(Duration::from_millis(100)),
    )
    .await
    .unwrap();
    let listener = server.listen((server_ip, 8080)).await.unwrap();
    let server_udp = server.udp_local_addr().unwrap();
    let client = Context::new(
        ContextConfig::new(
            client_secret,
            client_ip,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_peer(server_public, server_udp)
        .with_peer_verifier(move |key| async move {
            (key == server_public).then(|| vec![server_cidr])
        }),
    )
    .await
    .unwrap();

    let client_stream =
        tokio::time::timeout(Duration::from_secs(2), client.connect((server_ip, 8080)))
            .await
            .unwrap()
            .unwrap();
    let (server_stream, _) = listener.accept().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server_stream.state(), wg_tokio::TcpState::Closed);

    drop(server_stream);
    drop(client_stream);
    client.finalise().await.unwrap();
    server.finalise().await.unwrap();
}
