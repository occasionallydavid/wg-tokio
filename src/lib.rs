//! A minimal `tokio::net`-style TCP API over a point-to-point WireGuard tunnel.
//!
//! [`Context`] owns a BoringTun tunnel and a smoltcp interface. It turns TCP
//! sockets from that interface into tokio [`AsyncRead`] and [`AsyncWrite`]
//! objects. Applications such as hyper can use the resulting streams without
//! knowing that their bytes travel over WireGuard.
//!
//! A context represents exactly one WireGuard peer: the peer's public key and
//! the local private key define the tunnel, and the two configured tunnel IP
//! addresses route TCP traffic over it.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::{Duration, Instant};

#[cfg(all(feature = "crypto-ring", feature = "crypto-rust"))]
compile_error!("enable only one of `crypto-ring` or `crypto-rust`");
#[cfg(not(any(feature = "crypto-ring", feature = "crypto-rust")))]
compile_error!("enable either `crypto-ring` or `crypto-rust`");

#[cfg(feature = "crypto-rust")]
use nordisk as boringtun;

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium, PacketMeta};
use smoltcp::socket::{Socket, tcp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf, Ready};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub use boringtun::x25519::{PublicKey, StaticSecret};
pub use smoltcp::socket::tcp::State as TcpState;
pub use smoltcp::wire::IpCidr as AllowedIp;

pub type PeerVerifierFuture =
    Pin<Box<dyn Future<Output = Option<Vec<AllowedIp>>> + Send + 'static>>;
pub type PeerVerifier = Box<dyn Fn(PublicKey) -> PeerVerifierFuture + Send + Sync + 'static>;

const MTU: usize = 1420;
const TCP_BUFFER_SIZE: usize = 64 * 1024;
const MAX_UDP_DATAGRAM: usize = 65_535;
const DRIVER_SLICE: Duration = Duration::from_secs(1);
const LISTENER_BACKLOG: usize = 32;

#[derive(Clone, Copy)]
pub struct KnownPeer {
    pub public_key: PublicKey,
    pub endpoint: SocketAddr,
}

/// Configuration for a WireGuard context and its shared TCP/IP stack.
pub struct ContextConfig {
    /// The local WireGuard private key.
    pub local_private_key: StaticSecret,
    /// This endpoint's address inside the WireGuard tunnel.
    pub local_ip: IpAddr,
    /// UDP address on which to receive WireGuard packets.
    pub udp_bind: SocketAddr,
    /// Peers that can be dialled before they have initiated a handshake.
    pub known_peers: Vec<KnownPeer>,
    /// Async authorization and allowed-address lookup for peer public keys.
    pub peer_verifier: Option<PeerVerifier>,
    /// Forget peers after this much authenticated inactivity.
    pub peer_idle_timeout: Option<Duration>,
    /// Maximum handshake packets accepted in one rate-limit period.
    pub handshake_rate_limit: u64,
}

impl ContextConfig {
    pub fn new(local_private_key: StaticSecret, local_ip: IpAddr, udp_bind: SocketAddr) -> Self {
        Self {
            local_private_key,
            local_ip,
            udp_bind,
            known_peers: Vec::new(),
            peer_verifier: None,
            peer_idle_timeout: None,
            handshake_rate_limit: 100,
        }
    }

    /// Add a peer that this context can dial before receiving its handshake.
    #[must_use]
    pub fn with_peer(mut self, public_key: PublicKey, endpoint: SocketAddr) -> Self {
        self.known_peers.push(KnownPeer {
            public_key,
            endpoint,
        });
        self
    }

    /// Set an async verifier called with the configured peer public key.
    ///
    /// The verifier may capture state and perform asynchronous work such as a
    /// database lookup. A `false` result rejects Context creation.
    #[must_use]
    pub fn with_peer_verifier<F, Fut>(mut self, verifier: F) -> Self
    where
        F: Fn(PublicKey) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<Vec<AllowedIp>>> + Send + 'static,
    {
        self.peer_verifier = Some(Box::new(move |key| {
            Box::pin(verifier(key)) as PeerVerifierFuture
        }));
        self
    }

    /// Forget peers after a period without authenticated peer traffic.
    #[must_use]
    pub fn with_peer_idle_timeout(mut self, peer_idle_timeout: Duration) -> Self {
        self.peer_idle_timeout = Some(peer_idle_timeout);
        self
    }

    /// Sets the number of handshake packets accepted per rate-limit period.
    #[must_use]
    pub fn with_handshake_rate_limit(mut self, limit: u64) -> Self {
        self.handshake_rate_limit = limit;
        self
    }
}

/// A WireGuard-backed network context.
pub struct Context {
    inner: Arc<Inner>,
    _driver: Arc<Driver>,
}

struct Driver {
    task: JoinHandle<()>,
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Inner {
    stack: Mutex<Stack>,
    peer_routes: Mutex<Vec<PeerRoute>>,
    wakers: Mutex<Vec<Waker>>,
    driver_notify: Notify,
    state_notify: Notify,
    transport_busy: AtomicBool,
    finalised: AtomicBool,
    peer_idle_timeout: Option<Duration>,
    udp_addr: SocketAddr,
    local_ip: IpAddr,
}

#[derive(Clone)]
struct PeerRoute {
    peer_public_key: PublicKey,
    allowed: Vec<AllowedIp>,
}

struct PeerState {
    public_key: PublicKey,
    endpoint: SocketAddr,
    allowed: Vec<AllowedIp>,
    tunn: Tunn,
    last_activity: Instant,
    index: u32,
}

type AcceptedConnection = (usize, SocketHandle, SocketHandle, SocketAddr, SocketAddr);

struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    retired: Vec<SocketHandle>,
    listeners: Vec<SocketHandle>,
}

impl Context {
    /// Create and start a WireGuard context.
    pub async fn new(config: ContextConfig) -> io::Result<Self> {
        if config.known_peers.is_empty() && config.peer_verifier.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a peer verifier is required for inbound WireGuard peers",
            ));
        }

        let udp = UdpSocket::bind(config.udp_bind).await?;
        let udp_addr = udp.local_addr()?;
        let local_public = PublicKey::from(&config.local_private_key);
        let rate_limiter = Arc::new(RateLimiter::new(&local_public, config.handshake_rate_limit));
        let mut peers = HashMap::new();
        let mut routes = Vec::new();

        for (offset, known) in config.known_peers.iter().enumerate() {
            let allowed = match &config.peer_verifier {
                Some(verifier) => verifier(known.public_key).await,
                None => None,
            }
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "WireGuard peer rejected by async verifier",
                )
            })?;
            let index = (offset as u32) + 1;
            let tunn = Tunn::new(
                config.local_private_key.clone(),
                known.public_key,
                None,
                None,
                index,
                Some(Arc::clone(&rate_limiter)),
            );
            peers.insert(
                known.public_key,
                PeerState {
                    public_key: known.public_key,
                    endpoint: known.endpoint,
                    allowed: allowed.clone(),
                    tunn,
                    last_activity: Instant::now(),
                    index,
                },
            );
            routes.push(PeerRoute {
                peer_public_key: known.public_key,
                allowed,
            });
        }

        let mut stack = Stack::new(config.local_ip);
        stack.poll_interface();

        let inner = Arc::new(Inner {
            stack: Mutex::new(stack),
            peer_routes: Mutex::new(routes),
            wakers: Mutex::new(Vec::new()),
            driver_notify: Notify::new(),
            state_notify: Notify::new(),
            transport_busy: AtomicBool::new(false),
            finalised: AtomicBool::new(false),
            peer_idle_timeout: config.peer_idle_timeout,
            udp_addr,
            local_ip: config.local_ip,
        });

        let task_inner = Arc::clone(&inner);
        let task = tokio::spawn(async move {
            run_driver(
                task_inner,
                udp,
                config.local_private_key,
                local_public,
                config.peer_verifier,
                rate_limiter,
                peers,
                (config.known_peers.len() as u32) + 1,
            )
            .await;
        });

        Ok(Self {
            inner,
            _driver: Arc::new(Driver { task }),
        })
    }

    /// The actual UDP address bound by this context.
    pub fn udp_local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inner.udp_addr)
    }

    /// Open a TCP connection to `remote` through the tunnel.
    ///
    /// This waits for the TCP handshake and returns an object implementing
    /// tokio's [`AsyncRead`] and [`AsyncWrite`].
    pub async fn connect(&self, remote: impl Into<SocketAddr>) -> io::Result<TcpStream> {
        if self.inner.finalised.load(Ordering::Acquire) {
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        let remote = remote.into();
        let peer_public_key = self.inner.peer_for_ip(remote.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no WireGuard peer permits {remote}"),
            )
        })?;

        let handle = self.inner.start_connect(remote)?;
        self.inner.request_driver();

        loop {
            let notified = self.inner.state_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let state = lock(&self.inner.stack).state(handle);
            match state {
                tcp::State::Established => {
                    return Ok(TcpStream {
                        inner: Arc::clone(&self.inner),
                        handle: Mutex::new(handle),
                        nodelay: AtomicBool::new(false),
                        _driver: Arc::clone(&self._driver),
                        peer_public_key,
                    });
                }
                tcp::State::Closed => {
                    lock(&self.inner.stack).remove(handle);
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                _ => {
                    notified.await;
                }
            }
        }
    }

    /// Listen for TCP connections on this context's tunnel IP.
    pub async fn listen(&self, addr: impl Into<SocketAddr>) -> io::Result<TcpListener> {
        if self.inner.finalised.load(Ordering::Acquire) {
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        let addr = addr.into();
        if addr.ip() != self.inner.local_ip {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "listen IP must be the context local IP {}, got {}",
                    self.inner.local_ip, addr
                ),
            ));
        }
        if addr.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listen port must not be zero",
            ));
        }

        let mut stack = lock(&self.inner.stack);
        let mut handles = Vec::with_capacity(LISTENER_BACKLOG);
        for _ in 0..LISTENER_BACKLOG {
            let handle = stack.add_socket();
            if let Err(err) = stack.socket_mut(handle).listen(addr.port()) {
                stack.remove(handle);
                for handle in handles {
                    stack.remove(handle);
                }
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("cannot listen on {addr}: {err:?}"),
                ));
            }
            handles.push(handle);
        }
        stack.listeners.extend(&handles);
        drop(stack);

        self.inner.request_driver();
        Ok(TcpListener {
            inner: Arc::clone(&self.inner),
            handles: Mutex::new(handles),
            local_addr: addr,
            _driver: Arc::clone(&self._driver),
        })
    }

    /// Close every TCP socket gracefully and wait for final acknowledgements.
    ///
    /// A context must be finalised explicitly or by its configured idle timeout
    /// before it is dropped.
    pub async fn finalise(&self) -> io::Result<()> {
        if self.inner.finalised.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut grace_elapsed = false;
        loop {
            let notified = self.inner.state_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let (quiet, emitted, timer_pending) = {
                let mut stack = lock(&self.inner.stack);
                let handles: Vec<_> = stack.sockets.iter().map(|(handle, _)| handle).collect();

                for handle in handles {
                    let socket = stack.socket_mut(handle);
                    match socket.state() {
                        tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived => {
                            socket.abort();
                        }
                        tcp::State::Closed | tcp::State::TimeWait => {}
                        _ => {
                            if socket.may_send() {
                                socket.close();
                            }
                        }
                    }
                }

                let emitted = stack.poll_interface();
                let quiet = stack.sockets.iter().all(|(_, socket)| match socket {
                    Socket::Tcp(socket) => {
                        matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
                    }
                });
                let tx_pending = !stack.device.tx.is_empty();
                let Stack { iface, sockets, .. } = &mut *stack;
                let timer_pending = iface
                    .poll_delay(SmolInstant::now(), sockets)
                    .is_some_and(|delay| delay.total_millis() < 1_000);

                (quiet && !tx_pending, emitted, timer_pending)
            };

            if emitted || timer_pending {
                self.inner.request_driver();
            }
            if quiet && !timer_pending && !self.inner.transport_busy.load(Ordering::Acquire) {
                if !grace_elapsed {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    grace_elapsed = true;
                    continue;
                }
                self.inner.finish();
                return Ok(());
            }

            notified.await;
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.inner.finalised.load(Ordering::Acquire) {
            panic!("WireGuard context dropped without finalise() or idle timeout");
        }
    }
}

impl Inner {
    fn request_driver(&self) {
        self.driver_notify.notify_one();
    }

    fn finish(&self) {
        if !self.finalised.swap(true, Ordering::AcqRel) {
            self.request_driver();
            self.wake_all();
        }
    }

    fn peer_for_ip(&self, ip: IpAddr) -> Option<PublicKey> {
        lock(&self.peer_routes)
            .iter()
            .find(|route| {
                route
                    .allowed
                    .iter()
                    .any(|allowed| allowed.contains_addr(&IpAddress::from(ip)))
            })
            .map(|route| route.peer_public_key)
    }

    fn set_peer_routes(&self, peer_public_key: PublicKey, allowed: Vec<AllowedIp>) {
        let mut routes = lock(&self.peer_routes);
        routes.retain(|route| route.peer_public_key != peer_public_key);
        routes.push(PeerRoute {
            peer_public_key,
            allowed,
        });
    }

    fn remove_peer_routes(&self, peer_public_key: PublicKey) {
        lock(&self.peer_routes).retain(|route| route.peer_public_key != peer_public_key);
    }

    fn forget_peer(&self, peer_public_key: PublicKey, allowed: &[AllowedIp]) {
        self.remove_peer_routes(peer_public_key);
        let mut stack = lock(&self.stack);
        let listeners = stack.listeners.clone();
        let handles: Vec<_> = stack
            .sockets
            .iter()
            .filter_map(|(handle, socket)| match socket {
                Socket::Tcp(socket) => socket
                    .remote_endpoint()
                    .map(|endpoint| IpAddress::from(IpAddr::from(endpoint.addr)))
                    .filter(|remote| allowed.iter().any(|allowed| allowed.contains_addr(remote)))
                    .map(|_| handle),
            })
            .collect();

        for handle in handles {
            if !listeners.contains(&handle) {
                stack.socket_mut(handle).abort();
            }
        }

        stack.poll_interface();
        stack.device.tx.clear();
        drop(stack);
        self.wake_all();
    }

    fn register_waker(&self, cx: &TaskContext<'_>) {
        let mut wakers = lock(&self.wakers);
        if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
            wakers.push(cx.waker().clone());
        }
    }

    fn wake_all(&self) {
        let wakers = {
            let mut wakers = lock(&self.wakers);
            std::mem::take(&mut *wakers)
        };
        for waker in wakers {
            waker.wake();
        }
        self.state_notify.notify_waiters();
    }

    fn poll_stack(&self) -> Vec<Vec<u8>> {
        lock(&self.stack).poll()
    }

    fn next_delay(&self) -> Duration {
        let mut stack = lock(&self.stack);
        let now = SmolInstant::now();
        let Stack { iface, sockets, .. } = &mut *stack;
        iface
            .poll_delay(now, sockets)
            .map(|duration| Duration::from_micros(duration.total_micros()))
            .unwrap_or(DRIVER_SLICE)
            .clamp(Duration::from_millis(1), DRIVER_SLICE)
    }

    fn start_connect(&self, remote: SocketAddr) -> io::Result<SocketHandle> {
        let mut stack = lock(&self.stack);
        for _ in 0..1024 {
            let handle = stack.add_socket();
            let local_port = next_ephemeral_port();
            let Stack { iface, sockets, .. } = &mut *stack;
            match sockets.get_mut::<tcp::Socket<'static>>(handle).connect(
                iface.context(),
                IpEndpoint::from(remote),
                local_port,
            ) {
                Ok(()) => return Ok(handle),
                Err(tcp::ConnectError::InvalidState) => {
                    stack.remove(handle);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "remote address is not usable",
                    ));
                }
                Err(_) => stack.remove(handle),
            }
        }
        Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
    }
}

impl Stack {
    fn new(local_ip: IpAddr) -> Self {
        let mut device = QueueDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_seed();

        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        let prefix_len = if local_ip.is_ipv4() { 32 } else { 128 };
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::from(local_ip), prefix_len))
                .expect("one interface address always fits");
        });

        match local_ip {
            IpAddr::V4(local) => {
                iface
                    .routes_mut()
                    .add_default_ipv4_route(local)
                    .expect("default IPv4 route fits");
            }
            IpAddr::V6(local) => {
                iface
                    .routes_mut()
                    .add_default_ipv6_route(local)
                    .expect("default IPv6 route fits");
            }
        }

        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            retired: Vec::new(),
            listeners: Vec::new(),
        }
    }

    fn poll_interface(&mut self) -> bool {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        self.reap();
        !self.device.tx.is_empty()
    }

    fn poll(&mut self) -> Vec<Vec<u8>> {
        self.poll_interface();
        self.device.take_tx()
    }

    fn add_socket(&mut self) -> SocketHandle {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        );
        socket.set_ack_delay(None);
        self.sockets.add(socket)
    }

    fn socket_mut(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(handle)
    }

    fn socket(&self, handle: SocketHandle) -> &tcp::Socket<'static> {
        self.sockets.get(handle)
    }

    fn state(&self, handle: SocketHandle) -> tcp::State {
        self.socket(handle).state()
    }

    fn remove(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }

    fn retire(&mut self, handle: SocketHandle) {
        self.retired.push(handle);
    }

    fn reap(&mut self) {
        for handle in std::mem::take(&mut self.retired) {
            if matches!(
                self.state(handle),
                tcp::State::Closed | tcp::State::TimeWait
            ) {
                self.remove(handle);
            } else {
                self.retired.push(handle);
            }
        }
    }

    fn accept(
        &mut self,
        listener: SocketHandle,
    ) -> io::Result<Option<(SocketHandle, SocketHandle, SocketAddr, SocketAddr)>> {
        let socket = self.socket(listener);
        if !matches!(
            socket.state(),
            tcp::State::Established
                | tcp::State::CloseWait
                | tcp::State::FinWait1
                | tcp::State::FinWait2
                | tcp::State::Closing
                | tcp::State::LastAck
        ) {
            return Ok(None);
        }

        let remote = socket
            .remote_endpoint()
            .map(SocketAddr::from)
            .ok_or_else(|| io::Error::other("accepted socket has no peer"))?;
        let local = socket
            .local_endpoint()
            .map(SocketAddr::from)
            .ok_or_else(|| io::Error::other("accepted socket has no local address"))?;

        let Socket::Tcp(accepted) = self.sockets.remove(listener);

        let mut replacement = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        );
        replacement.listen(local.port()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("cannot relisten on {}: {err:?}", local.port()),
            )
        })?;

        let replacement_handle = self.sockets.add(replacement);
        let accepted_handle = self.sockets.add(accepted);
        if let Some(listener_handle) = self
            .listeners
            .iter_mut()
            .find(|listener_handle| **listener_handle == listener)
        {
            *listener_handle = replacement_handle;
        }
        Ok(Some((replacement_handle, accepted_handle, local, remote)))
    }

    fn accept_any(&mut self, listeners: &[SocketHandle]) -> io::Result<Option<AcceptedConnection>> {
        for (position, listener) in listeners.iter().enumerate() {
            if let Some((replacement, accepted, local, remote)) = self.accept(*listener)? {
                return Ok(Some((position, replacement, accepted, local, remote)));
            }
        }
        Ok(None)
    }
}

#[derive(Default)]
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl QueueDevice {
    fn take_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain(..).collect()
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((
            RxToken { packet },
            TxToken {
                queue: &mut self.tx,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities.max_burst_size = None;
        capabilities
    }
}

struct RxToken {
    packet: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.queue.push_back(packet);
        result
    }

    fn set_meta(&mut self, _meta: PacketMeta) {}
}

/// A TCP stream carried by a [`Context`]'s WireGuard tunnel.
pub struct TcpStream {
    inner: Arc<Inner>,
    handle: Mutex<SocketHandle>,
    nodelay: AtomicBool,
    peer_public_key: PublicKey,
    _driver: Arc<Driver>,
}

impl TcpStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let stack = lock(&self.inner.stack);
        stack
            .socket(*lock(&self.handle))
            .local_endpoint()
            .map(SocketAddr::from)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "stream has no local address")
            })
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        let stack = lock(&self.inner.stack);
        stack
            .socket(*lock(&self.handle))
            .remote_endpoint()
            .map(SocketAddr::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream has no peer"))
    }

    pub fn state(&self) -> TcpState {
        let stack = lock(&self.inner.stack);
        stack.state(*lock(&self.handle))
    }

    pub async fn readable(&self) -> io::Result<()> {
        self.ready(Interest::READABLE).await.map(|_| ())
    }

    pub async fn writable(&self) -> io::Result<()> {
        self.ready(Interest::WRITABLE).await.map(|_| ())
    }

    pub async fn ready(&self, interest: Interest) -> io::Result<Ready> {
        loop {
            let notified = self.inner.state_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let ready = self.current_ready();
            if readiness_matches(ready, interest) {
                return Ok(ready);
            }
            notified.await;
        }
    }

    pub fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stack = lock(&self.inner.stack);
        let handle = *lock(&self.handle);
        let socket = stack.socket_mut(handle);
        if socket.can_recv() {
            return socket
                .recv_slice(buf)
                .map_err(|err| io::Error::other(format!("{err:?}")));
        }
        if !socket.may_recv() {
            return Ok(0);
        }
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    pub fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut stack = lock(&self.inner.stack);
        let handle = *lock(&self.handle);
        let socket = stack.socket_mut(handle);
        if !socket.may_send() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        if !socket.can_send() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let written = socket
            .send_slice(buf)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, format!("{err:?}")))?;
        drop(stack);
        self.inner.request_driver();
        Ok(written)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stack = lock(&self.inner.stack);
        let handle = *lock(&self.handle);
        let socket = stack.socket_mut(handle);
        if !socket.may_recv() && !socket.can_recv() {
            return Ok(0);
        }
        socket
            .peek_slice(buf)
            .map_err(|err| io::Error::other(format!("{err:?}")))
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        let mut stack = lock(&self.inner.stack);
        let handle = *lock(&self.handle);
        stack.socket_mut(handle).set_nagle_enabled(!nodelay);
        self.nodelay.store(nodelay, Ordering::Relaxed);
        drop(stack);
        self.inner.request_driver();
        Ok(())
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(self.nodelay.load(Ordering::Relaxed))
    }

    /// The authorized WireGuard identity of the remote peer.
    pub fn peer_public_key(&self) -> PublicKey {
        self.peer_public_key
    }

    /// Wait until a graceful close has flushed its final ACK.
    ///
    /// This is useful after reading to EOF and shutting down the write half,
    /// when the application needs to keep the context alive through the last
    /// TCP acknowledgement.
    pub async fn wait_closed(&self) -> io::Result<()> {
        loop {
            if self.inner.finalised.load(Ordering::Acquire) {
                return Ok(());
            }
            let notified = self.inner.state_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let (closed, tx_pending, emitted, close_timer_pending) = {
                let mut stack = lock(&self.inner.stack);
                let emitted = stack.poll_interface();
                let handle = *lock(&self.handle);
                let closed = matches!(
                    stack.state(handle),
                    tcp::State::Closed | tcp::State::TimeWait
                );
                let Stack { iface, sockets, .. } = &mut *stack;
                let close_timer_pending = iface
                    .poll_delay(SmolInstant::now(), sockets)
                    .is_some_and(|delay| delay.total_millis() < 1_000);
                (
                    closed,
                    !stack.device.tx.is_empty(),
                    emitted,
                    close_timer_pending,
                )
            };

            if emitted || tx_pending {
                self.inner.request_driver();
            }
            if closed
                && !tx_pending
                && !close_timer_pending
                && !self.inner.transport_busy.load(Ordering::Acquire)
            {
                return Ok(());
            }

            notified.await;
        }
    }

    fn current_ready(&self) -> Ready {
        let stack = lock(&self.inner.stack);
        let socket = stack.socket(*lock(&self.handle));
        let mut ready = Ready::EMPTY;
        if socket.can_recv() {
            ready |= Ready::READABLE;
        }
        if !socket.may_recv() {
            ready |= Ready::READ_CLOSED;
        }
        if socket.can_send() {
            ready |= Ready::WRITABLE;
        }
        if !socket.may_send() {
            ready |= Ready::WRITE_CLOSED;
        }
        ready
    }

    fn poll_socket_read(
        &self,
        cx: &TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stack = lock(&self.inner.stack);
        let handle = *lock(&self.handle);
        let socket = stack.socket_mut(handle);
        if socket.can_recv() {
            match socket.recv_slice(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(err) => {
                    return Poll::Ready(Err(io::Error::other(format!("{err:?}"))));
                }
            }
        }
        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }
        drop(stack);
        self.inner.register_waker(cx);
        Poll::Pending
    }

    fn poll_flush_socket(&self, cx: &TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut stack = lock(&self.inner.stack);
        let handle = *lock(&self.handle);
        let socket = stack.socket_mut(handle);
        if socket.send_queue() == 0 || !socket.may_send() {
            return Poll::Ready(Ok(()));
        }
        let emitted = stack.poll_interface();
        drop(stack);
        self.inner.register_waker(cx);
        if emitted {
            self.inner.request_driver();
        }
        Poll::Pending
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let handle = self.handle.get_mut().unwrap_or_else(|err| err.into_inner());
        let mut stack = lock(&self.inner.stack);
        let state = stack.state(*handle);
        if matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
            stack.remove(*handle);
        } else {
            stack.socket_mut(*handle).close();
            stack.retire(*handle);
        }
        drop(stack);
        self.inner.request_driver();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_socket_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut stack = lock(&self.inner.stack);
        let handle = *lock(&self.handle);
        let socket = stack.socket_mut(handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if !socket.can_send() {
            drop(stack);
            self.inner.register_waker(cx);
            return Poll::Pending;
        }
        match socket.send_slice(buf) {
            Ok(written) => {
                stack.poll_interface();
                drop(stack);
                self.inner.request_driver();
                Poll::Ready(Ok(written))
            }
            Err(err) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{err:?}"),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_socket(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let (changed, emitted) = {
            let mut stack = lock(&self.inner.stack);
            let handle = *lock(&self.handle);
            let socket = stack.socket_mut(handle);
            let changed = socket.may_send();
            if changed {
                socket.close();
            }
            (changed, stack.poll_interface())
        };
        if changed || emitted {
            self.inner.request_driver();
        }
        self.poll_flush_socket(cx)
    }
}

/// A listener for TCP connections over a WireGuard context.
pub struct TcpListener {
    inner: Arc<Inner>,
    handles: Mutex<Vec<SocketHandle>>,
    local_addr: SocketAddr,
    _driver: Arc<Driver>,
}

impl TcpListener {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        loop {
            if self.inner.finalised.load(Ordering::Acquire) {
                return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
            }
            let notified = self.inner.state_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let accepted = {
                let mut handles = lock(&self.handles);
                let mut stack = lock(&self.inner.stack);
                match stack.accept_any(&handles) {
                    Ok(Some((position, replacement, accepted, _local, remote))) => {
                        handles[position] = replacement;
                        Some((accepted, remote))
                    }
                    Ok(None) => None,
                    Err(err) => return Err(err),
                }
            };

            if let Some((accepted_handle, remote)) = accepted {
                let peer_public_key = self.inner.peer_for_ip(remote.ip()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("no authorized WireGuard peer owns {}", remote.ip()),
                    )
                })?;
                self.inner.request_driver();
                return Ok((
                    TcpStream {
                        inner: Arc::clone(&self.inner),
                        handle: Mutex::new(accepted_handle),
                        nodelay: AtomicBool::new(false),
                        _driver: Arc::clone(&self._driver),
                        peer_public_key,
                    },
                    remote,
                ));
            }

            notified.await;
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let handles = self
            .handles
            .get_mut()
            .unwrap_or_else(|err| err.into_inner());
        let mut stack = lock(&self.inner.stack);
        for handle in handles.iter() {
            stack.listeners.retain(|listener| listener != handle);
            stack.socket_mut(*handle).abort();
            stack.remove(*handle);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_driver(
    inner: Arc<Inner>,
    udp: UdpSocket,
    local_private: StaticSecret,
    local_public: PublicKey,
    verifier: Option<PeerVerifier>,
    rate_limiter: Arc<RateLimiter>,
    mut peers: HashMap<PublicKey, PeerState>,
    mut next_index: u32,
) {
    let mut udp_buffer = vec![0; MAX_UDP_DATAGRAM];
    let mut tunnel_buffer = vec![0; MAX_UDP_DATAGRAM];
    let mut cookie_buffer = [0u8; 64];

    loop {
        let mut delay = inner.next_delay();
        if let Some(timeout) = inner.peer_idle_timeout {
            for peer in peers.values() {
                let remaining = timeout.saturating_sub(peer.last_activity.elapsed());
                delay = delay.min(remaining.max(Duration::from_millis(1)));
            }
        }
        let notified = inner.driver_notify.notified();
        let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut inbound = Vec::new();

        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep(delay) => {}
            result = udp.recv_from(&mut udp_buffer) => {
                if let Ok((len, source)) = result {
                    let datagram = &udp_buffer[..len];
                    rate_limiter.reset_count();
                    let parsed = match rate_limiter.verify_packet(
                        Some(source.ip()),
                        datagram,
                        &mut cookie_buffer,
                    ) {
                        Ok(packet) => Some(packet),
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            outbound.push((source, cookie.to_vec()));
                            None
                        }
                        Err(_) => None,
                    };

                    let target = parsed.as_ref().and_then(|packet| match packet {
                        Packet::HandshakeInit(init) => parse_handshake_anon(
                            &local_private,
                            &local_public,
                            init,
                        )
                        .ok()
                        .map(|handshake| PublicKey::from(handshake.peer_static_public)),
                        Packet::HandshakeResponse(packet) => {
                            peer_key_by_index(&peers, packet.receiver_idx)
                        }
                        Packet::PacketCookieReply(packet) => {
                            peer_key_by_index(&peers, packet.receiver_idx)
                        }
                        Packet::PacketData(packet) => {
                            peer_key_by_index(&peers, packet.receiver_idx)
                        }
                    });

                    if let Some(peer_key) = target {
                        let cookie_reply =
                            matches!(parsed.as_ref(), Some(Packet::PacketCookieReply(_)));
                        let is_handshake_init =
                            matches!(parsed.as_ref(), Some(Packet::HandshakeInit(_)));
                        let allowed = if is_handshake_init {
                            match &verifier {
                                Some(verifier) => verifier(peer_key).await,
                                None => peers.get(&peer_key).map(|peer| peer.allowed.clone()),
                            }
                        } else {
                            peers.get(&peer_key).map(|peer| peer.allowed.clone())
                        };

                        if let Some(allowed) = allowed {
                            let peer = peers.entry(peer_key).or_insert_with(|| {
                                let index = next_index;
                                next_index += 1;
                                let tunn = Tunn::new(
                                    local_private.clone(),
                                    peer_key,
                                    None,
                                    None,
                                    index,
                                    Some(Arc::clone(&rate_limiter)),
                                );
                                PeerState {
                                    public_key: peer_key,
                                    endpoint: source,
                                    allowed: allowed.clone(),
                                    tunn,
                                    last_activity: Instant::now(),
                                    index,
                                }
                            });
                            peer.endpoint = source;
                            peer.allowed = allowed.clone();
                            peer.last_activity = Instant::now();
                            inner.set_peer_routes(peer_key, allowed);
                            decapsulate_peer(
                                peer,
                                source.ip(),
                                datagram,
                                cookie_reply,
                                &mut tunnel_buffer,
                                &mut inbound,
                                &mut outbound,
                            );
                        }
                    }
                }
            }
        }

        if inner.finalised.load(Ordering::Acquire) {
            break;
        }

        if let Some(timeout) = inner.peer_idle_timeout {
            let expired: Vec<_> = peers
                .iter()
                .filter(|(_, peer)| peer.last_activity.elapsed() >= timeout)
                .map(|(key, peer)| (*key, peer.allowed.clone()))
                .collect();
            for (key, allowed) in expired {
                peers.remove(&key);
                inner.forget_peer(key, &allowed);
            }
        }

        inner.transport_busy.store(true, Ordering::Release);

        if !inbound.is_empty() {
            let mut stack = lock(&inner.stack);
            stack.device.rx.extend(inbound.drain(..));
        }

        for peer in peers.values_mut() {
            update_peer_timers(peer, &mut tunnel_buffer, &mut inbound, &mut outbound);
        }

        if !inbound.is_empty() {
            let mut stack = lock(&inner.stack);
            stack.device.rx.extend(inbound.drain(..));
        }

        let packets = inner.poll_stack();
        for packet in packets {
            let Some(destination) = Tunn::dst_address(&packet) else {
                continue;
            };
            let Some(peer_key) = inner.peer_for_ip(destination) else {
                continue;
            };
            if let Some(peer) = peers.get_mut(&peer_key) {
                encapsulate_peer(
                    peer,
                    &packet,
                    &mut tunnel_buffer,
                    &mut inbound,
                    &mut outbound,
                );
            }
        }

        if !inbound.is_empty() {
            let mut stack = lock(&inner.stack);
            stack.device.rx.extend(inbound.drain(..));
            stack.poll_interface();
        }

        for (destination, packet) in outbound {
            let _ = udp.send_to(&packet, destination).await;
        }

        // Encryption may reveal newly queued packets or make a TCP socket
        // readable/writable, so give API waiters another poll.
        inner.transport_busy.store(false, Ordering::Release);
        inner.wake_all();
    }
}

fn peer_key_by_index(
    peers: &HashMap<PublicKey, PeerState>,
    receiver_idx: u32,
) -> Option<PublicKey> {
    let index = receiver_idx >> 8;
    peers
        .values()
        .find(|peer| peer.index == index)
        .map(|peer| peer.public_key)
}

fn update_peer_timers(
    peer: &mut PeerState,
    buffer: &mut [u8],
    inbound: &mut Vec<Vec<u8>>,
    outbound: &mut Vec<(SocketAddr, Vec<u8>)>,
) {
    let result = peer.tunn.update_timers(buffer);
    handle_tunn_result(peer, result, inbound, outbound);
}

fn encapsulate_peer(
    peer: &mut PeerState,
    packet: &[u8],
    buffer: &mut [u8],
    inbound: &mut Vec<Vec<u8>>,
    outbound: &mut Vec<(SocketAddr, Vec<u8>)>,
) {
    let result = peer.tunn.encapsulate(packet, buffer);
    handle_tunn_result(peer, result, inbound, outbound);
}

fn decapsulate_peer(
    peer: &mut PeerState,
    source: IpAddr,
    datagram: &[u8],
    cookie_reply: bool,
    buffer: &mut [u8],
    inbound: &mut Vec<Vec<u8>>,
    outbound: &mut Vec<(SocketAddr, Vec<u8>)>,
) -> bool {
    let mut authenticated = false;
    let mut cookie_accepted = false;
    let mut pending = Some(datagram);

    while let Some(datagram) = pending.take() {
        let result = peer.tunn.decapsulate(Some(source), datagram, buffer);
        cookie_accepted |= cookie_reply && matches!(&result, TunnResult::Done);
        if matches!(
            &result,
            TunnResult::WriteToNetwork(_)
                | TunnResult::WriteToTunnelV4(_, _)
                | TunnResult::WriteToTunnelV6(_, _)
        ) {
            authenticated = true;
            handle_tunn_result(peer, result, inbound, outbound);
            pending = Some(&[]);
        } else {
            break;
        }
    }
    if cookie_accepted {
        let result = peer.tunn.format_handshake_initiation(buffer, true);
        handle_tunn_result(peer, result, inbound, outbound);
    }
    authenticated
}

fn handle_tunn_result(
    peer: &PeerState,
    result: TunnResult<'_>,
    inbound: &mut Vec<Vec<u8>>,
    outbound: &mut Vec<(SocketAddr, Vec<u8>)>,
) {
    match result {
        TunnResult::WriteToNetwork(packet) => {
            outbound.push((peer.endpoint, packet.to_vec()));
        }
        TunnResult::WriteToTunnelV4(packet, source) => {
            if peer
                .allowed
                .iter()
                .any(|allowed| allowed.contains_addr(&IpAddress::from(source)))
            {
                inbound.push(packet.to_vec());
            }
        }
        TunnResult::WriteToTunnelV6(packet, source) => {
            if peer
                .allowed
                .iter()
                .any(|allowed| allowed.contains_addr(&IpAddress::from(source)))
            {
                inbound.push(packet.to_vec());
            }
        }
        TunnResult::Done | TunnResult::Err(_) => {}
    }
}

fn readiness_matches(ready: Ready, interest: Interest) -> bool {
    (interest.is_readable() && ready.is_readable())
        || (interest.is_writable() && ready.is_writable())
        || (interest.is_error() && ready == Ready::ERROR)
}

fn next_ephemeral_port() -> u16 {
    const FIRST: u16 = 49_152;
    const COUNT: u16 = u16::MAX - FIRST + 1;

    static NEXT_PORT: OnceLock<AtomicU16> = OnceLock::new();
    let next =
        NEXT_PORT.get_or_init(|| AtomicU16::new(FIRST + (random_seed() % u64::from(COUNT)) as u16));
    let port = next.fetch_add(1, Ordering::Relaxed);
    FIRST + (port.wrapping_sub(FIRST) % COUNT)
}

fn random_seed() -> u64 {
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    now ^ u64::from(COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn rate_limiter_resets_once_per_period() {
        let client_private = StaticSecret::from([1; 32]);
        let server_private = StaticSecret::from([2; 32]);
        let server_public = PublicKey::from(&server_private);
        let rate_limiter = RateLimiter::new(&server_public, 1);
        let mut client = Tunn::new(client_private, server_public, None, None, 1, None);
        let mut packet = [0_u8; MAX_UDP_DATAGRAM];
        let TunnResult::WriteToNetwork(initiation) =
            client.format_handshake_initiation(&mut packet, false)
        else {
            panic!("client did not produce a handshake initiation");
        };
        let mut cookie = [0_u8; 64];

        assert!(
            rate_limiter
                .verify_packet(
                    Some("127.0.0.1".parse().unwrap()),
                    &*initiation,
                    &mut cookie
                )
                .is_ok()
        );
        assert!(matches!(
            rate_limiter.verify_packet(
                Some("127.0.0.1".parse().unwrap()),
                &*initiation,
                &mut cookie
            ),
            Err(TunnResult::WriteToNetwork(_))
        ));

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        rate_limiter.reset_count();
        assert!(
            rate_limiter
                .verify_packet(
                    Some("127.0.0.1".parse().unwrap()),
                    &*initiation,
                    &mut cookie
                )
                .is_ok()
        );
    }
}
