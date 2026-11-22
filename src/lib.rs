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

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
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

pub type PeerVerifierFuture = Pin<Box<dyn Future<Output = bool> + Send + 'static>>;
pub type PeerVerifier = Box<dyn Fn(PublicKey) -> PeerVerifierFuture + Send + Sync + 'static>;

const MTU: usize = 1420;
const TCP_BUFFER_SIZE: usize = 64 * 1024;
const MAX_UDP_DATAGRAM: usize = 65_535;
const DRIVER_SLICE: Duration = Duration::from_secs(1);

/// Configuration for one point-to-point WireGuard context.
pub struct ContextConfig {
    /// The local WireGuard private key.
    pub local_private_key: StaticSecret,
    /// The remote peer's WireGuard public key.
    pub peer_public_key: PublicKey,
    /// This endpoint's address inside the WireGuard tunnel.
    pub local_ip: IpAddr,
    /// The remote endpoint's address inside the WireGuard tunnel.
    pub peer_ip: IpAddr,
    /// UDP address on which to receive WireGuard packets.
    pub udp_bind: SocketAddr,
    /// Optional initial UDP endpoint for the remote WireGuard peer.
    ///
    /// Clients normally set this. Servers can leave it unset and learn the
    /// endpoint from the first valid WireGuard packet.
    pub peer_addr: Option<SocketAddr>,
    /// Async authorization hook for the configured peer public key.
    pub peer_verifier: Option<PeerVerifier>,
    /// Forget the active WireGuard peer after this much peer inactivity.
    pub peer_idle_timeout: Option<Duration>,
}

impl ContextConfig {
    pub fn new(
        local_private_key: StaticSecret,
        peer_public_key: PublicKey,
        local_ip: IpAddr,
        peer_ip: IpAddr,
        udp_bind: SocketAddr,
    ) -> Self {
        Self {
            local_private_key,
            peer_public_key,
            local_ip,
            peer_ip,
            udp_bind,
            peer_addr: None,
            peer_verifier: None,
            peer_idle_timeout: None,
        }
    }

    /// Set the peer's initial UDP endpoint.
    #[must_use]
    pub fn with_peer_addr(mut self, peer_addr: SocketAddr) -> Self {
        self.peer_addr = Some(peer_addr);
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
        Fut: Future<Output = bool> + Send + 'static,
    {
        self.peer_verifier = Some(Box::new(move |key| {
            Box::pin(verifier(key)) as PeerVerifierFuture
        }));
        self
    }

    /// Forget the active peer after a period without authenticated peer traffic.
    #[must_use]
    pub fn with_peer_idle_timeout(mut self, peer_idle_timeout: Duration) -> Self {
        self.peer_idle_timeout = Some(peer_idle_timeout);
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
    wakers: Mutex<Vec<Waker>>,
    driver_notify: Notify,
    state_notify: Notify,
    transport_busy: AtomicBool,
    finalised: AtomicBool,
    last_activity: Mutex<Instant>,
    peer_idle_timeout: Option<Duration>,
    udp_addr: SocketAddr,
    local_ip: IpAddr,
    peer_ip: IpAddr,
    peer_public_key: PublicKey,
}

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
        if config.local_ip.is_ipv4() != config.peer_ip.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "local_ip and peer_ip must use the same address family",
            ));
        }
        if let Some(verifier) = &config.peer_verifier
            && !verifier(config.peer_public_key).await
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "WireGuard peer rejected by async verifier",
            ));
        }

        let udp = UdpSocket::bind(config.udp_bind).await?;
        let udp_addr = udp.local_addr()?;
        let mut stack = Stack::new(config.local_ip, config.peer_ip);
        stack.poll_interface();

        let inner = Arc::new(Inner {
            stack: Mutex::new(stack),
            wakers: Mutex::new(Vec::new()),
            driver_notify: Notify::new(),
            state_notify: Notify::new(),
            transport_busy: AtomicBool::new(false),
            finalised: AtomicBool::new(false),
            last_activity: Mutex::new(Instant::now()),
            peer_idle_timeout: config.peer_idle_timeout,
            udp_addr,
            local_ip: config.local_ip,
            peer_ip: config.peer_ip,
            peer_public_key: config.peer_public_key,
        });

        let tunn = Tunn::new(
            config.local_private_key,
            config.peer_public_key,
            None,
            None,
            0,
            None,
        );

        let task_inner = Arc::clone(&inner);
        let task = tokio::spawn(async move {
            run_driver(task_inner, udp, tunn, config.peer_addr).await;
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

    /// The authorized remote WireGuard public key for this context.
    pub fn peer_public_key(&self) -> PublicKey {
        self.inner.peer_public_key
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
        if remote.ip() != self.inner.peer_ip {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "remote IP must be the context peer IP {}, got {}",
                    self.inner.peer_ip, remote
                ),
            ));
        }

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
        let handle = stack.add_socket();
        if let Err(err) = stack.socket_mut(handle).listen(addr.port()) {
            stack.remove(handle);
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("cannot listen on {addr}: {err:?}"),
            ));
        }
        stack.listeners.push(handle);
        drop(stack);

        self.inner.request_driver();
        Ok(TcpListener {
            inner: Arc::clone(&self.inner),
            handle: Mutex::new(handle),
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

    fn touch(&self) {
        *lock(&self.last_activity) = Instant::now();
    }

    fn peer_timeout_delay(&self, driver_delay: Duration) -> Duration {
        let Some(timeout) = self.peer_idle_timeout else {
            return driver_delay;
        };
        let remaining = timeout.saturating_sub(lock(&self.last_activity).elapsed());
        driver_delay.min(remaining.max(Duration::from_millis(1)))
    }

    fn peer_timed_out(&self) -> bool {
        self.peer_idle_timeout
            .is_some_and(|timeout| lock(&self.last_activity).elapsed() >= timeout)
    }

    fn forget_peer(&self) {
        let mut stack = lock(&self.stack);
        let listeners = stack.listeners.clone();
        let handles: Vec<_> = stack.sockets.iter().map(|(handle, _)| handle).collect();

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
    fn new(local_ip: IpAddr, peer_ip: IpAddr) -> Self {
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

        match peer_ip {
            IpAddr::V4(peer) => {
                iface
                    .routes_mut()
                    .add_default_ipv4_route(peer)
                    .expect("default IPv4 route fits");
            }
            IpAddr::V6(peer) => {
                iface
                    .routes_mut()
                    .add_default_ipv6_route(peer)
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
        self.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ))
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
        self.inner.peer_public_key
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
    handle: Mutex<SocketHandle>,
    local_addr: SocketAddr,
    _driver: Arc<Driver>,
}

impl TcpListener {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// The authorized WireGuard identity of the expected remote peer.
    pub fn peer_public_key(&self) -> PublicKey {
        self.inner.peer_public_key
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
                let mut handle = lock(&self.handle);
                let mut stack = lock(&self.inner.stack);
                match stack.accept(*handle) {
                    Ok(Some((replacement, accepted, _local, remote))) => {
                        *handle = replacement;
                        Some((accepted, remote))
                    }
                    Ok(None) => None,
                    Err(err) => return Err(err),
                }
            };

            if let Some((accepted_handle, remote)) = accepted {
                self.inner.request_driver();
                return Ok((
                    TcpStream {
                        inner: Arc::clone(&self.inner),
                        handle: Mutex::new(accepted_handle),
                        nodelay: AtomicBool::new(false),
                        _driver: Arc::clone(&self._driver),
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
        let handle = self.handle.get_mut().unwrap_or_else(|err| err.into_inner());
        let mut stack = lock(&self.inner.stack);
        stack.listeners.retain(|listener| listener != handle);
        stack.socket_mut(*handle).abort();
        stack.remove(*handle);
    }
}

async fn run_driver(
    inner: Arc<Inner>,
    udp: UdpSocket,
    mut tunn: Tunn,
    mut peer_addr: Option<SocketAddr>,
) {
    let mut udp_buffer = vec![0; MAX_UDP_DATAGRAM];
    let mut tunnel_buffer = vec![0; MTU + 256];

    loop {
        let delay = inner.next_delay();
        let delay = if peer_addr.is_some() {
            inner.peer_timeout_delay(delay)
        } else {
            delay
        };
        let notified = inner.driver_notify.notified();
        let mut outbound = Vec::new();
        let mut inbound = Vec::new();

        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep(delay) => {}
            result = udp.recv_from(&mut udp_buffer) => {
                if let Ok((len, source)) = result {
                    let authenticated = decapsulate(
                        &mut tunn,
                        source.ip(),
                        &udp_buffer[..len],
                        &mut tunnel_buffer,
                        &mut inbound,
                        &mut outbound,
                    );
                    if authenticated {
                        peer_addr = Some(source);
                        inner.touch();
                    }
                }
            }
        }

        if inner.finalised.load(Ordering::Acquire) {
            break;
        }
        if peer_addr.is_some() && inner.peer_timed_out() {
            peer_addr = None;
            inner.forget_peer();
        }

        inner.transport_busy.store(true, Ordering::Release);

        if !inbound.is_empty() {
            let mut stack = lock(&inner.stack);
            stack.device.rx.extend(inbound.drain(..));
        }

        update_timers(&mut tunn, &mut tunnel_buffer, &mut inbound, &mut outbound);

        if !inbound.is_empty() {
            let mut stack = lock(&inner.stack);
            stack.device.rx.extend(inbound.drain(..));
        }

        let packets = inner.poll_stack();
        for packet in packets {
            encapsulate(
                &mut tunn,
                &packet,
                &mut tunnel_buffer,
                &mut inbound,
                &mut outbound,
            );
        }

        if !inbound.is_empty() {
            let mut stack = lock(&inner.stack);
            stack.device.rx.extend(inbound.drain(..));
            stack.poll_interface();
        }

        send_datagrams(&udp, peer_addr, outbound).await;

        // Encryption may reveal newly queued packets or make a TCP socket
        // readable/writable, so give API waiters another poll.
        inner.transport_busy.store(false, Ordering::Release);
        inner.wake_all();
    }
}

async fn send_datagrams(udp: &UdpSocket, peer_addr: Option<SocketAddr>, packets: Vec<Vec<u8>>) {
    let Some(peer_addr) = peer_addr else {
        return;
    };
    for packet in packets {
        let _ = udp.send_to(&packet, peer_addr).await;
    }
}

fn update_timers(
    tunn: &mut Tunn,
    buffer: &mut [u8],
    inbound: &mut Vec<Vec<u8>>,
    outbound: &mut Vec<Vec<u8>>,
) {
    match tunn.update_timers(buffer) {
        TunnResult::WriteToNetwork(packet) => outbound.push(packet.to_vec()),
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            inbound.push(packet.to_vec())
        }
        TunnResult::Done | TunnResult::Err(_) => {}
    }
}

fn encapsulate(
    tunn: &mut Tunn,
    packet: &[u8],
    buffer: &mut [u8],
    inbound: &mut Vec<Vec<u8>>,
    outbound: &mut Vec<Vec<u8>>,
) {
    match tunn.encapsulate(packet, buffer) {
        TunnResult::WriteToNetwork(packet) => outbound.push(packet.to_vec()),
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            inbound.push(packet.to_vec())
        }
        TunnResult::Done | TunnResult::Err(_) => {}
    }
}

fn decapsulate(
    tunn: &mut Tunn,
    source: IpAddr,
    datagram: &[u8],
    buffer: &mut [u8],
    inbound: &mut Vec<Vec<u8>>,
    outbound: &mut Vec<Vec<u8>>,
) -> bool {
    let mut authenticated = false;
    let mut pending = Some(datagram);

    while let Some(datagram) = pending.take() {
        match tunn.decapsulate(Some(source), datagram, buffer) {
            TunnResult::WriteToNetwork(packet) => {
                authenticated = true;
                outbound.push(packet.to_vec());
                pending = Some(&[]);
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                authenticated = true;
                inbound.push(packet.to_vec());
                pending = Some(&[]);
            }
            TunnResult::Done => break,
            TunnResult::Err(_) => break,
        }
    }
    authenticated
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
