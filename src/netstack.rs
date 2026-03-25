use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use parking_lot::Mutex;
use rand::Rng;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
    UdpMetadata,
};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::tunnel::WireGuardTunnel;

const TCP_BUFFER_SIZE: usize = 64 * 1024;
const UDP_BUFFER_SIZE: usize = 64 * 1024;
const UDP_METADATA_SLOTS: usize = 32;
const EPHEMERAL_PORT_MIN: u16 = 49_152;
const EPHEMERAL_PORT_MAX: u16 = 65_535;
const NETSTACK_IDLE_POLL_FALLBACK: Duration = Duration::from_millis(250);
const NETSTACK_MIN_POLL_SLEEP: Duration = Duration::from_millis(1);

#[derive(Debug, Error)]
pub enum NetstackError {
    #[error("IPv6 targets are not supported in v1")]
    Ipv6NotSupported,
    #[error("TCP connect failed: {0}")]
    TcpConnect(String),
    #[error("TCP connect timed out")]
    TcpConnectTimeout,
    #[error("TCP read timed out")]
    TcpReadTimeout,
    #[error("TCP write timed out")]
    TcpWriteTimeout,
    #[error("UDP send timed out")]
    UdpSendTimeout,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("UDP bind failed: {0}")]
    UdpBind(String),
    #[error("UDP send failed: {0}")]
    UdpSend(String),
    #[error("UDP receive failed: {0}")]
    UdpRecv(String),
}

type Result<T> = std::result::Result<T, NetstackError>;

struct VirtualDevice {
    rx_queue: VecDeque<BytesMut>,
    tx_queue: VecDeque<BytesMut>,
    mtu: usize,
}

impl VirtualDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    fn push_rx(&mut self, packet: BytesMut) {
        self.rx_queue.push_back(packet);
    }

    fn drain_tx(&mut self) -> Vec<BytesMut> {
        self.tx_queue.drain(..).collect()
    }
}

struct VirtualRxToken {
    buffer: BytesMut,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<BytesMut>,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = BytesMut::zeroed(len);
        let result = f(&mut buffer);
        self.tx_queue.push_back(buffer);
        result
    }

    fn set_meta(&mut self, _meta: smoltcp::phy::PacketMeta) {}
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(|buffer| {
            (
                VirtualRxToken { buffer },
                VirtualTxToken {
                    tx_queue: &mut self.tx_queue,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct NetStackInner {
    interface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
}

pub struct NetStack {
    inner: Mutex<NetStackInner>,
    wg_tunnel: Arc<WireGuardTunnel>,
    wg_tx: mpsc::Sender<BytesMut>,
}

impl NetStack {
    pub fn new(wg_tunnel: Arc<WireGuardTunnel>) -> Arc<Self> {
        let mtu = wg_tunnel.mtu() as usize;
        let local_ip = wg_tunnel.tunnel_ip();
        let wg_tx = wg_tunnel.outgoing_sender();

        let mut device = VirtualDevice::new(mtu);
        let config = Config::new(HardwareAddress::Ip);
        let mut interface = Interface::new(config, &mut device, Instant::now());
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(local_ip), 32))
                .expect("failed to add local tunnel address");
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::UNSPECIFIED)
            .expect("failed to add default route");

        tracing::debug!(local_ip = %local_ip, mtu, "initialized userspace netstack");

        Arc::new(Self {
            inner: Mutex::new(NetStackInner {
                interface,
                device,
                sockets: SocketSet::new(Vec::new()),
            }),
            wg_tunnel,
            wg_tx,
        })
    }

    fn local_ip(&self) -> Ipv4Addr {
        self.wg_tunnel.tunnel_ip()
    }

    pub fn poll(&self) -> bool {
        let mut inner = self.inner.lock();
        let timestamp = Instant::now();
        let NetStackInner {
            interface,
            device,
            sockets,
        } = &mut *inner;

        let changed = interface.poll(timestamp, device, sockets) != PollResult::None;
        let packets = device.drain_tx();
        drop(inner);

        for packet in packets {
            let tx = self.wg_tx.clone();
            tokio::spawn(async move {
                if let Err(error) = tx.send(packet).await {
                    tracing::error!("failed to queue packet for WireGuard: {error}");
                }
            });
        }

        changed
    }

    pub fn push_rx_packet(&self, packet: BytesMut) {
        let mut inner = self.inner.lock();
        inner.device.push_rx(packet);
    }

    fn next_poll_sleep(&self) -> Duration {
        let mut inner = self.inner.lock();
        let now = Instant::now();
        let NetStackInner {
            interface, sockets, ..
        } = &mut *inner;
        let delay = interface.poll_delay(now, sockets);
        match delay {
            Some(delay) => {
                let millis = delay.total_millis();
                if millis == 0 {
                    NETSTACK_MIN_POLL_SLEEP
                } else {
                    Duration::from_millis(millis)
                }
            }
            None => NETSTACK_IDLE_POLL_FALLBACK,
        }
    }

    pub async fn run_poll_loop(self: &Arc<Self>) -> anyhow::Result<()> {
        tracing::debug!("starting netstack poll loop");
        loop {
            self.poll();
            tokio::time::sleep(self.next_poll_sleep()).await;
        }
    }

    pub async fn run_rx_loop(
        self: &Arc<Self>,
        mut rx: mpsc::Receiver<BytesMut>,
    ) -> anyhow::Result<()> {
        tracing::debug!("starting netstack receive loop");
        while let Some(packet) = rx.recv().await {
            self.push_rx_packet(packet);
            self.poll();
        }
        Ok(())
    }

    pub fn create_tcp_socket(&self) -> SocketHandle {
        let mut inner = self.inner.lock();
        let rx = TcpSocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let tx = TcpSocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let handle = inner.sockets.add(TcpSocket::new(rx, tx));
        tracing::debug!(?handle, "created virtual TCP socket");
        handle
    }

    pub fn connect_tcp(&self, handle: SocketHandle, addr: SocketAddr) -> Result<()> {
        let remote = match addr {
            SocketAddr::V4(v4) => {
                smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port())
            }
            SocketAddr::V6(_) => return Err(NetstackError::Ipv6NotSupported),
        };

        let local_port = random_ephemeral_port();
        let local = smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(self.local_ip()), local_port);

        let mut inner = self.inner.lock();
        let NetStackInner {
            interface, sockets, ..
        } = &mut *inner;
        let cx = interface.context();
        let socket = sockets.get_mut::<TcpSocket>(handle);
        tracing::debug!(
            ?handle,
            local_ip = %self.local_ip(),
            local_port,
            remote = %addr,
            "connecting virtual TCP socket"
        );
        socket
            .connect(cx, remote, local)
            .map_err(|error| NetstackError::TcpConnect(error.to_string()))
    }

    pub fn tcp_state(&self, handle: SocketHandle) -> TcpState {
        let inner = self.inner.lock();
        inner.sockets.get::<TcpSocket>(handle).state()
    }

    pub fn tcp_can_send(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        inner.sockets.get::<TcpSocket>(handle).can_send()
    }

    pub fn tcp_can_recv(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        inner.sockets.get::<TcpSocket>(handle).can_recv()
    }

    pub fn tcp_may_send(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        inner.sockets.get::<TcpSocket>(handle).may_send()
    }

    pub fn tcp_may_recv(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        inner.sockets.get::<TcpSocket>(handle).may_recv()
    }

    pub fn tcp_send(&self, handle: SocketHandle, data: &[u8]) -> Result<usize> {
        let mut inner = self.inner.lock();
        inner
            .sockets
            .get_mut::<TcpSocket>(handle)
            .send_slice(data)
            .map_err(|error| NetstackError::TcpConnect(error.to_string()))
    }

    pub fn tcp_recv(&self, handle: SocketHandle, buffer: &mut [u8]) -> Result<usize> {
        let mut inner = self.inner.lock();
        inner
            .sockets
            .get_mut::<TcpSocket>(handle)
            .recv_slice(buffer)
            .map_err(|error| NetstackError::TcpConnect(error.to_string()))
    }

    pub fn close_tcp(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock();
        tracing::debug!(?handle, "closing virtual TCP socket");
        inner.sockets.get_mut::<TcpSocket>(handle).close();
    }

    pub fn remove_socket(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock();
        tracing::debug!(?handle, "removing virtual socket");
        inner.sockets.remove(handle);
    }

    pub fn create_udp_socket(&self, local_port: Option<u16>) -> Result<(SocketHandle, u16)> {
        let mut inner = self.inner.lock();
        for _ in 0..128 {
            let port = local_port.unwrap_or_else(random_ephemeral_port);
            let rx_meta = vec![UdpPacketMetadata::EMPTY; UDP_METADATA_SLOTS];
            let tx_meta = vec![UdpPacketMetadata::EMPTY; UDP_METADATA_SLOTS];
            let rx_data = vec![0u8; UDP_BUFFER_SIZE];
            let tx_data = vec![0u8; UDP_BUFFER_SIZE];
            let rx = UdpPacketBuffer::new(rx_meta, rx_data);
            let tx = UdpPacketBuffer::new(tx_meta, tx_data);
            let mut socket = UdpSocket::new(rx, tx);
            match socket.bind((IpAddress::Ipv4(self.local_ip()), port)) {
                Ok(()) => {
                    let handle = inner.sockets.add(socket);
                    tracing::debug!(?handle, local_ip = %self.local_ip(), local_port = port, "created virtual UDP socket");
                    return Ok((handle, port));
                }
                Err(error) if local_port.is_some() => {
                    return Err(NetstackError::UdpBind(error.to_string()));
                }
                Err(_) => {}
            }
        }

        Err(NetstackError::UdpBind(
            "failed to allocate an ephemeral UDP port".into(),
        ))
    }

    pub fn udp_can_send(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        inner.sockets.get::<UdpSocket>(handle).can_send()
    }

    pub fn udp_can_recv(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        inner.sockets.get::<UdpSocket>(handle).can_recv()
    }

    pub fn udp_send_to(
        &self,
        handle: SocketHandle,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<usize> {
        let remote = match addr {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => return Err(NetstackError::Ipv6NotSupported),
        };

        let mut inner = self.inner.lock();
        inner
            .sockets
            .get_mut::<UdpSocket>(handle)
            .send_slice(data, UdpMetadata::from(remote))
            .map_err(|error| NetstackError::UdpSend(error.to_string()))?;
        Ok(data.len())
    }

    pub fn udp_recv_from(
        &self,
        handle: SocketHandle,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddrV4)> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<UdpSocket>(handle);
        let (payload, metadata) = socket
            .recv()
            .map_err(|error| NetstackError::UdpRecv(error.to_string()))?;
        let size = payload.len().min(buffer.len());
        buffer[..size].copy_from_slice(&payload[..size]);
        let endpoint = metadata.endpoint;
        let address = match endpoint.addr {
            IpAddress::Ipv4(ip) => SocketAddrV4::new(ip, endpoint.port),
        };
        Ok((size, address))
    }
}

fn random_ephemeral_port() -> u16 {
    rand::thread_rng().gen_range(EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX)
}

pub struct TcpConnection {
    netstack: Arc<NetStack>,
    handle: SocketHandle,
}

impl TcpConnection {
    pub async fn connect(netstack: Arc<NetStack>, addr: SocketAddr) -> Result<Self> {
        let handle = netstack.create_tcp_socket();
        netstack.connect_tcp(handle, addr)?;
        tracing::debug!(?handle, remote = %addr, "waiting for virtual TCP connection establishment");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            netstack.poll();
            let state = netstack.tcp_state(handle);
            if state == TcpState::Established {
                tracing::info!(?handle, remote = %addr, "virtual TCP connection established");
                return Ok(Self { netstack, handle });
            }
            if matches!(
                state,
                TcpState::Closed | TcpState::Closing | TcpState::TimeWait
            ) {
                tracing::debug!(?handle, remote = %addr, state = ?state, "virtual TCP connection failed");
                netstack.remove_socket(handle);
                return Err(NetstackError::TcpConnect(format!(
                    "connection failed in state {state:?}"
                )));
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::debug!(?handle, remote = %addr, "virtual TCP connection timed out");
                netstack.remove_socket(handle);
                return Err(NetstackError::TcpConnectTimeout);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            self.netstack.poll();
            if self.netstack.tcp_can_recv(self.handle) {
                return self.netstack.tcp_recv(self.handle, buffer);
            }
            if !self.netstack.tcp_may_recv(self.handle) {
                return Ok(0);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetstackError::TcpReadTimeout);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    pub async fn write_all(&self, data: &[u8]) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut written = 0usize;

        while written < data.len() {
            self.netstack.poll();
            if self.netstack.tcp_can_send(self.handle) {
                written += self.netstack.tcp_send(self.handle, &data[written..])?;
            }
            if !self.netstack.tcp_may_send(self.handle) {
                return Err(NetstackError::ConnectionClosed);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetstackError::TcpWriteTimeout);
            }
            if written < data.len() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        self.netstack.poll();
        Ok(())
    }

    pub fn shutdown(&self) {
        self.netstack.close_tcp(self.handle);
        self.netstack.poll();
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        self.netstack.close_tcp(self.handle);
        self.netstack.poll();
    }
}

#[derive(Clone)]
pub struct VirtualUdpSocket {
    netstack: Arc<NetStack>,
    handle: SocketHandle,
}

impl VirtualUdpSocket {
    pub fn bind(netstack: Arc<NetStack>, local_port: Option<u16>) -> Result<Self> {
        let (handle, _) = netstack.create_udp_socket(local_port)?;
        tracing::debug!(?handle, requested_port = ?local_port, "bound virtual UDP socket");
        Ok(Self { netstack, handle })
    }

    pub async fn send_to(&self, addr: SocketAddr, data: &[u8]) -> Result<usize> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            self.netstack.poll();
            if self.netstack.udp_can_send(self.handle) {
                let written = self.netstack.udp_send_to(self.handle, addr, data)?;
                self.netstack.poll();
                return Ok(written);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetstackError::UdpSendTimeout);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    pub async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddrV4)> {
        loop {
            self.netstack.poll();
            if self.netstack.udp_can_recv(self.handle) {
                return self.netstack.udp_recv_from(self.handle, buffer);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

impl Drop for VirtualUdpSocket {
    fn drop(&mut self) {
        self.netstack.remove_socket(self.handle);
    }
}
