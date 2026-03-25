use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::Packet;
use gotatun::x25519::{PublicKey, StaticSecret};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::task::JoinSet;
use zerocopy::IntoBytes;

use crate::config::TunnelConfig;
use crate::netstack::NetStack;

const CHANNEL_CAPACITY: usize = 256;
const MAX_UDP_PACKET: usize = 65_535;

pub struct WireGuardTunnel {
    tunn: Mutex<Tunn>,
    udp_socket: Arc<UdpSocket>,
    peer_endpoint: SocketAddrV4,
    tunnel_ip: Ipv4Addr,
    mtu: u16,
    incoming_tx: mpsc::Sender<BytesMut>,
    incoming_rx: Mutex<Option<mpsc::Receiver<BytesMut>>>,
    outgoing_tx: mpsc::Sender<BytesMut>,
    outgoing_rx: AsyncMutex<mpsc::Receiver<BytesMut>>,
}

impl WireGuardTunnel {
    pub async fn new(config: TunnelConfig) -> Result<Arc<Self>> {
        let private_key = StaticSecret::from(config.private_key);
        let peer_public_key = PublicKey::from(config.peer_public_key);
        let rate_limiter = Arc::new(RateLimiter::new(&peer_public_key, 0));
        let tunn = Tunn::new_with_reserved(
            private_key,
            peer_public_key,
            config.preshared_key,
            config.persistent_keepalive,
            rand::random::<u32>() >> 8,
            rate_limiter,
            config.reserved_bytes,
        );

        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.listen_port.unwrap_or(0));
        let udp_socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind WireGuard UDP socket on {}", bind_addr))?;
        let local_addr = udp_socket
            .local_addr()
            .context("failed to read WireGuard local UDP socket address")?;

        let (incoming_tx, incoming_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(CHANNEL_CAPACITY);

        tracing::info!(
            local_addr = %local_addr,
            peer_endpoint = %config.peer_endpoint,
            tunnel_ip = %config.tunnel_ip,
            mtu = config.mtu,
            keepalive = ?config.persistent_keepalive,
            reserved = ?config.reserved_bytes,
            "initialized WireGuard tunnel transport"
        );

        Ok(Arc::new(Self {
            tunn: Mutex::new(tunn),
            udp_socket: Arc::new(udp_socket),
            peer_endpoint: config.peer_endpoint,
            tunnel_ip: config.tunnel_ip,
            mtu: config.mtu,
            incoming_tx,
            incoming_rx: Mutex::new(Some(incoming_rx)),
            outgoing_tx,
            outgoing_rx: AsyncMutex::new(outgoing_rx),
        }))
    }

    pub fn tunnel_ip(&self) -> Ipv4Addr {
        self.tunnel_ip
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn outgoing_sender(&self) -> mpsc::Sender<BytesMut> {
        self.outgoing_tx.clone()
    }

    pub fn take_incoming_receiver(&self) -> Option<mpsc::Receiver<BytesMut>> {
        self.incoming_rx.lock().take()
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let tunn = self.tunn.lock();
        tunn.stats().0
    }

    pub async fn initiate_handshake(&self) -> Result<()> {
        tracing::debug!(peer_endpoint = %self.peer_endpoint, "initiating WireGuard handshake");
        let packet = {
            let mut tunn = self.tunn.lock();
            tunn.format_handshake_initiation(false)
        };

        if let Some(packet) = packet {
            self.udp_socket
                .send_to(packet.as_bytes(), self.peer_endpoint)
                .await
                .context("failed to send WireGuard handshake")?;
        }

        Ok(())
    }

    pub async fn wait_for_handshake(&self, timeout_duration: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        tracing::debug!(timeout = ?timeout_duration, "waiting for WireGuard handshake");
        loop {
            if self.time_since_last_handshake().is_some() {
                tracing::debug!(elapsed = ?start.elapsed(), "WireGuard handshake observed");
                return Ok(());
            }

            if start.elapsed() >= timeout_duration {
                return Err(anyhow!("timed out waiting for WireGuard handshake"));
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub async fn send_ip_packet(&self, packet: BytesMut) -> Result<()> {
        tracing::trace!(
            size = packet.len(),
            "sending IP packet through WireGuard tunnel"
        );
        let encrypted = {
            let mut tunn = self.tunn.lock();
            let packet = Packet::from_bytes(packet);
            tunn.handle_outgoing_packet(packet)
        };

        if let Some(packet) = encrypted {
            let packet: Packet = packet.into();
            self.udp_socket
                .send_to(packet.as_bytes(), self.peer_endpoint)
                .await
                .context("failed to send encrypted WireGuard packet")?;
        }

        Ok(())
    }

    fn process_incoming_udp(&self, data: &[u8]) -> Option<BytesMut> {
        let packet = Packet::from_bytes(BytesMut::from(data));
        let packet = match packet.try_into_wg() {
            Ok(packet) => packet,
            Err(error) => {
                tracing::debug!("discarding non-WireGuard packet: {error}");
                return None;
            }
        };

        let mut tunn = self.tunn.lock();
        match tunn.handle_incoming_packet(packet) {
            TunnResult::Done => None,
            TunnResult::Err(error) => {
                tracing::debug!("WireGuard packet handling error: {error:?}");
                None
            }
            TunnResult::WriteToNetwork(response) => {
                let packet: Packet = response.into();
                let bytes = BytesMut::from(packet.as_bytes());
                let socket = self.udp_socket.clone();
                let peer_endpoint = self.peer_endpoint;
                tokio::spawn(async move {
                    if let Err(error) = socket.send_to(&bytes, peer_endpoint).await {
                        tracing::error!("failed to send WireGuard response packet: {error}");
                    }
                });

                for queued in tunn.get_queued_packets() {
                    let packet: Packet = queued.into();
                    let bytes = BytesMut::from(packet.as_bytes());
                    let socket = self.udp_socket.clone();
                    let peer_endpoint = self.peer_endpoint;
                    tokio::spawn(async move {
                        if let Err(error) = socket.send_to(&bytes, peer_endpoint).await {
                            tracing::error!("failed to send queued WireGuard packet: {error}");
                        }
                    });
                }

                None
            }
            TunnResult::WriteToTunnel(packet) => Some(BytesMut::from(packet.as_bytes())),
        }
    }

    pub async fn run_receive_loop(self: &Arc<Self>) -> Result<()> {
        let mut buffer = vec![0u8; MAX_UDP_PACKET];
        tracing::debug!(peer_endpoint = %self.peer_endpoint, "starting WireGuard receive loop");

        loop {
            let (size, from) = self
                .udp_socket
                .recv_from(&mut buffer)
                .await
                .context("failed to receive WireGuard UDP packet")?;

            if from != SocketAddr::V4(self.peer_endpoint) {
                tracing::debug!("ignoring packet from unexpected peer {from}");
                continue;
            }

            tracing::trace!(size, from = %from, "received WireGuard UDP packet");

            if let Some(packet) = self.process_incoming_udp(&buffer[..size]) {
                if self.incoming_tx.send(packet).await.is_err() {
                    return Err(anyhow!("incoming WireGuard channel closed"));
                }
            }
        }
    }

    pub async fn run_send_loop(self: &Arc<Self>) -> Result<()> {
        let mut rx = self.outgoing_rx.lock().await;
        tracing::debug!(peer_endpoint = %self.peer_endpoint, "starting WireGuard send loop");
        while let Some(packet) = rx.recv().await {
            self.send_ip_packet(packet).await?;
        }
        Ok(())
    }

    pub async fn run_timer_loop(self: &Arc<Self>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        tracing::debug!("starting WireGuard timer loop");

        loop {
            interval.tick().await;

            let packets = {
                let mut tunn = self.tunn.lock();
                match tunn.update_timers() {
                    Ok(Some(packet)) => {
                        let packet: Packet = packet.into();
                        vec![BytesMut::from(packet.as_bytes())]
                    }
                    Ok(None) => Vec::new(),
                    Err(error) => {
                        tracing::debug!("WireGuard timer update returned {error:?}");
                        Vec::new()
                    }
                }
            };

            for packet in packets {
                self.udp_socket
                    .send_to(&packet, self.peer_endpoint)
                    .await
                    .context("failed to send WireGuard timer packet")?;
            }
        }
    }
}

pub struct ManagedTunnel {
    wg_tunnel: Arc<WireGuardTunnel>,
    netstack: Arc<NetStack>,
    tasks: JoinSet<()>,
}

impl ManagedTunnel {
    pub async fn connect(config: TunnelConfig) -> Result<Self> {
        tracing::info!(
            endpoint = %config.peer_endpoint,
            tunnel_ip = %config.tunnel_ip,
            mtu = config.mtu,
            "bringing up managed WireGuard tunnel"
        );
        let wg_tunnel = WireGuardTunnel::new(config).await?;
        let incoming_rx = wg_tunnel
            .take_incoming_receiver()
            .ok_or_else(|| anyhow!("failed to acquire WireGuard incoming receiver"))?;
        let netstack = NetStack::new(wg_tunnel.clone());

        let mut tasks = JoinSet::new();

        {
            let wg = wg_tunnel.clone();
            tasks.spawn(async move {
                if let Err(error) = wg.run_receive_loop().await {
                    tracing::error!("WireGuard receive loop stopped: {error:#}");
                }
            });
        }

        {
            let wg = wg_tunnel.clone();
            tasks.spawn(async move {
                if let Err(error) = wg.run_send_loop().await {
                    tracing::error!("WireGuard send loop stopped: {error:#}");
                }
            });
        }

        {
            let wg = wg_tunnel.clone();
            tasks.spawn(async move {
                if let Err(error) = wg.run_timer_loop().await {
                    tracing::error!("WireGuard timer loop stopped: {error:#}");
                }
            });
        }

        {
            let netstack_clone = netstack.clone();
            tasks.spawn(async move {
                if let Err(error) = netstack_clone.run_poll_loop().await {
                    tracing::error!("netstack poll loop stopped: {error:#}");
                }
            });
        }

        {
            let netstack_clone = netstack.clone();
            tasks.spawn(async move {
                if let Err(error) = netstack_clone.run_rx_loop(incoming_rx).await {
                    tracing::error!("netstack rx loop stopped: {error:#}");
                }
            });
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        wg_tunnel.initiate_handshake().await?;
        wg_tunnel
            .wait_for_handshake(Duration::from_secs(10))
            .await?;

        tracing::info!("managed WireGuard tunnel is ready");

        Ok(Self {
            wg_tunnel,
            netstack,
            tasks,
        })
    }

    pub fn netstack(&self) -> Arc<NetStack> {
        self.netstack.clone()
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.wg_tunnel.time_since_last_handshake()
    }

    pub async fn shutdown(mut self) {
        tracing::info!("shutting down managed WireGuard tunnel");
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

impl Drop for ManagedTunnel {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}
