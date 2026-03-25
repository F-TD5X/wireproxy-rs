use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use fast_socks5::server::{self, Socks5ServerProtocol};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{new_udp_header, parse_udp_request, ReplyError, Socks5Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::cli::SocksAuth;
use crate::dns::DnsResolver;
use crate::netstack::{NetStack, NetstackError, TcpConnection, VirtualUdpSocket};

#[derive(Clone)]
pub struct SocksServer {
    bind_addr: String,
    auth: SocksAuth,
    netstack: Arc<NetStack>,
    resolver: DnsResolver,
}

impl SocksServer {
    pub fn new(
        bind_addr: String,
        auth: SocksAuth,
        netstack: Arc<NetStack>,
        resolver: DnsResolver,
    ) -> Self {
        Self {
            bind_addr,
            auth,
            netstack,
            resolver,
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .with_context(|| format!("failed to bind SOCKS5 listener on {}", self.bind_addr))?;
        tracing::info!(
            bind_addr = %listener.local_addr()?,
            auth = %auth_mode_label(&self.auth),
            "SOCKS5 server listening"
        );

        loop {
            let (stream, peer_addr) = listener.accept().await.context("failed to accept client")?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(error) = server.handle_client(stream).await {
                    tracing::error!("SOCKS5 client {} failed: {error:#}", peer_addr);
                }
            });
        }
    }

    async fn handle_client(&self, stream: TcpStream) -> Result<()> {
        let peer_addr = stream
            .peer_addr()
            .context("failed to read client peer address")?;
        let local_addr = stream
            .local_addr()
            .context("failed to read local socket address")?;
        tracing::info!(
            client = %peer_addr,
            local_addr = %local_addr,
            auth = %auth_mode_label(&self.auth),
            "accepted SOCKS5 client"
        );
        let proto = match &self.auth {
            SocksAuth::None => Socks5ServerProtocol::accept_no_auth(stream)
                .await
                .context("SOCKS auth negotiation failed")?,
            SocksAuth::Password { username, password } => {
                let username = username.clone();
                let password = password.clone();
                let (proto, _) =
                    Socks5ServerProtocol::accept_password_auth(stream, move |user, pass| {
                        user == username && pass == password
                    })
                    .await
                    .context("SOCKS password authentication failed")?;
                proto
            }
        };

        let (proto, command, target) = proto
            .read_command()
            .await
            .context("failed to read SOCKS command")?;
        tracing::info!(
            client = %peer_addr,
            command = %command_label(&command),
            target = %target,
            "received SOCKS5 command"
        );
        match command {
            Socks5Command::TCPConnect => {
                self.handle_tcp_connect(proto, target, local_addr, peer_addr)
                    .await?;
            }
            Socks5Command::UDPAssociate => {
                self.handle_udp_associate(proto, local_addr, peer_addr)
                    .await?;
            }
            Socks5Command::TCPBind => {
                tracing::warn!(client = %peer_addr, "client requested unsupported SOCKS5 BIND command");
                proto.reply_error(&ReplyError::CommandNotSupported).await?;
            }
        }

        tracing::info!(client = %peer_addr, "SOCKS5 client session completed");
        Ok(())
    }

    async fn handle_tcp_connect(
        &self,
        proto: Socks5ServerProtocol<TcpStream, server::states::CommandRead>,
        target: TargetAddr,
        local_addr: SocketAddr,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let requested_target = target_to_string(&target);
        let remote_addr = match self.resolve_target(target).await {
            Ok(remote_addr) => remote_addr,
            Err(reply) => {
                tracing::warn!(
                    client = %client_addr,
                    target = %requested_target,
                    reply = ?reply,
                    "failed to resolve SOCKS TCP target"
                );
                proto.reply_error(&reply).await?;
                return Ok(());
            }
        };

        tracing::info!(client = %client_addr, remote = %remote_addr, "opening SOCKS TCP tunnel");

        let connection = match TcpConnection::connect(self.netstack.clone(), remote_addr).await {
            Ok(connection) => Arc::new(connection),
            Err(error) => {
                tracing::warn!(
                    client = %client_addr,
                    remote = %remote_addr,
                    error = %error,
                    "failed to establish upstream TCP connection"
                );
                proto.reply_error(&map_netstack_error(&error)).await?;
                return Ok(());
            }
        };

        let reply_addr = SocketAddr::new(local_addr.ip(), 0);
        let stream = proto.reply_success(reply_addr).await?;
        let (mut client_reader, mut client_writer) = tokio::io::split(stream);
        let uploaded_bytes = Arc::new(AtomicU64::new(0));
        let downloaded_bytes = Arc::new(AtomicU64::new(0));

        let upstream = connection.clone();
        let uploaded_bytes_task = uploaded_bytes.clone();
        let client_to_remote = tokio::spawn(async move {
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let read = client_reader.read(&mut buffer).await?;
                if read == 0 {
                    upstream.shutdown();
                    return Ok::<(), anyhow::Error>(());
                }
                uploaded_bytes_task.fetch_add(read as u64, Ordering::Relaxed);
                upstream
                    .write_all(&buffer[..read])
                    .await
                    .map_err(anyhow::Error::new)?;
            }
        });

        let mut remote_buffer = [0u8; 16 * 1024];
        loop {
            let read = connection
                .read(&mut remote_buffer)
                .await
                .map_err(anyhow::Error::new)?;
            if read == 0 {
                break;
            }
            downloaded_bytes.fetch_add(read as u64, Ordering::Relaxed);
            client_writer
                .write_all(&remote_buffer[..read])
                .await
                .context("failed to write proxied TCP data to client")?;
            client_writer.flush().await?;
        }

        connection.shutdown();
        let _ = client_to_remote.await;
        tracing::info!(
            client = %client_addr,
            remote = %remote_addr,
            uploaded_bytes = uploaded_bytes.load(Ordering::Relaxed),
            downloaded_bytes = downloaded_bytes.load(Ordering::Relaxed),
            "closed SOCKS TCP tunnel"
        );
        Ok(())
    }

    async fn handle_udp_associate(
        &self,
        proto: Socks5ServerProtocol<TcpStream, server::states::CommandRead>,
        local_addr: SocketAddr,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let client_udp = Arc::new(
            UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0))
                .await
                .context("failed to bind local SOCKS UDP relay socket")?,
        );
        let udp_reply_addr = client_udp.local_addr()?;
        let mut control_stream = proto.reply_success(udp_reply_addr).await?;
        tracing::info!(
            client = %client_addr,
            relay = %udp_reply_addr,
            "opened SOCKS UDP associate relay"
        );

        let remote_udp = Arc::new(
            VirtualUdpSocket::bind(self.netstack.clone(), None).map_err(anyhow::Error::new)?,
        );
        let resolver = self.resolver.clone();
        let client_peer = Arc::new(tokio::sync::Mutex::new(None::<SocketAddr>));

        let client_task = {
            let client_udp = client_udp.clone();
            let remote_udp = remote_udp.clone();
            let client_peer = client_peer.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 65_535];
                loop {
                    let (size, peer_addr) = client_udp.recv_from(&mut buffer).await?;
                    {
                        let mut current = client_peer.lock().await;
                        match *current {
                            None => {
                                tracing::debug!(
                                    client = %client_addr,
                                    udp_peer = %peer_addr,
                                    "bound SOCKS UDP relay to first client UDP peer"
                                );
                                *current = Some(peer_addr)
                            }
                            Some(existing) if existing != peer_addr => continue,
                            Some(_) => {}
                        }
                    }

                    let (fragment, target, payload) = parse_udp_request(&buffer[..size])
                        .await
                        .map_err(anyhow::Error::new)?;
                    if fragment != 0 {
                        tracing::debug!(
                            client = %client_addr,
                            udp_peer = %peer_addr,
                            fragment,
                            "dropping fragmented SOCKS UDP datagram"
                        );
                        continue;
                    }

                    let remote_addr = match resolve_target_with(&resolver, target).await {
                        Ok(remote_addr) => remote_addr,
                        Err(error) => {
                            tracing::debug!(
                                client = %client_addr,
                                udp_peer = %peer_addr,
                                error = %error,
                                "dropping UDP datagram due to unresolved target"
                            );
                            continue;
                        }
                    };

                    tracing::debug!(
                        client = %client_addr,
                        udp_peer = %peer_addr,
                        remote = %remote_addr,
                        size = payload.len(),
                        "forwarding UDP payload through tunnel"
                    );
                    remote_udp
                        .send_to(remote_addr, payload)
                        .await
                        .map_err(anyhow::Error::new)?;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            })
        };

        let remote_task = {
            let client_udp = client_udp.clone();
            let remote_udp = remote_udp.clone();
            let client_peer = client_peer.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 65_535];
                loop {
                    let (size, from) = remote_udp
                        .recv_from(&mut buffer)
                        .await
                        .map_err(anyhow::Error::new)?;
                    let peer = {
                        let current = client_peer.lock().await;
                        *current
                    };
                    let Some(peer) = peer else {
                        continue;
                    };

                    let mut packet = new_udp_header(from).map_err(anyhow::Error::new)?;
                    packet.extend_from_slice(&buffer[..size]);
                    tracing::debug!(
                        client = %client_addr,
                        remote = %from,
                        udp_peer = %peer,
                        size,
                        "sending UDP payload back to SOCKS client"
                    );
                    client_udp
                        .send_to(&packet, peer)
                        .await
                        .context("failed to send UDP reply to SOCKS client")?;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            })
        };

        let control_task = tokio::spawn(async move {
            let _ = server::wait_on_tcp(&mut control_stream).await;
        });

        let mut client_task = client_task;
        let mut remote_task = remote_task;
        let mut control_task = control_task;
        tokio::select! {
            result = &mut client_task => {
                flatten_task_result(result)?;
            }
            result = &mut remote_task => {
                flatten_task_result(result)?;
            }
            _ = &mut control_task => {}
        }

        client_task.abort();
        remote_task.abort();
        control_task.abort();

        tracing::info!(
            client = %client_addr,
            relay = %udp_reply_addr,
            "closed SOCKS UDP associate relay"
        );

        Ok(())
    }

    async fn resolve_target(
        &self,
        target: TargetAddr,
    ) -> std::result::Result<SocketAddr, ReplyError> {
        resolve_target_with(&self.resolver, target).await
    }
}

async fn resolve_target_with(
    resolver: &DnsResolver,
    target: TargetAddr,
) -> std::result::Result<SocketAddr, ReplyError> {
    match target {
        TargetAddr::Ip(addr) => Ok(addr),
        TargetAddr::Domain(domain, port) => {
            let ip = resolver
                .resolve_ip(&domain)
                .await
                .map_err(|_| ReplyError::HostUnreachable)?;
            tracing::debug!(domain = %domain, resolved_ip = %ip, port, "resolved SOCKS target domain");
            Ok(SocketAddr::new(ip, port))
        }
    }
}

fn map_netstack_error(error: &NetstackError) -> ReplyError {
    match error {
        NetstackError::TcpConnect(_)
        | NetstackError::TcpConnectTimeout
        | NetstackError::UdpSendTimeout => ReplyError::HostUnreachable,
        NetstackError::ConnectionClosed
        | NetstackError::UdpBind(_)
        | NetstackError::UdpSend(_)
        | NetstackError::UdpRecv(_)
        | NetstackError::TcpReadTimeout
        | NetstackError::TcpWriteTimeout => ReplyError::GeneralFailure,
    }
}

fn flatten_task_result(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(inner) => inner,
        Err(error) => Err(anyhow::Error::new(error)),
    }
}

fn auth_mode_label(auth: &SocksAuth) -> &'static str {
    match auth {
        SocksAuth::None => "none",
        SocksAuth::Password { .. } => "password",
    }
}

fn command_label(command: &Socks5Command) -> &'static str {
    match command {
        Socks5Command::TCPConnect => "CONNECT",
        Socks5Command::TCPBind => "BIND",
        Socks5Command::UDPAssociate => "UDP_ASSOCIATE",
    }
}

fn target_to_string(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Ip(addr) => addr.to_string(),
        TargetAddr::Domain(domain, port) => format!("{domain}:{port}"),
    }
}
