mod cli;
mod config;
mod dns;
mod netstack;
mod socks;
mod tunnel;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::Cli;
use crate::config::WgConfigFile;
use crate::dns::DnsResolver;
use crate::socks::SocksServer;
use crate::tunnel::ManagedTunnel;

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let cli = Cli::parse();
    let socks_auth = cli.socks_auth()?;
    let wg_config = WgConfigFile::load(&cli.config)?;
    let tunnel_config = wg_config.resolve().await?;
    let dns_server = tunnel_config.dns_server;

    tracing::info!(
        socks_bind = %cli.socks_bind(),
        config = %cli.config.display(),
        auth = cli.socks_auth_label(),
        tunnel_ip = %tunnel_config.tunnel_ip,
        endpoint = %tunnel_config.peer_endpoint,
        mtu = tunnel_config.mtu,
        dns = ?dns_server,
        reserved = ?tunnel_config.reserved_bytes,
        "starting WireGuard SOCKS proxy"
    );

    let tunnel = ManagedTunnel::connect(tunnel_config)
        .await
        .context("failed to establish WireGuard tunnel")?;
    if let Some(age) = tunnel.time_since_last_handshake() {
        tracing::info!(elapsed = ?age, "WireGuard tunnel established");
    }

    let resolver = DnsResolver::new(tunnel.netstack(), dns_server);
    if !resolver.has_server() {
        tracing::warn!("No [Interface] DNS server configured; SOCKS domain targets will fail");
    }

    let server = SocksServer::new(cli.socks_bind(), socks_auth, tunnel.netstack(), resolver);

    tokio::select! {
        result = server.run() => {
            result?;
        }
        ctrl_c = tokio::signal::ctrl_c() => {
            ctrl_c.context("failed to wait for ctrl-c")?;
            tracing::info!("received ctrl-c, shutting down");
        }
    }

    tunnel.shutdown().await;
    tracing::info!("shutdown complete");
    Ok(())
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
