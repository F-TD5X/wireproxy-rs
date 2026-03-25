use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ini::{Ini, Properties};
use tokio::net::lookup_host;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelAddresses {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone)]
pub struct WgConfigFile {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub tunnel_addrs: TunnelAddresses,
    pub dns_server: Option<IpAddr>,
    pub mtu: u16,
    pub listen_port: Option<u16>,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub persistent_keepalive: Option<u16>,
    pub reserved_bytes: [u8; 3],
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub tunnel_addrs: TunnelAddresses,
    pub dns_server: Option<IpAddr>,
    pub mtu: u16,
    pub listen_port: Option<u16>,
    pub peer_endpoint: SocketAddr,
    pub persistent_keepalive: Option<u16>,
    pub reserved_bytes: [u8; 3],
}

impl WgConfigFile {
    pub fn load(path: &Path) -> Result<Self> {
        tracing::debug!(path = %path.display(), "loading WireGuard config");
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read WireGuard config {}", path.display()))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self> {
        let config = Ini::load_from_str(content).context("failed to parse WireGuard config")?;

        let interface = unique_section(&config, "Interface")?;
        let peer = unique_section(&config, "Peer")?;

        let private_key = decode_key(required(interface, "PrivateKey")?, "PrivateKey")?;
        let peer_public_key = decode_key(required(peer, "PublicKey")?, "PublicKey")?;
        let preshared_key = optional(peer, "PresharedKey")
            .map(|value| decode_key(value, "PresharedKey"))
            .transpose()?;

        let tunnel_addrs = parse_tunnel_addresses(required(interface, "Address")?, "Address")?;
        let dns_server = optional(interface, "DNS")
            .map(|value| parse_first_ip(value, "DNS"))
            .transpose()?;
        let mtu = optional(interface, "MTU")
            .map(|value| parse_u16(value, "MTU"))
            .transpose()?
            .unwrap_or(1420);
        let listen_port = optional(interface, "ListenPort")
            .map(|value| parse_u16(value, "ListenPort"))
            .transpose()?;

        let (endpoint_host, endpoint_port) = parse_endpoint(required(peer, "Endpoint")?)?;
        let persistent_keepalive = optional(peer, "PersistentKeepalive")
            .map(|value| parse_u16(value, "PersistentKeepalive"))
            .transpose()?;
        let reserved_bytes = optional(peer, "Reserved")
            .map(parse_reserved_bytes)
            .transpose()?
            .unwrap_or([0, 0, 0]);

        // Validate the fields we intentionally support, even when unused in v1.
        let _ = optional(peer, "AllowedIPs");

        let parsed = Self {
            private_key,
            peer_public_key,
            preshared_key,
            tunnel_addrs,
            dns_server,
            mtu,
            listen_port,
            endpoint_host,
            endpoint_port,
            persistent_keepalive,
            reserved_bytes,
        };

        tracing::debug!(
            tunnel_ipv4 = ?parsed.tunnel_addrs.ipv4,
            tunnel_ipv6 = ?parsed.tunnel_addrs.ipv6,
            dns = ?parsed.dns_server,
            mtu = parsed.mtu,
            listen_port = ?parsed.listen_port,
            endpoint_host = %parsed.endpoint_host,
            endpoint_port = parsed.endpoint_port,
            keepalive = ?parsed.persistent_keepalive,
            reserved = ?parsed.reserved_bytes,
            has_psk = parsed.preshared_key.is_some(),
            "parsed WireGuard config"
        );

        Ok(parsed)
    }

    pub async fn resolve(self) -> Result<TunnelConfig> {
        tracing::debug!(
            endpoint_host = %self.endpoint_host,
            endpoint_port = self.endpoint_port,
            "resolving WireGuard endpoint"
        );
        let endpoint = resolve_endpoint(&self.endpoint_host, self.endpoint_port).await?;

        let resolved = TunnelConfig {
            private_key: self.private_key,
            peer_public_key: self.peer_public_key,
            preshared_key: self.preshared_key,
            tunnel_addrs: self.tunnel_addrs,
            dns_server: self.dns_server,
            mtu: self.mtu,
            listen_port: self.listen_port,
            peer_endpoint: endpoint,
            persistent_keepalive: self.persistent_keepalive,
            reserved_bytes: self.reserved_bytes,
        };

        tracing::info!(
            tunnel_ipv4 = ?resolved.tunnel_addrs.ipv4,
            tunnel_ipv6 = ?resolved.tunnel_addrs.ipv6,
            endpoint = %resolved.peer_endpoint,
            mtu = resolved.mtu,
            dns = ?resolved.dns_server,
            reserved = ?resolved.reserved_bytes,
            "resolved WireGuard runtime config"
        );

        Ok(resolved)
    }
}

fn unique_section<'a>(config: &'a Ini, name: &str) -> Result<&'a Properties> {
    let sections: Vec<_> = config.section_all(Some(name)).collect();
    match sections.as_slice() {
        [section] => Ok(*section),
        [] => bail!("missing required [{}] section", name),
        _ => bail!("expected exactly one [{}] section", name),
    }
}

fn required<'a>(section: &'a Properties, key: &str) -> Result<&'a str> {
    section
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing required key {}", key))
}

fn optional<'a>(section: &'a Properties, key: &str) -> Option<&'a str> {
    section
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn decode_key(value: &str, key_name: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(value)
        .with_context(|| format!("{} is not valid base64", key_name))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{} must decode to 32 bytes, got {}", key_name, v.len()))
}

fn parse_tunnel_addresses(value: &str, key_name: &str) -> Result<TunnelAddresses> {
    let mut addrs = TunnelAddresses::default();

    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| entry.split('/').next())
    {
        match entry.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) if addrs.ipv4.is_none() => addrs.ipv4 = Some(ip),
            Ok(IpAddr::V6(ip)) if addrs.ipv6.is_none() => addrs.ipv6 = Some(ip),
            Ok(_) => {}
            Err(_) => {}
        }
    }

    if addrs.ipv4.is_none() && addrs.ipv6.is_none() {
        bail!("{} does not contain an IP address", key_name);
    }

    Ok(addrs)
}

fn parse_first_ip(value: &str, key_name: &str) -> Result<IpAddr> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| entry.split('/').next())
        .find_map(|entry| entry.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow!("{} does not contain an IP address", key_name))
}

fn parse_u16(value: &str, key_name: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("{} is not a valid u16", key_name))
}

fn parse_endpoint(value: &str) -> Result<(String, u16)> {
    if value.starts_with('[') {
        if let Some(idx) = value.find(']') {
            let host = value[1..idx].to_string();
            let port = value[idx + 1..]
                .trim_start_matches(':')
                .parse::<u16>()
                .context("invalid endpoint port")?;
            return Ok((host, port));
        }
    }

    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("Endpoint must be host:port"))?;
    let port = port.parse::<u16>().context("invalid endpoint port")?;
    Ok((host.to_string(), port))
}

fn parse_reserved_bytes(value: &str) -> Result<[u8; 3]> {
    let parts: Vec<_> = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();

    if parts.len() != 3 {
        bail!("Reserved must contain exactly three comma-separated bytes");
    }

    let mut reserved = [0u8; 3];
    for (idx, part) in parts.iter().enumerate() {
        reserved[idx] = part
            .parse::<u8>()
            .with_context(|| format!("Reserved byte {} is invalid", idx))?;
    }
    Ok(reserved)
}

async fn resolve_endpoint(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        tracing::debug!(
            host = %host,
            port,
            endpoint = %SocketAddr::new(ip, port),
            "WireGuard endpoint already an IP address"
        );
        return Ok(SocketAddr::new(ip, port));
    }

    let mut addrs = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve endpoint {}", host))?;
    let endpoint = addrs
        .next()
        .ok_or_else(|| anyhow!("endpoint {} did not resolve to an IP address", host))?;
    tracing::debug!(host = %host, port, endpoint = %endpoint, "resolved WireGuard endpoint hostname");
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::WgConfigFile;

    const SAMPLE_CONFIG: &str = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32, 2606:4700:110:8c00::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = 1280
ListenPort = 51820

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = engage.cloudflareclient.com:2408
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
Reserved = 1,2,3
"#;

    #[test]
    fn parses_single_peer_config() {
        let config = WgConfigFile::parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(config.tunnel_addrs.ipv4.unwrap().to_string(), "172.16.0.2");
        assert_eq!(
            config.tunnel_addrs.ipv6.unwrap().to_string(),
            "2606:4700:110:8c00::2"
        );
        assert_eq!(config.dns_server.unwrap().to_string(), "1.1.1.1");
        assert_eq!(config.mtu, 1280);
        assert_eq!(config.listen_port, Some(51820));
        assert_eq!(config.endpoint_port, 2408);
        assert_eq!(config.reserved_bytes, [1, 2, 3]);
    }

    #[test]
    fn rejects_multiple_peers() {
        let config = format!(
            "{}\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 1.1.1.1:1\n",
            SAMPLE_CONFIG
        );
        assert!(WgConfigFile::parse(&config).is_err());
    }

    #[test]
    fn defaults_reserved_bytes_to_zero() {
        let config = WgConfigFile::parse(
            r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 1.1.1.1:51820
"#,
        )
        .unwrap();

        assert_eq!(config.reserved_bytes, [0, 0, 0]);
    }

    #[test]
    fn parses_ipv6_only_interface_config() {
        let config = WgConfigFile::parse(
            r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 2606:4700:110:8c00::2/128
DNS = 2606:4700:4700::1111

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = [2606:4700:d0::a29f:c001]:51820
"#,
        )
        .unwrap();

        assert_eq!(config.tunnel_addrs.ipv4, None);
        assert_eq!(
            config.tunnel_addrs.ipv6.unwrap().to_string(),
            "2606:4700:110:8c00::2"
        );
        assert_eq!(
            config.dns_server.unwrap().to_string(),
            "2606:4700:4700::1111"
        );
        assert_eq!(config.endpoint_host, "2606:4700:d0::a29f:c001");
        assert_eq!(config.endpoint_port, 51820);
    }
}
