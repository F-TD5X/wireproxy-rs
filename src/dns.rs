use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;

use crate::netstack::{NetStack, VirtualUdpSocket};

const DNS_PORT: u16 = 53;

#[derive(Clone)]
pub struct DnsResolver {
    netstack: Arc<NetStack>,
    dns_server: Option<SocketAddr>,
}

impl DnsResolver {
    pub fn new(netstack: Arc<NetStack>, dns_server: Option<IpAddr>) -> Self {
        Self {
            netstack,
            dns_server: dns_server.map(|ip| SocketAddr::new(ip, DNS_PORT)),
        }
    }

    pub fn has_server(&self) -> bool {
        self.dns_server.is_some()
    }

    pub async fn resolve_ip(&self, domain: &str) -> Result<IpAddr> {
        let dns_server = self
            .dns_server
            .ok_or_else(|| anyhow!("no [Interface] DNS server configured"))?;
        tracing::debug!(domain = %domain, dns_server = %dns_server, "resolving domain through tunnel DNS");
        match self
            .resolve_query(domain, dns_server, DnsRecordType::Aaaa)
            .await
        {
            Ok(ip) => Ok(ip),
            Err(ipv6_error) => {
                tracing::debug!(
                    domain = %domain,
                    dns_server = %dns_server,
                    error = %ipv6_error,
                    "AAAA lookup failed, falling back to A"
                );
                self.resolve_query(domain, dns_server, DnsRecordType::A)
                    .await
                    .context("failed to resolve domain through tunnel DNS")
            }
        }
    }

    async fn resolve_query(
        &self,
        domain: &str,
        dns_server: SocketAddr,
        record_type: DnsRecordType,
    ) -> Result<IpAddr> {
        let socket = VirtualUdpSocket::bind(self.netstack.clone(), None)
            .context("failed to bind DNS UDP socket")?;
        let query_id = rand::thread_rng().gen::<u16>();
        let query = build_dns_query(query_id, domain, record_type)?;
        socket
            .send_to(dns_server, &query)
            .await
            .context("failed to send DNS query over WireGuard")?;

        let mut buffer = [0u8; 2048];
        loop {
            let recv = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
                .await
                .context("timed out waiting for DNS response")??;
            let (size, from) = recv;
            if from != dns_server {
                tracing::debug!(domain = %domain, from = %from, expected = %dns_server, "ignoring DNS response from unexpected source");
                continue;
            }
            let ip = parse_dns_response(query_id, record_type, &buffer[..size])?;
            tracing::debug!(
                domain = %domain,
                dns_server = %dns_server,
                record_type = %record_type.label(),
                resolved_ip = %ip,
                "resolved domain through tunnel DNS"
            );
            return Ok(ip);
        }
    }
}

#[derive(Clone, Copy)]
enum DnsRecordType {
    A,
    Aaaa,
}

impl DnsRecordType {
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        }
    }
}

fn build_dns_query(id: u16, domain: &str, record_type: DnsRecordType) -> Result<Vec<u8>> {
    let mut query = Vec::with_capacity(512);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in domain.split('.') {
        if label.is_empty() {
            bail!("domain contains an empty label");
        }
        if label.len() > 63 {
            bail!("domain label exceeds 63 bytes");
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&record_type.code().to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Ok(query)
}

fn parse_dns_response(
    expected_id: u16,
    expected_type: DnsRecordType,
    message: &[u8],
) -> Result<IpAddr> {
    if message.len() < 12 {
        bail!("DNS response is too short");
    }

    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != expected_id {
        bail!("DNS response ID does not match query");
    }

    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        bail!("DNS response is not marked as a response");
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        bail!("DNS server returned error code {}", rcode);
    }

    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut cursor = 12usize;

    for _ in 0..questions {
        skip_name(message, &mut cursor)?;
        cursor = cursor
            .checked_add(4)
            .filter(|cursor| *cursor <= message.len())
            .ok_or_else(|| anyhow!("DNS question section is truncated"))?;
    }

    for _ in 0..answers {
        skip_name(message, &mut cursor)?;
        if cursor + 10 > message.len() {
            bail!("DNS answer section is truncated");
        }

        let record_type = u16::from_be_bytes([message[cursor], message[cursor + 1]]);
        let record_class = u16::from_be_bytes([message[cursor + 2], message[cursor + 3]]);
        let data_len = u16::from_be_bytes([message[cursor + 8], message[cursor + 9]]) as usize;
        cursor += 10;

        if cursor + data_len > message.len() {
            bail!("DNS answer payload is truncated");
        }

        if record_class == 1 {
            match expected_type {
                DnsRecordType::A if record_type == 1 && data_len == 4 => {
                    return Ok(IpAddr::V4(Ipv4Addr::new(
                        message[cursor],
                        message[cursor + 1],
                        message[cursor + 2],
                        message[cursor + 3],
                    )));
                }
                DnsRecordType::Aaaa if record_type == 28 && data_len == 16 => {
                    let octets: [u8; 16] = message[cursor..cursor + data_len]
                        .try_into()
                        .expect("validated AAAA record length");
                    return Ok(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }

        cursor += data_len;
    }

    Err(anyhow!(
        "DNS response did not contain a {} record",
        expected_type.label()
    ))
}

fn skip_name(message: &[u8], cursor: &mut usize) -> Result<()> {
    let mut local_cursor = *cursor;
    let mut jumped = false;
    let mut seen = 0usize;

    loop {
        let Some(&len) = message.get(local_cursor) else {
            bail!("DNS name is truncated");
        };

        if len & 0xc0 == 0xc0 {
            let Some(&next) = message.get(local_cursor + 1) else {
                bail!("DNS compression pointer is truncated");
            };
            let pointer = (((len & 0x3f) as usize) << 8) | next as usize;
            if pointer >= message.len() {
                bail!("DNS compression pointer is out of range");
            }
            if !jumped {
                *cursor = local_cursor + 2;
            }
            local_cursor = pointer;
            jumped = true;
        } else if len == 0 {
            if !jumped {
                *cursor = local_cursor + 1;
            }
            return Ok(());
        } else {
            local_cursor += 1;
            let next = local_cursor + len as usize;
            if next > message.len() {
                bail!("DNS label exceeds packet length");
            }
            local_cursor = next;
            if !jumped {
                *cursor = local_cursor;
            }
        }

        seen += 1;
        if seen > message.len() {
            bail!("DNS name parsing loop detected");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{build_dns_query, parse_dns_response, DnsRecordType};

    #[test]
    fn builds_a_query() {
        let query = build_dns_query(0x1234, "example.com", DnsRecordType::A).unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(&query[12..25], b"\x07example\x03com\0");
        assert_eq!(&query[25..], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn parses_a_record_answer() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184,
            216, 34,
        ];

        let ip = parse_dns_response(0x1234, DnsRecordType::A, &response).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn parses_aaaa_record_answer() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10, 0x26,
            0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19,
            0x46,
        ];

        let ip = parse_dns_response(0x1234, DnsRecordType::Aaaa, &response).unwrap();
        assert_eq!(
            ip,
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946
            ))
        );
    }
}
