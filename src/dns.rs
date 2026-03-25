use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;

use crate::netstack::{NetStack, VirtualUdpSocket};

const DNS_PORT: u16 = 53;

#[derive(Clone)]
pub struct DnsResolver {
    netstack: Arc<NetStack>,
    dns_server: Option<SocketAddrV4>,
}

impl DnsResolver {
    pub fn new(netstack: Arc<NetStack>, dns_server: Option<Ipv4Addr>) -> Self {
        Self {
            netstack,
            dns_server: dns_server.map(|ip| SocketAddrV4::new(ip, DNS_PORT)),
        }
    }

    pub fn has_server(&self) -> bool {
        self.dns_server.is_some()
    }

    pub async fn resolve_ipv4(&self, domain: &str) -> Result<Ipv4Addr> {
        let dns_server = self
            .dns_server
            .ok_or_else(|| anyhow!("no [Interface] DNS server configured"))?;
        tracing::debug!(domain = %domain, dns_server = %dns_server, "resolving domain through tunnel DNS");
        let socket = VirtualUdpSocket::bind(self.netstack.clone(), None)
            .context("failed to bind DNS UDP socket")?;
        let query_id = rand::thread_rng().gen::<u16>();
        let query = build_dns_query(query_id, domain)?;
        socket
            .send_to(SocketAddr::V4(dns_server), &query)
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
            let ip = parse_dns_response(query_id, &buffer[..size])?;
            tracing::debug!(domain = %domain, dns_server = %dns_server, resolved_ip = %ip, "resolved domain through tunnel DNS");
            return Ok(ip);
        }
    }
}

fn build_dns_query(id: u16, domain: &str) -> Result<Vec<u8>> {
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
    query.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Ok(query)
}

fn parse_dns_response(expected_id: u16, message: &[u8]) -> Result<Ipv4Addr> {
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

        if record_type == 1 && record_class == 1 && data_len == 4 {
            return Ok(Ipv4Addr::new(
                message[cursor],
                message[cursor + 1],
                message[cursor + 2],
                message[cursor + 3],
            ));
        }

        cursor += data_len;
    }

    Err(anyhow!("DNS response did not contain an A record"))
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
    use super::{build_dns_query, parse_dns_response};

    #[test]
    fn builds_a_query() {
        let query = build_dns_query(0x1234, "example.com").unwrap();
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

        let ip = parse_dns_response(0x1234, &response).unwrap();
        assert_eq!(ip.octets(), [93, 184, 216, 34]);
    }
}
