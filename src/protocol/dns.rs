use core::str::FromStr;

#[cfg(all(feature = "rt_tokio"))]
use futures::prelude::*;
use trust_dns_client::{
    client::{Client, ClientHandle, SyncClient},
    error::ClientResult,
    op::DnsResponse,
    rr::{DNSClass, Name, RData, Record, RecordType},
    udp::UdpClientConnection,
};
#[cfg(all(feature = "rt_tokio"))]
use trust_dns_client::{
    client::AsyncClient,
    proto::error::ProtoError,
    udp::UdpClientStream,
};

use smolsocket::SocketAddr;

use super::{CrateResult, Error, SocksAddr};

fn parse_addr(nameserver: &str) -> CrateResult<::std::net::SocketAddr> {
    Ok(nameserver.parse().map_err(|_| Error::DnsError(None))?)
}

fn to_name(domain: &str) -> CrateResult<Name> {
    Ok(Name::from_str((domain.to_owned() + ".").as_str()).map_err(|_| Error::AddrError)?)
}

fn new_sync_client(nameserver: &str) -> CrateResult<SyncClient<UdpClientConnection>> {
    let address = parse_addr(nameserver)?;
    let conn = UdpClientConnection::new(address)
        .map_err(|_| Error::DnsError(None))?;
    let client = SyncClient::new(conn);
    Ok(client)
}

pub fn dns_response_to_ip(response: ClientResult<DnsResponse>) -> CrateResult<Option<::std::net::IpAddr>> {
    let response = response.map_err(|_| Error::DnsError(None))?;
    let answers: &[Record] = response.answers();
    Ok(if answers.len() > 0 {
        if let &RData::A(ref ip) = answers[0].rdata() {
            Some(::std::net::IpAddr::V4(ip.clone()))
        } else {
            None
        }
    } else {
        None
    })
}

pub fn resolve_addr(addr: &SocksAddr, nameserver: &str) -> CrateResult<SocketAddr> {
    let resolver = crate::DnsResolver::new(nameserver, None)?;
    resolver.try_resolve_addr(addr)
}

#[cfg(all(feature = "rt_tokio"))]
pub async fn resolve_domain_async(domain: &str, nameserver: &str) -> CrateResult<Option<::std::net::IpAddr>> {
    let address = parse_addr(nameserver)?;
    let name = to_name(domain)?;

    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, task) = AsyncClient::connect(stream).await
        .map_err(|_| Error::DnsError(None))?;

    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
    let task = future::Abortable::new(task, abort_registration);
    let _jh: tokio::task::JoinHandle<Result<Result<(), ProtoError>, future::Aborted>> = tokio::spawn(task);

    let response = client.query(name, DNSClass::IN, RecordType::A).await;
    abort_handle.abort();
    dns_response_to_ip(response)
}

pub struct DnsResolver {
    // primary: String,
    primary_client: SyncClient<UdpClientConnection>,
    // secondary: Option<String>,
    secondary_client: Option<SyncClient<UdpClientConnection>>,
}

/// Dont use this in a context of Tokio because of it attempts to block the current thread
/// while the thread is being used to drive asynchronous tasks.
impl DnsResolver {
    pub fn new(primary: &str, secondary: Option<&str>) -> CrateResult<Self> {
        let primary_client = new_sync_client(primary)?;
        let (_secondary, secondary_client) = if let Some(secondary) = secondary {
            let secondary_client = new_sync_client(secondary)?;
            (Some(secondary.to_string()), Some(secondary_client))
        } else {
            (None, None)
        };
        Ok(Self {
            // primary: primary.to_string(),
            primary_client,
            // secondary,
            secondary_client,
        })
    }

    pub fn new_open_dns() -> CrateResult<Self> { // Cisco OpenDNS
        Self::new("208.67.222.222:53", Some("208.67.220.220:53"))
    }

    pub fn new_cloud_flare_dns() -> CrateResult<Self> { // Cloudflare
        Self::new("1.1.1.1:53", Some("1.0.0.1:53"))
    }

    pub fn new_google_dns() -> CrateResult<Self> { // Google Public DNS
        Self::new("8.8.8.8:53", Some("8.8.4.4:53"))
    }

    pub fn new_quad9() -> CrateResult<Self> { // Quad9
        Self::new("9.9.9.9:53", Some("149.112.112.112:53"))
    }

    fn try_resolve_addr_by(addr: &SocksAddr, client: &SyncClient<UdpClientConnection>) -> CrateResult<SocketAddr> {
        match addr {
            #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
            SocksAddr::SocketAddr(socket_addr) => Ok(socket_addr.clone()),
            SocksAddr::DomainPort(domain, port) => {
                if let Ok(ip) = DnsResolver::try_resolve_domain_by(domain, client) {
                    if let Ok(addr) = SocketAddr::new(ip.into(), port.clone()) {
                        Ok(addr)
                    } else {
                        Err(Error::DnsError(Some(domain.to_string())))
                    }
                } else {
                    Err(Error::DnsError(Some(domain.to_string())))
                }
            }
        }
    }

    fn try_resolve_domain_by(domain: &str, client: &SyncClient<UdpClientConnection>) -> CrateResult<::std::net::IpAddr> {
        let name = to_name(domain)?;
        let response = client.query(&name, DNSClass::IN, RecordType::A);
        if let Ok(resolved) = dns_response_to_ip(response) {
            if let Some(ip) = resolved {
                Ok(ip)
            } else {
                Err(Error::DnsError(Some(domain.to_string())))
            }
        } else {
            Err(Error::DnsError(Some(domain.to_string())))
        }
    }

    pub fn try_resolve_addr(&self, addr: &SocksAddr) -> CrateResult<SocketAddr> {
        let result = DnsResolver::try_resolve_addr_by(addr, &self.primary_client);
        if result.is_ok() {
            result
        } else {
            if let Some(ref secondary_client) = self.secondary_client {
                DnsResolver::try_resolve_addr_by(addr, secondary_client)
            } else {
                result
            }
        }
    }

    pub fn try_resolve_domain(&self, domain: &str) -> CrateResult<::std::net::IpAddr> {
        let result = DnsResolver::try_resolve_domain_by(domain, &self.primary_client);
        if result.is_ok() {
            result
        } else {
            if let Some(ref secondary_client) = self.secondary_client {
                DnsResolver::try_resolve_domain_by(domain, secondary_client)
            } else {
                result
            }
        }
    }
}

#[cfg(test)]
mod test {
    use ::std::env;

    use super::*;

    fn init_logger() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "debug");
        }
        let _ = pretty_env_logger::try_init_timed();
    }

    #[test]
    fn test_socks_addr_domain_resolve() {
        init_logger();

        let socks_addr = SocksAddr::DomainPort("bing.com".to_string(), 443);
        let resolved = socks_addr.resolve("8.8.8.8:53");
        info!("resolved {:?}", resolved);
        assert!(resolved.is_ok());
        let socket_addr = resolved.unwrap();
        assert_eq!(socket_addr.len(), 6);
    }

    #[cfg(all(feature = "rt_tokio"))]
    #[tokio::test]
    async fn test_resolve_async() {
        init_logger();

        let result = resolve_domain_async("google.com", "8.8.8.8:53").await;
        info!("result {:?}", result);
        assert!(result.is_ok());
    }
}
