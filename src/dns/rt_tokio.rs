use futures::prelude::*;
use trust_dns_client::{
    client::ClientHandle,
    rr::{DNSClass, RecordType},
};
#[cfg(all(feature = "rt_tokio"))]
use trust_dns_client::{
    client::AsyncClient,
    proto::{error::ProtoError, udp::UdpResponse},
    udp::UdpClientStream,
};

use smolsocket::SocketAddr;

use crate::{CrateResult, Error, SocksAddr};

use super::{dns_response_to_ip, dns_response_to_ip2, parse_addr, to_name};

#[cfg(all(feature = "rt_tokio"))]
pub async fn async_dns_resolve(domain: &str, nameserver: &str) -> CrateResult<Option<::std::net::IpAddr>> {
    let (mut client, ah) = new_async_client(nameserver).await?;
    let name = to_name(domain)?;
    let response = client.query(name, DNSClass::IN, RecordType::A).await;
    ah.abort();
    dns_response_to_ip(response)
}

#[cfg(all(feature = "rt_tokio"))]
async fn new_async_client(nameserver: &str) -> CrateResult<(AsyncClient<UdpResponse>, future::AbortHandle)> {
    let address = parse_addr(nameserver)?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (client, task) = AsyncClient::connect(stream).await
        .map_err(|_| Error::DnsError(None))?;

    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
    let task = future::Abortable::new(task, abort_registration);
    let _jh: tokio::task::JoinHandle<Result<Result<(), ProtoError>, future::Aborted>> = tokio::spawn(task);
    Ok((client, abort_handle))
}

#[cfg(all(feature = "rt_tokio"))]
pub struct AsyncDnsResolver {
    primary_client: (AsyncClient<UdpResponse>, future::AbortHandle),
    secondary_client: Option<(AsyncClient<UdpResponse>, future::AbortHandle)>,
}

impl AsyncDnsResolver {
    pub async fn new(primary: &str, secondary: Option<&str>) -> CrateResult<Self> {
        let primary_client = new_async_client(primary).await?;
        let secondary_client = if let Some(secondary) = secondary {
            let secondary_client = new_async_client(secondary).await?;
            Some(secondary_client)
        } else {
            None
        };
        Ok(Self {
            primary_client,
            secondary_client,
        })
    }

    pub async fn new_google_dns() -> CrateResult<Self> { // Google Public DNS
        Self::new("8.8.8.8:53", Some("8.8.4.4:53")).await
    }

    async fn try_resolve_addr_by(addr: &SocksAddr, client: &mut AsyncClient<UdpResponse>) -> CrateResult<SocketAddr> {
        match addr {
            #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
            SocksAddr::SocketAddr(socket_addr) => Ok(*socket_addr),
            SocksAddr::DomainPort(domain, port) => {
                let ip = AsyncDnsResolver::try_resolve_domain_by(domain, client).await?;
                Ok((ip, *port).into())
            }
        }
    }

    async fn try_resolve_domain_by(domain: &str, client: &mut AsyncClient<UdpResponse>) -> CrateResult<::std::net::IpAddr> {
        let name = to_name(domain)?;
        let response = client.query(name, DNSClass::IN, RecordType::A).await;
        dns_response_to_ip2(domain, response)
    }

    pub async fn try_resolve_addr(&mut self, addr: &SocksAddr) -> CrateResult<SocketAddr> {
        let result = AsyncDnsResolver::try_resolve_addr_by(addr, &mut self.primary_client.0).await;
        if result.is_ok() {
            result
        } else if let Some(ref mut secondary_client) = &mut self.secondary_client {
            AsyncDnsResolver::try_resolve_addr_by(addr, &mut secondary_client.0).await
        } else {
            result
        }
    }

    pub async fn try_resolve_domain(&mut self, domain: &str) -> CrateResult<::std::net::IpAddr> {
        let result = AsyncDnsResolver::try_resolve_domain_by(domain, &mut self.primary_client.0).await;
        if result.is_ok() {
            result
        } else if let Some(ref mut secondary_client) = &mut self.secondary_client {
            AsyncDnsResolver::try_resolve_domain_by(domain, &mut secondary_client.0).await
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "rt_tokio"))]
    #[tokio::test]
    async fn test_resolve_async() {
        crate::tests::init_logger();

        let result = async_dns_resolve("google.com", "8.8.8.8:53").await;
        info!("result {:?}", result);
        assert!(result.is_ok());
    }
}
