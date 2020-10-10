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

use super::{CrateResult, Error};

fn to_name(domain: &str) -> CrateResult<Name> {
    Ok(Name::from_str((domain.to_owned() + ".").as_str()).map_err(|_| Error::AddrParseError)?)
}

pub fn dns_response_to_ip(response: ClientResult<DnsResponse>) -> CrateResult<Option<::std::net::IpAddr>> {
    let response = response.map_err(|_| Error::AddrParseError)?;
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

/// Dont use this in a context of Tokio because of it attempts to block the current thread
/// while the thread is being used to drive asynchronous tasks.
pub fn resolve(domain: &str, nameserver: &str) -> CrateResult<Option<::std::net::IpAddr>> {
    let address = nameserver.parse().map_err(|_| Error::AddrParseError)?;
    let name = to_name(domain)?;

    let conn = UdpClientConnection::new(address)
        .map_err(|_| Error::AddrParseError)?;
    let client = SyncClient::new(conn); // TODO support async client
    let response = client.query(&name, DNSClass::IN, RecordType::A);
    dns_response_to_ip(response)
}

#[cfg(all(feature = "rt_tokio"))]
pub async fn resolve_async(domain: &str, nameserver: &str) -> CrateResult<Option<::std::net::IpAddr>> {
    let address = nameserver.parse().map_err(|_| Error::AddrParseError)?;
    let name = to_name(domain)?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, task) = AsyncClient::connect(stream).await
        .map_err(|_| Error::AddrParseError)?;

    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
    let task = future::Abortable::new(task, abort_registration);
    let _jh: tokio::task::JoinHandle<Result<Result<(), ProtoError>, future::Aborted>> = tokio::spawn(task);

    let response = client.query(name, DNSClass::IN, RecordType::A).await;
    abort_handle.abort();
    dns_response_to_ip(response)
}

#[cfg(test)]
mod test {
    use ::std::env;

    use crate::protocol::addr::Addr;

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

        let socks_addr = Addr::DomainPort("bing.com".to_string(), 443);
        let resolved = socks_addr.resolve("8.8.8.8:53");
        info!("resolved {:?}", resolved);
        assert!(resolved.is_ok());
        let option = resolved.unwrap();
        assert!(option.is_some());
        let socket_addr = option.unwrap();
        assert_eq!(socket_addr.len(), 6);
    }

    #[cfg(all(feature = "rt_tokio"))]
    #[tokio::test]
    async fn test_resolve_async() {
        init_logger();

        let result = resolve_async("google.com", "8.8.8.8:53").await;
        info!("result {:?}", result);
        assert!(result.is_ok());
    }
}
