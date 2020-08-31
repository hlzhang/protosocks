use core::convert::TryFrom;

use bytes::{Buf, BytesMut};

use super::{Cmd, Decoder, Encodable, Encoder, Error, field, HasAddr, Rep, Result, SocksAddr, Ver};
use super::addr::field_port;
use std::fmt::{Display, Formatter};
use std::fmt;

// Requests
//
// Once the method-dependent subnegotiation has completed, the client
// sends the request details.  If the negotiated method includes
// encapsulation for purposes of integrity checking and/or
// confidentiality, these requests MUST be encapsulated in the method-
// dependent encapsulation.
//
// The SOCKS request is formed as follows:
//
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
//
// Where:
//
// o  VER    protocol version: X'05'
// o  CMD
//    o  CONNECT X'01'
//    o  BIND X'02'
//    o  UDP ASSOCIATE X'03'
// o  RSV    RESERVED
// o  ATYP   address type of following address
//    o  IP V4 address: X'01'
//    o  DOMAINNAME: X'03'
//    o  IP V6 address: X'04'
// o  DST.ADDR       desired destination address
// o  DST.PORT desired destination port in network octet
// order
//
// The SOCKS server will typically evaluate the request based on source
// and destination addresses, and return one or more reply messages, as
// appropriate for the request type.
//
//
// Replies
//
// The SOCKS request information is sent by the client as soon as it has
// established a connection to the SOCKS server, and completed the
// authentication negotiations.  The server evaluates the request, and
// returns a reply formed as follows:
//
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
//
// CONNECT
//
// In the reply to a CONNECT, BND.PORT contains the port number that the
// server assigned to connect to the target host, while BND.ADDR
// contains the associated IP address.  The supplied BND.ADDR is often
// different from the IP address that the client uses to reach the SOCKS
// server, since such servers are often multi-homed.  It is expected
// that the SOCKS server will use DST.ADDR and DST.PORT, and the
// client-side source address and port in evaluating the CONNECT
// request.
//
// BIND
//
// The BIND request is used in protocols which require the client to
// accept connections from the server.  FTP is a well-known example,
// which uses the primary client-to-server connection for commands and
// status reports, but may use a server-to-client connection for
// transferring data on demand (e.g. LS, GET, PUT).
//
// It is expected that the client side of an application protocol will
// use the BIND request only to establish secondary connections after a
// primary connection is established using CONNECT.  In is expected that
// a SOCKS server will use DST.ADDR and DST.PORT in evaluating the BIND
// request.
//
// Two replies are sent from the SOCKS server to the client during a
// BIND operation.  The first is sent after the server creates and binds
// a new socket.  The BND.PORT field contains the port number that the
// SOCKS server assigned to listen for an incoming connection.  The
// BND.ADDR field contains the associated IP address.  The client will
// typically use these pieces of information to notify (via the primary
// or control connection) the application server of the rendezvous
// address.  The second reply occurs only after the anticipated incoming
// connection succeeds or fails.
//
// In the second reply, the BND.PORT and BND.ADDR fields contain the
// address and port number of the connecting host.
//
// UDP ASSOCIATE
//
// The UDP ASSOCIATE request is used to establish an association within
// the UDP relay process to handle UDP datagrams.  The DST.ADDR and
// DST.PORT fields contain the address and port that the client expects
// to use to send UDP datagrams on for the association.  The server MAY
// use this information to limit access to the association.  If the
// client is not in possesion of the information at the time of the UDP
// ASSOCIATE, the client MUST use a port number and address of all
// zeros.
//
// A UDP association terminates when the TCP connection that the UDP
// ASSOCIATE request arrived on terminates.
//
// In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
// fields indicate the port number/address where the client MUST send
// UDP request messages to be relayed.
//
// Reply Processing
//
// When a reply (REP value other than X'00') indicates a failure, the
// SOCKS server MUST terminate the TCP connection shortly after sending
// the reply.  This must be no more than 10 seconds after detecting the
// condition that caused a failure.
//
// If the reply code (REP value of X'00') indicates a success, and the
// request was either a BIND or a CONNECT, the client may now start
// passing data.  If the selected authentication method supports
// encapsulation for the purposes of integrity, authentication and/or
// confidentiality, the data are encapsulated using the method-dependent
// encapsulation.  Similarly, when data arrives at the SOCKS server for
// the client, the server MUST encapsulate the data as appropriate for
// the authentication method in use.
//
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    compact: bool,
    addr: HasAddr<T>,
}

const FIELD_COMPACT_ATYP: usize = 1;
const FIELD_COMPACT_ADDR_PORT: crate::field::Rest = 2..;
const FIELD_COMPACT_CMD_OR_REP: usize = 0;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with RFC1928 request packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet {
            compact: false,
            addr: HasAddr::new_unchecked(field::ATYP, buffer),
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub fn new_compact_unchecked(buffer: T) -> Packet<T> {
        Packet {
            compact: true,
            addr: HasAddr::new_unchecked(FIELD_COMPACT_ATYP, buffer),
        }
    }

    pub fn new_compact_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_compact_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    #[inline]
    fn buffer_ref(&self) -> &[u8] {
        self.addr.buffer.as_ref()
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_socks_addr]
    ///
    /// [set_methods]: #method.set_socks_addr
    #[inline]
    pub fn check_len(&self) -> Result<()> {
        self.addr.check_addr_len()?;
        if self.buffer_ref().len() > self.total_len() {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }

    /// Return the length (unchecked).
    #[inline]
    pub fn total_len(&self) -> usize {
        self.addr.len_to_port()
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        if self.compact {
            Ver::SOCKS5.into()
        } else {
            let data = self.buffer_ref();
            data[field::VER]
        }
    }

    /// Return the cmd of request or rep of reply.
    #[inline]
    pub fn cmd_or_rep(&self) -> u8 {
        let data = self.buffer_ref();
        if self.compact {
            data[FIELD_COMPACT_CMD_OR_REP]
        } else {
            data[field::CMD_OR_REP]
        }
    }

    /// Return the atyp.
    #[inline]
    pub fn atyp(&self) -> u8 {
        self.addr.atyp()
    }

    /// Return the dst port of request or bnd port of reply (unchecked).
    #[inline]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn take_buffer(self) -> T {
        self.addr.take_buffer()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the addr (unchecked).
    #[inline]
    pub fn addr(&self) -> &'a [u8] {
        self.addr.addr()
    }

    /// Return a pointer to the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn socks_addr(&self) -> &'a [u8] {
        self.addr.socks_addr()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    #[inline]
    fn buffer_mut(&mut self) -> &mut [u8] {
        self.addr.buffer.as_mut()
    }

    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        if !self.compact {
            let data = self.buffer_mut();
            data[field::VER] = value;
        }
    }

    /// Set the cmd or rep.
    #[inline]
    pub fn set_cmd_or_rep(&mut self, value: u8) {
        if self.compact {
            let data = self.buffer_mut();
            data[FIELD_COMPACT_CMD_OR_REP] = value;
        } else {
            let data = self.buffer_mut();
            data[field::CMD_OR_REP] = value;
        }
    }

    /// Set the atyp.
    #[inline]
    pub fn set_atyp(&mut self, value: u8) {
        self.addr.set_atyp(value)
    }

    /// Set the addr (unchecked).
    #[inline]
    pub fn set_addr(&mut self, value: &[u8]) {
        self.addr.set_addr(value)
    }

    /// Set the port (unchecked).
    #[inline]
    pub fn set_port(&mut self, value: u16) {
        self.addr.set_port(value)
    }

    /// Set the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn set_socks_addr(&mut self, value: &[u8]) {
        self.addr.set_socks_addr(value)
    }

    /// Return a mutable pointer to the addr (unchecked).
    #[inline]
    pub fn addr_mut(&mut self) -> &mut [u8] {
        self.addr.addr_mut()
    }

    /// Return a mutable pointer to the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn socks_addr_mut(&mut self) -> &mut [u8] {
        self.addr.socks_addr_mut()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.buffer_ref()
    }
}

/// A high-level representation of a Cmd packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CmdRepr {
    pub cmd: Cmd,
    pub addr: SocksAddr,
}

impl Display for CmdRepr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.cmd, self.addr)
    }
}

impl CmdRepr {
    pub fn new_connect(addr: SocksAddr) -> Self {
        CmdRepr { cmd: Cmd::Connect, addr }
    }

    pub fn new_bind(addr: SocksAddr) -> Self {
        CmdRepr { cmd: Cmd::Bind, addr }
    }

    pub fn new_udp_associate(addr: SocksAddr) -> Self {
        CmdRepr { cmd: Cmd::UdpAssociate, addr }
    }

    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<CmdRepr> {
        packet.check_len()?;

        // Version 5 is expected.
        if packet.compact {
            if packet.version() != Ver::SOCKS5 as u8 {
                return Err(Error::Malformed);
            }
            if packet.as_ref()[field::RSV] != 0 {
                return Err(Error::Malformed);
            }
        }

        Ok(CmdRepr {
            cmd: Cmd::try_from(packet.cmd_or_rep())?,
            addr: SocksAddr::try_from(packet.socks_addr())?,
        })
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let addr_len = self.addr.addr_len();
        field_port(field::ADDR_PORT.start, addr_len).end
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        packet.set_version(Ver::SOCKS5.into());
        packet.set_cmd_or_rep(self.cmd as u8);
        packet.set_socks_addr(&self.addr.to_vec());
    }

    pub fn compact_buffer_len(&self) -> usize {
        let addr_len = self.addr.addr_len();
        field_port(FIELD_COMPACT_ADDR_PORT.start, addr_len).end
    }
}

impl Decoder<CmdRepr> for CmdRepr {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>> {
        let pkt = Packet::new_unchecked(src.as_ref());
        match CmdRepr::parse(&pkt) {
            Ok(repr) => {
                src.advance(repr.buffer_len());
                Ok(Some(repr))
            }
            Err(Error::Truncated) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Encodable for CmdRepr {
    fn encode_into(&self, dst: &mut BytesMut) {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = Packet::new_unchecked(dst);
        self.emit(&mut pkt);
    }
}

impl Encoder<CmdRepr> for CmdRepr {
    fn encode(item: &CmdRepr, dst: &mut BytesMut) {
        item.encode_into(dst);
    }
}

/// A high-level representation of a Rep packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RepRepr {
    pub rep: Rep,
    pub addr: SocksAddr,
}

impl RepRepr {
    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<RepRepr> {
        packet.check_len()?;

        // Version 5 is expected.
        if packet.version() != Ver::SOCKS5 as u8 {
            return Err(Error::Malformed);
        }
        if packet.as_ref()[field::RSV] != 0 {
            return Err(Error::Malformed);
        }

        Ok(RepRepr {
            rep: Rep::try_from(packet.cmd_or_rep())?,
            addr: SocksAddr::try_from(packet.socks_addr())?,
        })
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let addr_len = self.addr.addr_len();
        field_port(field::ADDR_PORT.start, addr_len).end
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        packet.set_version(Ver::SOCKS5.into());
        packet.set_cmd_or_rep(self.rep as u8);
        packet.set_socks_addr(&self.addr.to_vec());
    }
}

impl Decoder<RepRepr> for RepRepr {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>> {
        let pkt = Packet::new_unchecked(src.as_ref());
        match RepRepr::parse(&pkt) {
            Ok(repr) => {
                src.advance(repr.buffer_len());
                Ok(Some(repr))
            }
            Err(Error::Truncated) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Encodable for RepRepr {
    fn encode_into(&self, dst: &mut BytesMut) {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = Packet::new_unchecked(dst);
        self.emit(&mut pkt);
    }
}

impl Encoder<RepRepr> for RepRepr {
    fn encode(item: &RepRepr, dst: &mut BytesMut) {
        item.encode_into(dst);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    #[cfg(feature = "proto-ipv4")]
    use smoltcp::wire::Ipv4Address;
    #[cfg(feature = "proto-ipv6")]
    use smoltcp::wire::Ipv6Address;

    #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
    use smolsocket::SocketAddr;

    use crate::Atyp;

    use super::*;

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_cmd_invalid_len() {
        let mut truncated_bytes = vec![0x00 as u8; 4];
        let mut truncated = Packet::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::SOCKS5 as u8);
        truncated.set_atyp(Atyp::V4 as u8);
        assert_eq!(truncated.check_len(), Err(Error::Truncated));
        let mut truncated_bytes_mut = BytesMut::new();
        truncated_bytes_mut.extend(truncated_bytes);
        assert_eq!(CmdRepr::decode(&mut truncated_bytes_mut), Ok(None));

        let mut truncated_bytes = vec![0x00 as u8; 5];
        let mut truncated = Packet::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::SOCKS5 as u8);
        truncated.set_atyp(Atyp::V4 as u8);
        assert_eq!(truncated.check_len(), Err(Error::Truncated));

        assert_eq!(truncated.total_len(), 10);
        let mut malformed_bytes = vec![0x00 as u8; truncated.total_len() + 1];
        let mut malformed = Packet::new_unchecked(&mut malformed_bytes);
        malformed.set_version(Ver::SOCKS5 as u8);
        malformed.set_atyp(Atyp::V4 as u8);
        assert_eq!(malformed.check_len(), Err(Error::Malformed));
        let mut malformed_bytes_mut = BytesMut::new();
        malformed_bytes_mut.extend(malformed_bytes);
        assert_eq!(
            CmdRepr::decode(&mut malformed_bytes_mut),
            Err(Error::Malformed)
        );
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_cmd_connect_ip4() {
        let socket_addr = SocketAddr::new_ip4_port(127, 0, 0, 1, 80);
        let socks_addr = SocksAddr::SocketAddr(socket_addr);
        let repr = CmdRepr {
            cmd: Cmd::Connect,
            addr: socks_addr.clone(),
        };
        assert_eq!(repr.buffer_len(), 10);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::V4 as u8);
        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(0, 0, 0, 0).as_bytes());
        pkt.set_addr(Ipv4Address::new(192, 168, 0, 1).as_bytes());
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv4Address::new(192, 168, 0, 1).as_bytes()
        );
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.socks_addr_mut(), socks_addr.to_vec().as_slice());

        let pkt_to_parse = Packet::new_checked(pkt.as_ref()).expect("should be valid");
        assert_eq!(
            pkt_to_parse.addr(),
            Ipv4Address::new(127, 0, 0, 1).as_bytes()
        );
        let parsed = CmdRepr::parse(&pkt_to_parse).expect("should parse");
        assert_eq!(parsed, repr);
        assert_eq!(parsed.addr.atyp(), Atyp::V4);
        if let SocksAddr::SocketAddr(SocketAddr::V4(socket_addr)) = parsed.addr {
            assert!(socket_addr.addr.is_loopback());
        }

        let mut bytes_mut = BytesMut::new();
        CmdRepr::encode(&repr, &mut bytes_mut);
        let decoded = CmdRepr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }

    #[cfg(feature = "proto-ipv6")]
    #[test]
    fn test_cmd_connect_ip6() {
        let socket_addr = SocketAddr::new_ip6_port(0, 0, 0, 0, 0, 0, 0, 1, 80);
        let socks_addr = SocksAddr::SocketAddr(socket_addr);
        let repr = CmdRepr {
            cmd: Cmd::Connect,
            addr: socks_addr.clone(),
        };
        assert_eq!(repr.buffer_len(), 22);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::V6 as u8);
        assert_eq!(pkt.atyp(), Atyp::V6 as u8);
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0).as_bytes()
        );
        pkt.set_addr(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).as_bytes());
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).as_bytes()
        );
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.socks_addr_mut(), socks_addr.to_vec().as_slice());

        let pkt_to_parse = Packet::new_checked(pkt.as_ref()).expect("should be valid");
        assert_eq!(
            pkt_to_parse.addr(),
            Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1).as_bytes()
        );
        let parsed = CmdRepr::parse(&pkt_to_parse).expect("should parse");
        assert_eq!(parsed, repr);
        assert_eq!(parsed.addr.atyp(), Atyp::V6);
        if let SocksAddr::SocketAddr(SocketAddr::V6(socket_addr)) = parsed.addr {
            assert!(socket_addr.addr.is_loopback());
        }

        let mut bytes_mut = BytesMut::new();
        CmdRepr::encode(&repr, &mut bytes_mut);
        let decoded = CmdRepr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }

    #[test]
    fn test_cmd_connect_domain() {
        let socks_addr = SocksAddr::DomainPort("google.com".to_string(), 443);
        let repr = CmdRepr {
            cmd: Cmd::Connect,
            addr: socks_addr.clone(),
        };
        assert_eq!(repr.buffer_len(), 17);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::Domain as u8);
        assert_eq!(pkt.atyp(), Atyp::Domain as u8);
        assert_eq!(pkt.addr_mut()[0], 0);
        pkt.addr_mut()[0] = 10;
        assert_eq!(&pkt.addr_mut()[1..], b"\0\0\0\0\0\0\0\0\0\0");
        pkt.set_addr(b"          ");
        assert_eq!(&pkt.addr_mut()[1..], b"          ");
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.socks_addr_mut(), socks_addr.to_vec().as_slice());

        let pkt_to_parse = Packet::new_checked(pkt.as_ref()).expect("should be valid");
        assert_eq!(pkt_to_parse.addr()[0], 10);
        assert_eq!(&pkt_to_parse.addr()[1..], b"google.com");
        let parsed = CmdRepr::parse(&pkt_to_parse).expect("should parse");
        assert_eq!(parsed, repr);
        assert_eq!(parsed.addr.atyp(), Atyp::Domain);
        if let SocksAddr::DomainPort(domain, port) = parsed.addr {
            assert_eq!(domain, "google.com".to_string());
            assert_eq!(port, 443);
        }

        let mut bytes_mut = BytesMut::new();
        CmdRepr::encode(&repr, &mut bytes_mut);
        let decoded = CmdRepr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_rep_invalid_len() {
        let mut truncated_bytes = vec![0x00 as u8; 4];
        let mut truncated = Packet::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::SOCKS5 as u8);
        truncated.set_atyp(Atyp::V4 as u8);
        assert_eq!(truncated.check_len(), Err(Error::Truncated));
        let mut truncated_bytes_mut = BytesMut::new();
        truncated_bytes_mut.extend(truncated_bytes);
        assert_eq!(RepRepr::decode(&mut truncated_bytes_mut), Ok(None));

        let mut truncated_bytes = vec![0x00 as u8; 5];
        let mut truncated = Packet::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::SOCKS5 as u8);
        truncated.set_atyp(Atyp::V4 as u8);
        assert_eq!(truncated.check_len(), Err(Error::Truncated));

        assert_eq!(truncated.total_len(), 10);
        let mut malformed_bytes = vec![0x00 as u8; truncated.total_len() + 1];
        let mut malformed = Packet::new_unchecked(&mut malformed_bytes);
        malformed.set_version(Ver::SOCKS5 as u8);
        malformed.set_atyp(Atyp::V4 as u8);
        assert_eq!(malformed.check_len(), Err(Error::Malformed));
        let mut malformed_bytes_mut = BytesMut::new();
        malformed_bytes_mut.extend(malformed_bytes);
        assert_eq!(
            RepRepr::decode(&mut malformed_bytes_mut),
            Err(Error::Malformed)
        );
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_rep_success_ip4() {
        let socket_addr = SocketAddr::new_ip4_port(127, 0, 0, 1, 80);
        let socks_addr = SocksAddr::SocketAddr(socket_addr);
        let repr = RepRepr {
            rep: Rep::Success,
            addr: socks_addr.clone(),
        };
        assert_eq!(repr.buffer_len(), 10);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::V4 as u8);
        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(0, 0, 0, 0).as_bytes());
        pkt.set_addr(Ipv4Address::new(192, 168, 0, 1).as_bytes());
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv4Address::new(192, 168, 0, 1).as_bytes()
        );
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.socks_addr_mut(), socks_addr.to_vec().as_slice());

        let pkt_to_parse = Packet::new_checked(pkt.as_ref()).expect("should be valid");
        assert_eq!(
            pkt_to_parse.addr(),
            Ipv4Address::new(127, 0, 0, 1).as_bytes()
        );
        let parsed = RepRepr::parse(&pkt_to_parse).expect("should parse");
        assert_eq!(parsed, repr);
        assert_eq!(parsed.addr.atyp(), Atyp::V4);
        if let SocksAddr::SocketAddr(SocketAddr::V4(socket_addr)) = parsed.addr {
            assert!(socket_addr.addr.is_loopback());
        }

        let mut bytes_mut = BytesMut::new();
        RepRepr::encode(&repr, &mut bytes_mut);
        let decoded = RepRepr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }

    #[cfg(feature = "proto-ipv6")]
    #[test]
    fn test_rep_success_ip6() {
        let socket_addr = SocketAddr::new_ip6_port(0, 0, 0, 0, 0, 0, 0, 1, 80);
        let socks_addr = SocksAddr::SocketAddr(socket_addr);
        let repr = RepRepr {
            rep: Rep::Success,
            addr: socks_addr.clone(),
        };
        assert_eq!(repr.buffer_len(), 22);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::V6 as u8);
        assert_eq!(pkt.atyp(), Atyp::V6 as u8);
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0).as_bytes()
        );
        pkt.set_addr(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).as_bytes());
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).as_bytes()
        );
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.socks_addr_mut(), socks_addr.to_vec().as_slice());

        let pkt_to_parse = Packet::new_checked(pkt.as_ref()).expect("should be valid");
        assert_eq!(
            pkt_to_parse.addr(),
            Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1).as_bytes()
        );
        let parsed = RepRepr::parse(&pkt_to_parse).expect("should parse");
        assert_eq!(parsed, repr);
        assert_eq!(parsed.addr.atyp(), Atyp::V6);
        if let SocksAddr::SocketAddr(SocketAddr::V6(socket_addr)) = parsed.addr {
            assert!(socket_addr.addr.is_loopback());
        }

        let mut bytes_mut = BytesMut::new();
        RepRepr::encode(&repr, &mut bytes_mut);
        let decoded = RepRepr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }

    #[test]
    fn test_rep_success_domain() {
        let socks_addr = SocksAddr::DomainPort("google.com".to_string(), 443);
        let repr = RepRepr {
            rep: Rep::Success,
            addr: socks_addr.clone(),
        };
        assert_eq!(repr.buffer_len(), 17);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::Domain as u8);
        assert_eq!(pkt.atyp(), Atyp::Domain as u8);
        assert_eq!(pkt.addr_mut()[0], 0);
        pkt.addr_mut()[0] = 10;
        assert_eq!(&pkt.addr_mut()[1..], b"\0\0\0\0\0\0\0\0\0\0");
        pkt.set_addr(b"          ");
        assert_eq!(&pkt.addr_mut()[1..], b"          ");
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.socks_addr_mut(), socks_addr.to_vec().as_slice());

        let pkt_to_parse = Packet::new_checked(pkt.as_ref()).expect("should be valid");
        assert_eq!(pkt_to_parse.addr()[0], 10);
        assert_eq!(&pkt_to_parse.addr()[1..], b"google.com");
        let parsed = RepRepr::parse(&pkt_to_parse).expect("should parse");
        assert_eq!(parsed, repr);
        assert_eq!(parsed.addr.atyp(), Atyp::Domain);
        if let SocksAddr::DomainPort(domain, port) = parsed.addr {
            assert_eq!(domain, "google.com".to_string());
            assert_eq!(port, 443);
        }

        let mut bytes_mut = BytesMut::new();
        RepRepr::encode(&repr, &mut bytes_mut);
        let decoded = RepRepr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }
}
