use core::convert::TryFrom;

use bytes::{Buf, BytesMut};
use smolsocket::port_from_bytes;

use crate::field::Field;

use super::{
    addr::field_port, field, Decoder, Encodable, Encoder, Error, HasAddr, Result, SocksAddr,
};

//
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
//
// The fields in the UDP request header are:
//
//   o  RSV  Reserved X'0000'
//   o  FRAG    Current fragment number
//   o  ATYP    address type of following addresses:
//      o  IP V4 address: X'01'
//      o  DOMAINNAME: X'03'
//   o  IP V6 address: X'04'
//   o  DST.ADDR       desired destination address
//   o  DST.PORT       desired destination port
//   o  DATA     user data
//
// When a UDP relay server decides to relay a UDP datagram, it does so
// silently, without any notification to the requesting client.
// Similarly, it will drop datagrams it cannot or will not relay.  When
// a UDP relay server receives a reply datagram from a remote host, it
// MUST encapsulate that datagram using the above UDP request header,
// and any authentication-method-dependent encapsulation.
//
// The UDP relay server MUST acquire from the SOCKS server the expected
// IP address of the client that will send datagrams to the BND.PORT
// given in the reply to UDP ASSOCIATE.  It MUST drop any datagrams
// arriving from any source IP address other than the one recorded for
// the particular association.
//
// The FRAG field indicates whether or not this datagram is one of a
// number of fragments.  If implemented, the high-order bit indicates
// end-of-fragment sequence, while a value of X'00' indicates that this
// datagram is standalone.  Values between 1 and 127 indicate the
// fragment position within a fragment sequence.  Each receiver will
// have a REASSEMBLY QUEUE and a REASSEMBLY TIMER associated with these
// fragments.  The reassembly queue must be reinitialized and the
// associated fragments abandoned whenever the REASSEMBLY TIMER expires,
// or a new datagram arrives carrying a FRAG field whose value is less
// than the highest FRAG value processed for this fragment sequence.
// The reassembly timer MUST be no less than 5 seconds.  It is
// recommended that fragmentation be avoided by applications wherever
// possible.
//
// Implementation of fragmentation is optional; an implementation that
// does not support fragmentation MUST drop any datagram whose FRAG
// field is other than X'00'.
// The programming interface for a SOCKS-aware UDP MUST report an
// available buffer space for UDP datagrams that is smaller than the
// actual space provided by the operating system:
//
//   o  if ATYP is X'01' - 10+method_dependent octets smaller
//   o  if ATYP is X'03' - 262+method_dependent octets smaller
//   o  if ATYP is X'04' - 20+method_dependent octets smaller
//
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: AsRef<[u8]>>(HasAddr<T>);

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with RFC1928 UDP packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet(HasAddr::new_unchecked(field::ATYP, buffer))
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_header_len()?;
        Ok(packet)
    }

    fn buffer_ref(&self) -> &[u8] {
        self.0.buffer.as_ref()
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_socks_addr]
    ///
    /// [set_methods]: #method.set_socks_addr
    pub fn check_header_len(&self) -> Result<()> {
        self.0.check_addr_len()
    }

    /// Return the header length (without length of data) (unchecked).
    #[inline]
    pub fn header_len(&self) -> usize {
        self.0.len_to_port()
    }

    /// Return the data field (unchecked).
    #[inline]
    fn field_data(&self) -> Field {
        let start = self.0.field_port().end;
        start..self.0.buffer.as_ref().len()
    }

    /// Return the rsv field.
    #[inline]
    pub fn rsv(&self) -> u16 {
        let data = self.buffer_ref();
        let rsv_bytes = &data[field::UDP_RSV];
        port_from_bytes(rsv_bytes[0], rsv_bytes[1])
    }

    /// Return the frag.
    #[inline]
    pub fn frag(&self) -> u8 {
        let data = self.buffer_ref();
        data[field::UDP_FRAG]
    }

    /// Return the atyp.
    #[inline]
    pub fn atyp(&self) -> u8 {
        self.0.atyp()
    }

    /// Return the dst port of request or bnd port of reply (unchecked).
    #[inline]
    pub fn port(&self) -> u16 {
        self.0.port()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the addr (unchecked).
    #[inline]
    pub fn addr(&self) -> &'a [u8] {
        self.0.addr()
    }

    /// Return a pointer to the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn socks_addr(&self) -> &'a [u8] {
        self.0.socks_addr()
    }

    /// Return a pointer to the data (unchecked).
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let field = self.field_data();
        let data = self.0.buffer.as_ref();
        &data[field]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    fn buffer_mut(&mut self) -> &mut [u8] {
        self.0.buffer.as_mut()
    }

    /// Set the frag.
    #[inline]
    pub fn set_frag(&mut self, value: u8) {
        let data = self.buffer_mut();
        data[field::UDP_FRAG] = value;
    }

    /// Set the atyp.
    #[inline]
    pub fn set_atyp(&mut self, value: u8) {
        self.0.set_atyp(value)
    }

    /// Set the addr (unchecked).
    #[inline]
    pub fn set_addr(&mut self, value: &[u8]) {
        self.0.set_addr(value)
    }

    /// Set the port (unchecked).
    #[inline]
    pub fn set_port(&mut self, value: u16) {
        self.0.set_port(value)
    }

    /// Set the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn set_socks_addr(&mut self, value: &[u8]) {
        self.0.set_socks_addr(value)
    }

    /// Return a mutable pointer to the addr (unchecked).
    #[inline]
    pub fn addr_mut(&mut self) -> &mut [u8] {
        self.0.addr_mut()
    }

    /// Return a mutable pointer to the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn socks_addr_mut(&mut self) -> &mut [u8] {
        self.0.socks_addr_mut()
    }

    /// Return a mutable pointer to the data (unchecked).
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let field = self.field_data();
        let data = self.buffer_mut();
        &mut data[field]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.buffer_ref()
    }
}

/// A high-level representation of a UDP frag packet header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Repr {
    pub frag: u8,
    pub addr: SocksAddr,
    pub payload_len: usize,
}

impl Repr {
    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<Repr> {
        packet.check_header_len()?;

        // Version 5 is expected.
        if packet.rsv() != 0 as u16 {
            return Err(Error::Malformed);
        }
        let frag = packet.as_ref()[field::UDP_FRAG];
        if frag > 127 {
            return Err(Error::Malformed);
        }

        Ok(Repr {
            frag,
            addr: SocksAddr::try_from(packet.socks_addr())?,
            payload_len: packet.as_ref().len() - packet.header_len(),
        })
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let addr_len = self.addr.addr_len();
        field_port(field::ADDR_PORT.start, addr_len).end + self.payload_len
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        // packet.set_rsv(0);
        packet.set_frag(self.frag);
        packet.set_socks_addr(&self.addr.to_vec());
    }
}

impl Decoder<Repr> for Repr {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>> {
        let pkt = Packet::new_unchecked(src.as_ref());
        match Repr::parse(&pkt) {
            Ok(repr) => {
                src.advance(repr.buffer_len());
                Ok(Some(repr))
            }
            Err(Error::Truncated) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Encodable for Repr {
    fn encode_into(&self, dst: &mut BytesMut) {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = Packet::new_unchecked(dst);
        self.emit(&mut pkt);
    }
}

impl Encoder<Repr> for Repr {
    fn encode(item: &Repr, dst: &mut BytesMut) {
        item.encode_into(dst);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
    use smolsocket::SocketAddr;
    #[cfg(feature = "proto-ipv4")]
    use smoltcp::wire::Ipv4Address;

    use crate::Atyp;

    use super::*;

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_udp_invalid_len() {
        let mut truncated_bytes = vec![0x00 as u8; 4];
        let mut truncated = Packet::new_unchecked(&mut truncated_bytes);
        truncated.set_frag(0);
        truncated.set_atyp(Atyp::V4 as u8);
        assert_eq!(truncated.check_header_len(), Err(Error::Truncated));
        let mut truncated_bytes_mut = BytesMut::new();
        truncated_bytes_mut.extend(truncated_bytes);
        assert_eq!(Repr::decode(&mut truncated_bytes_mut), Ok(None));

        let mut truncated_bytes = vec![0x00 as u8; 5];
        let mut truncated = Packet::new_unchecked(&mut truncated_bytes);
        truncated.set_frag(0);
        truncated.set_atyp(Atyp::V4 as u8);
        assert_eq!(truncated.check_header_len(), Err(Error::Truncated));

        assert_eq!(truncated.header_len(), 10);
        let mut malformed_bytes = vec![0x00 as u8; truncated.header_len()];
        let mut malformed = Packet::new_unchecked(&mut malformed_bytes);
        malformed.set_frag(0);
        malformed.set_atyp(0); // invalid atyp
        assert_eq!(malformed.check_header_len(), Err(Error::Malformed));
        let mut malformed_bytes_mut = BytesMut::new();
        malformed_bytes_mut.extend(malformed_bytes);
        assert_eq!(
            Repr::decode(&mut malformed_bytes_mut),
            Err(Error::Malformed)
        );
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_data_len_0() {
        let socket_addr = SocketAddr::new_ip4_port(127, 0, 0, 1, 80);
        let addr = SocksAddr::SocketAddr(socket_addr);
        let repr = Repr {
            frag: 0,
            addr: addr.clone(),
            payload_len: 0,
        };
        assert_eq!(repr.addr.total_len(), 7);
        assert_eq!(repr.buffer_len(), 10);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(pkt.frag(), 0);
        pkt.set_frag(1);
        assert_eq!(pkt.frag(), 1);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::V4 as u8);
        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(0, 0, 0, 0).as_bytes());
        pkt.set_addr(Ipv4Address::new(192, 168, 0, 1).as_bytes());
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv4Address::new(192, 168, 0, 1).as_bytes()
        );
        assert_eq!(
            &Packet::new_unchecked(pkt.as_ref()).addr(),
            &Ipv4Address::new(192, 168, 0, 1).as_bytes()
        );
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.field_data(), 10..10);
        assert_eq!(pkt.data_mut().len(), 0);
        assert_eq!(Packet::new_checked(pkt.as_ref()).unwrap().data().len(), 0);

        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(127, 0, 0, 1).as_bytes());
        assert_eq!(pkt.port(), 80);
        assert_eq!(&pkt.socks_addr_mut(), &addr.to_vec().as_slice());

        let parsed = Repr::parse(&Packet::new_checked(pkt.buffer_ref()).unwrap()).unwrap();
        assert_eq!(parsed, repr);

        let mut bytes_mut = BytesMut::new();
        Repr::encode(&repr, &mut bytes_mut);
        let decoded = Repr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_data_len_1() {
        let socket_addr = SocketAddr::new_ip4_port(127, 0, 0, 1, 80);
        let addr = SocksAddr::SocketAddr(socket_addr);
        let repr = Repr {
            frag: 0,
            addr: addr.clone(),
            payload_len: 1,
        };
        assert_eq!(repr.addr.total_len(), 7);
        assert_eq!(repr.buffer_len(), 11);
        let mut bytes = vec![0x00 as u8; repr.buffer_len()];
        let mut pkt = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(pkt.frag(), 0);
        pkt.set_frag(1);
        assert_eq!(pkt.frag(), 1);
        assert_eq!(pkt.atyp(), 0);
        pkt.set_atyp(Atyp::V4 as u8);
        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(0, 0, 0, 0).as_bytes());
        pkt.set_addr(Ipv4Address::new(192, 168, 0, 1).as_bytes());
        assert_eq!(
            &pkt.addr_mut(),
            &Ipv4Address::new(192, 168, 0, 1).as_bytes()
        );
        assert_eq!(
            &Packet::new_unchecked(pkt.as_ref()).addr(),
            &Ipv4Address::new(192, 168, 0, 1).as_bytes()
        );
        assert_eq!(pkt.port(), 0);
        pkt.set_port(8080);
        assert_eq!(pkt.port(), 8080);

        repr.emit(&mut pkt);
        assert_eq!(pkt.field_data(), 10..11);
        assert_eq!(pkt.data_mut().len(), 1);
        assert_eq!(Packet::new_checked(pkt.as_ref()).unwrap().data().len(), 1);

        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(127, 0, 0, 1).as_bytes());
        assert_eq!(pkt.port(), 80);
        assert_eq!(&pkt.socks_addr_mut(), &addr.to_vec().as_slice());

        let parsed = Repr::parse(&Packet::new_checked(pkt.buffer_ref()).unwrap()).unwrap();
        assert_eq!(parsed, repr);

        let mut bytes_mut = BytesMut::new();
        Repr::encode(&repr, &mut bytes_mut);
        let decoded = Repr::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(repr)));
    }
}
