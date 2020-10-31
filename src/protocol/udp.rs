use core::convert::TryFrom;
use std::io::Write;
use std::time::{Duration, SystemTime};

use bytes::{Buf, Bytes, BytesMut};

use smolsocket::port_from_bytes;

use crate::field::Field;

use super::{
    addr::field_port, CrateResult, Decoder, Encodable, Encoder, Error, field, HasAddr, SocksAddr,
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
    pub fn new_checked(buffer: T) -> CrateResult<Packet<T>> {
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
    pub fn check_header_len(&self) -> CrateResult<()> {
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

    pub fn take_buffer(self) -> T {
        self.0.take_buffer()
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
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> CrateResult<Repr> {
        packet.check_header_len()?;

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

/// A high-level representation of a UDP frag packet.
/// Header size (max for Domain):
/// IPv4   10 bytes  (RSV(2) + FRAG(1) + (ATYP(1) + IP4(4) + PORT(2)))
/// IPv6   22 bytes  (RSV(2) + FRAG(1) + (ATYP(1) + IP6(16) + PORT(2)))
/// Domain 262 bytes (RSV(2) + FRAG(1) + (ATYP(1) + Domain(255) + PORT(2)))
///
/// For IPv4
/// The maximum safe UDP payload is 508 bytes.
/// Tt is possible to include IP options which can increase the size of the IP header to as much as 60 bytes.
/// This is a packet size of 576, minus the maximum 60-byte IP header and the 8-byte UDP header.
/// Any UDP payload this size or smaller is guaranteed to be deliverable over IP (though not guaranteed to be delivered).
/// Anything larger is allowed to be outright dropped by any router for any reason.
/// Except on an IPv6-only route, where the maximum payload is 1,212 bytes.
/// As others have mentioned, additional protocol headers could be added in some circumstances.
/// A more conservative value of around 300-400 bytes may be preferred instead.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Frag {
    pub frag: u8,
    pub addr: SocksAddr,
    pub payload: Bytes,
}

impl Frag {
    pub fn max_safe_payload_size(addr: &SocksAddr) -> usize {
        let header_len = 3 + addr.total_len();
        // The maximum safe UDP payload is 508 bytes
        508 - header_len
    }

    /// not frag
    pub fn new(addr: SocksAddr, payload: Bytes) -> Self {
        Self { frag: 0x00, addr, payload }
    }

    // TODO user should be able to specify the max_safe_payload_size
    /// frags
    pub fn new_frags(addr: SocksAddr, payload: Bytes) -> Vec<Self> {
        let mut frags = Vec::new();
        let max_payload_len = Frag::max_safe_payload_size(&addr);
        if payload.len() <= max_payload_len {
            frags.push(Frag { frag: 0x00, addr, payload })
        } else {
            let mut frag = 0x01 as u8;
            let mut chunks = payload.chunks(max_payload_len).peekable();
            while let Some(chunk) = chunks.next() {
                if chunks.peek().is_some() {
                    frags.push(Frag {
                        frag,
                        addr: addr.clone(),
                        payload: Bytes::copy_from_slice(chunk),
                    });
                } else {
                    // last
                    frags.push(Frag {
                        frag: frag | 0b1000_0000,
                        addr: addr.clone(),
                        payload: Bytes::copy_from_slice(chunk),
                    })
                }
                frag += 0x01;
            }
        }
        frags
    }

    pub fn frag(&self) -> u8 {
        // frag & 0b0111_1111 (127)
        self.frag & 0b0111_1111
    }

    pub fn is_frag(&self) -> bool {
        self.frag != 0
    }

    pub fn is_last_frag(&self) -> bool {
        Frag::is_end_of_seq(self.frag)
    }

    pub fn is_end_of_seq(frag: u8) -> bool {
        frag & 0b1000_0000 != 0
    }

    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> CrateResult<Frag> {
        packet.check_header_len()?;

        if packet.rsv() != 0 as u16 {
            return Err(Error::Malformed);
        }
        let frag = packet.as_ref()[field::UDP_FRAG];
        if frag > 127 {
            return Err(Error::Malformed);
        }

        Ok(Frag {
            frag,
            addr: SocksAddr::try_from(packet.socks_addr())?,
            payload: Bytes::copy_from_slice(packet.data()),
        })
    }

    fn header_len(&self) -> usize {
        let addr_len = self.addr.addr_len();
        field_port(field::ADDR_PORT.start, addr_len).end
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        self.header_len() + self.payload.len()
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        // packet.set_rsv(0);
        packet.set_frag(self.frag);
        packet.set_socks_addr(&self.addr.to_vec());
        packet
            .data_mut()
            .write_all(self.payload.as_ref())
            .expect("should write whole payload");
    }
}

impl Decoder<Frag> for Frag {
    fn decode(src: &mut BytesMut) -> CrateResult<Option<Self>> {
        let pkt = Packet::new_unchecked(src.as_ref());
        match Frag::parse(&pkt) {
            Ok(frag) => {
                src.advance(frag.buffer_len());
                Ok(Some(frag))
            }
            Err(Error::Truncated) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Encodable for Frag {
    fn encode_into(&self, dst: &mut BytesMut) {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = Packet::new_unchecked(dst);
        self.emit(&mut pkt);
    }
}

impl Encoder<Frag> for Frag {
    fn encode(item: &Frag, dst: &mut BytesMut) {
        item.encode_into(dst);
    }
}


const DURATION_0: Duration = Duration::from_secs(0);

pub struct FragAssembler {
    pub(crate) slots: Vec<Option<Frag>>,
    pub(crate) highest: u8,
    pub(crate) time: Option<SystemTime>,
}

impl Default for FragAssembler {
    fn default() -> FragAssembler {
        FragAssembler {
            slots: vec![None; 127],
            highest: 0,
            time: None,
        }
    }
}

impl FragAssembler {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn is_frag(udp_frag: &Frag) -> bool {
        udp_frag.frag != 0
    }

    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            if slot.is_some() {
                slot.take().unwrap();
            }
        }
        self.highest = 0x00;
    }

    pub fn on_frag(&mut self, udp_frag: Frag, now: &SystemTime) -> Option<Vec<Frag>> {
        if !udp_frag.is_frag() {
            return Some(vec![udp_frag]);
        }

        let frag = udp_frag.frag();
        let time_ok = self.time.map_or(true, |time| now.duration_since(time).unwrap_or(DURATION_0).as_secs() < 10);
        if frag > self.highest && time_ok {
            if udp_frag.is_last_frag() {
                if frag == self.highest + 1 {
                    let mut result = Vec::with_capacity(127);
                    for slot in &mut self.slots {
                        if slot.is_some() {
                            result.push(slot.take().unwrap());
                        } else {
                            break;
                        }
                    }
                    result.push(udp_frag);
                    self.highest = 0;
                    Some(result)
                } else {
                    self.clear();
                    None
                }
            } else {
                if self.highest == 0 {
                    self.time = Some(*now);
                }
                self.slots[frag as usize - 1] = Some(udp_frag);
                self.highest = frag;
                None
            }
        } else {
            self.clear();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    #[cfg(feature = "proto-ipv4")]
    use smoltcp::wire::Ipv4Address;

    #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
    use smolsocket::SocketAddr;

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
        assert_eq!(Frag::decode(&mut truncated_bytes_mut), Ok(None));

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
            Frag::decode(&mut malformed_bytes_mut),
            Err(Error::Malformed)
        );
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_repr_data_len_0() {
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

        let repr = Repr {
            frag: 0,
            addr: addr.clone(),
            payload_len: 0,
        };
        let mut bytes_mut = BytesMut::new();
        bytes_mut.resize(repr.buffer_len(), 0x00);
        let mut pkt = Packet::new_unchecked(bytes_mut);
        repr.emit(&mut pkt);
        pkt.set_frag(128);
        let bytes_mut = pkt.take_buffer();
        assert_eq!(
            Repr::parse(&Packet::new_unchecked(bytes_mut.as_ref())),
            Err(Error::Malformed)
        );

        let frag = Repr {
            frag: 0,
            addr,
            payload_len: 0,
        };
        let mut bytes_mut = BytesMut::new();
        bytes_mut.resize(frag.buffer_len(), 0x00);
        let mut pkt = Packet::new_unchecked(bytes_mut);
        frag.emit(&mut pkt);
        let mut bytes_mut = pkt.take_buffer();
        bytes_mut[0] = 0x01;
        assert_eq!(
            Repr::parse(&Packet::new_unchecked(bytes_mut.as_ref())),
            Err(Error::Malformed)
        );
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_frag_data_len_0() {
        let socket_addr = SocketAddr::new_ip4_port(127, 0, 0, 1, 80);
        let addr = SocksAddr::SocketAddr(socket_addr);
        let frag = Frag {
            frag: 0,
            addr: addr.clone(),
            payload: Bytes::new(),
        };
        assert_eq!(frag.addr.total_len(), 7);
        assert_eq!(frag.buffer_len(), 10);
        let mut bytes = vec![0x00 as u8; frag.buffer_len()];
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

        frag.emit(&mut pkt);
        assert_eq!(pkt.field_data(), 10..10);
        assert_eq!(pkt.data_mut().len(), 0);
        assert_eq!(Packet::new_checked(pkt.as_ref()).unwrap().data().len(), 0);

        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(127, 0, 0, 1).as_bytes());
        assert_eq!(pkt.port(), 80);
        assert_eq!(&pkt.socks_addr_mut(), &addr.to_vec().as_slice());

        let parsed = Frag::parse(&Packet::new_checked(pkt.buffer_ref()).unwrap()).unwrap();
        assert_eq!(parsed, frag);

        let mut bytes_mut = BytesMut::new();
        Frag::encode(&frag, &mut bytes_mut);
        let decoded = Frag::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(frag)));

        let frag = Frag {
            frag: 0,
            addr: addr.clone(),
            payload: Bytes::new(),
        };
        let mut bytes_mut = BytesMut::new();
        bytes_mut.resize(frag.buffer_len(), 0x00);
        let mut pkt = Packet::new_unchecked(bytes_mut);
        frag.emit(&mut pkt);
        pkt.set_frag(128);
        let bytes_mut = pkt.take_buffer();
        assert_eq!(
            Frag::parse(&Packet::new_unchecked(bytes_mut.as_ref())),
            Err(Error::Malformed)
        );

        let frag = Frag {
            frag: 0,
            addr,
            payload: Bytes::new(),
        };
        let mut bytes_mut = BytesMut::new();
        bytes_mut.resize(frag.buffer_len(), 0x00);
        let mut pkt = Packet::new_unchecked(bytes_mut);
        frag.emit(&mut pkt);
        let mut bytes_mut = pkt.take_buffer();
        bytes_mut[0] = 0x01;
        assert_eq!(
            Frag::parse(&Packet::new_unchecked(bytes_mut.as_ref())),
            Err(Error::Malformed)
        );
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_repr_data_len_1() {
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
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_frag_data_len_1() {
        let socket_addr = SocketAddr::new_ip4_port(127, 0, 0, 1, 80);
        let addr = SocksAddr::SocketAddr(socket_addr);
        let frag = Frag {
            frag: 0,
            addr: addr.clone(),
            payload: Bytes::from(vec![0xFF]),
        };
        assert_eq!(frag.addr.total_len(), 7);
        assert_eq!(frag.buffer_len(), 11);
        let mut bytes = vec![0x00 as u8; frag.buffer_len()];
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

        frag.emit(&mut pkt);
        assert_eq!(pkt.field_data(), 10..11);
        assert_eq!(pkt.data_mut().len(), 1);
        assert_eq!(Packet::new_checked(pkt.as_ref()).unwrap().data().len(), 1);

        assert_eq!(pkt.atyp(), Atyp::V4 as u8);
        assert_eq!(&pkt.addr_mut(), &Ipv4Address::new(127, 0, 0, 1).as_bytes());
        assert_eq!(pkt.port(), 80);
        assert_eq!(&pkt.socks_addr_mut(), &addr.to_vec().as_slice());

        let parsed = Frag::parse(&Packet::new_checked(pkt.buffer_ref()).unwrap()).unwrap();
        assert_eq!(parsed, frag);

        let mut bytes_mut = BytesMut::new();
        Frag::encode(&frag, &mut bytes_mut);
        let decoded = Frag::decode(&mut bytes_mut);
        assert_eq!(decoded, Ok(Some(frag)));
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    pub fn test_frag_assembler() {
        let now = SystemTime::now();
        let socket_addr = SocketAddr::new_ip4_port(127, 0, 0, 1, 80);
        let addr = SocksAddr::SocketAddr(socket_addr);
        let payload = vec![0x00; 1000];
        let frags = Frag::new_frags(addr, payload.into());
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0].frag, 1);
        assert_eq!(frags[0].frag(), 1);
        assert_eq!(frags[0].is_last_frag(), false);
        assert_eq!(frags[1].frag, 2);
        assert_eq!(frags[1].frag(), 2);
        assert_eq!(frags[1].is_last_frag(), false);
        assert_eq!(frags[2].frag(), 3);
        assert_eq!(frags[2].frag, 0b1000_0000 | 3);
        assert_eq!(frags[2].is_last_frag(), true);
        let mut assembler = FragAssembler::default();
        assert_eq!(assembler.on_frag(frags[0].clone(), &now), None);
        assert_eq!(assembler.slots[0], Some(frags[0].clone()));
        assert_eq!(assembler.on_frag(frags[1].clone(), &now), None);
        assert_eq!(assembler.slots[1], Some(frags[1].clone()));
        assert_eq!(
            assembler.on_frag(frags[2].clone(), &now),
            Some(vec![frags[0].clone(), frags[1].clone(), frags[2].clone()])
        );

        let mut assembler = FragAssembler::default();
        assert_eq!(assembler.on_frag(frags[2].clone(), &now), None);
        assert_eq!(assembler.slots[2], None);
        assert_eq!(assembler.highest, 0);

        let mut assembler = FragAssembler::default();
        assert_eq!(assembler.on_frag(frags[1].clone(), &now), None);
        assert_eq!(assembler.slots[1], Some(frags[1].clone()));
        assert_eq!(assembler.highest, 2);
        // smaller frag received, clear
        assert_eq!(assembler.on_frag(frags[0].clone(), &now), None);
        assert_eq!(assembler.slots[0], None);
        assert_eq!(assembler.slots[1], None);
        assert_eq!(assembler.highest, 0);
    }
}
