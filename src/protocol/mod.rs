use core::convert::TryFrom;
use core::fmt;

use bytes::BytesMut;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use snafu::Snafu;

pub use addr::{Addr as SocksAddr, HasAddr};
pub use cmd_rep::{
    CmdRepr, Packet as CmdPacket,
    RepRepr, Packet as RepPacket
};
pub use method_selection::{
    ReplyPacket as MethodPacket, ReplyRepr as MethodRepr,
    RequestPacket as MethodsPacket, RequestRepr as MethodsRepr,
};
pub use rfc1929::{
    ReplyPacket as AuthReplyPacket, ReplyRepr as AuthReplyRepr, RequestPacket as UserPassPacket,
    RequestRepr as UserPassRepr,
    Status,
    Ver as Rfc1929Ver
};
pub use udp::{Packet as UdpPacket, Repr as UdpRepr};

mod addr;
mod cmd_rep;
mod method_selection;
mod rfc1929;
mod udp;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Malformed,
    Truncated,
    #[cfg(not(all(feature = "proto-ipv4", feature = "proto-ipv6")))]
    UnsupportedAtyp,
    AddrParseError,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_val: std::str::Utf8Error) -> Self {
        Error::Malformed
    }
}

impl From<smolsocket::Error> for Error {
    fn from(_val: smolsocket::Error) -> Self {
        Error::AddrParseError
    }
}

// pub(crate) type OptionResult<T> = core::result::Result<Option<T>, Error>;
pub(crate) type Result<T> = core::result::Result<T, Error>;

mod field {
    use crate::field::*;

    pub const VER: usize = 0;

    /// method selection request
    pub const NMETHODS: usize = 1;
    /// method selection request
    pub const METHODS: Rest = 2..;

    pub fn methods(nmethods: u8) -> Field {
        2..2 + nmethods as usize
    }

    /// the method server selected
    pub const METHOD: usize = 1;

    /// request CMD or reply REP
    pub const CMD_OR_REP: usize = 1;
    /// request RSV, reply RSV
    pub const RSV: usize = 2;
    /// request ATYP, reply ATYP, udp_frag ATYP
    pub const ATYP: usize = 3;
    // pub const DOMAIN_LEN: usize = 4;
    /// request or reply ADDR_PORT (DOMAIN_LEN if address is domain:port) (Variable, length of ADDR depends on ATYP, PORT is always u16)
    pub const ADDR_PORT: Rest = 4..;
    // pub const IP4_ADDR_PORT: Field = 4..10;
    // pub const IP4_ADDR: Field = 4..8;
    // pub const IP4_PORT: Field = 8..10;
    // pub const IP6_ADDR_PORT: Field = 4..22;
    // pub const IP6_ADDR: Field = 4..20;
    // pub const IP6_PORT: Field = 20..22;

    /// udp_frag RSV
    pub const UDP_RSV: Field = 0..2;
    /// udp_frag FRAG
    pub const UDP_FRAG: usize = 2;
    // udp_frag (Variable, length of ADDR depends on ATYP, PORT is always u16)
    // pub const UDP_ADDR_PORT_DATA: Rest = 4..;
    // pub const UDP_IP4_DATA: Rest = 10..;
    // pub const UDP_IP6_DATA: Rest = 22..;

    /// rfc1929 request ULEN
    pub const ULEN: usize = 1;
    /// rfc1929 request UNAME, PLEN, and PASSWD
    pub const UNAME_PLEN_PASSWD: Rest = 2..;
    /// rfc1929 reply STATUS
    pub const STATUS: usize = 1;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq, Serialize, Snafu)]
#[repr(u8)]
pub enum Ver {
    #[snafu(display("Socks4"))]
    SOCKS4 = 0x04,
    #[snafu(display("Socks5"))]
    SOCKS5 = 0x05,
}

impl TryFrom<u8> for Ver {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        FromPrimitive::from_u8(val).ok_or(Error::Malformed)
    }
}

impl Into<u8> for &Ver {
    fn into(self) -> u8 {
        *self as u8
    }
}

impl From<Ver> for u8 {
    fn from(val: Ver) -> Self {
        val as u8
    }
}

// The values currently defined for METHOD are:
//
// o  X'00' NO AUTHENTICATION REQUIRED
// o  X'01' GSSAPI
// o  X'02' USERNAME/PASSWORD
// o  X'03' to X'7F' IANA ASSIGNED
// o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
// o  X'FF' NO ACCEPTABLE METHODS
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq, Serialize, Snafu)]
#[repr(u8)]
pub enum Method {
    #[snafu(display("NO AUTHENTICATION REQUIRED"))]
    NoAuth = 0x00,
    #[snafu(display("GSSAPI"))]
    GssApi = 0x01,
    #[snafu(display("USERNAME/PASSWORD"))]
    UserPass = 0x02,
    // X'03' to X'7F' IANA ASSIGNED
    // X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    #[snafu(display("NO ACCEPTABLE METHODS"))]
    NoMethods = 0xFF,
}

impl Method {
    pub fn try_from_slice(methods: &[u8]) -> Result<Vec<Method>> {
        let mut result = Vec::with_capacity(methods.len());
        for var in methods {
            result.push(Method::try_from(*var)?);
        }
        Ok(result)
    }
}

impl TryFrom<u8> for Method {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        FromPrimitive::from_u8(val).ok_or(Error::Malformed)
    }
}

impl From<Method> for u8 {
    fn from(val: Method) -> Self {
        val as u8
    }
}

impl From<&Method> for u8 {
    fn from(val: &Method) -> Self {
        *val as u8
    }
}

trait ToU8Vec<T> {
    fn to_u8_vec(&self) -> Vec<u8>;
}

impl ToU8Vec<Method> for &[Method] {
    fn to_u8_vec(&self) -> Vec<u8> {
        self.iter().map(|&m| m as u8).collect()
    }
}

/// SOCK5 CMD Type
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq, Serialize, Snafu)]
#[repr(u8)]
pub enum Cmd {
    #[snafu(display("Connect"))]
    Connect = 0x01,
    #[snafu(display("Bind"))]
    Bind = 0x02,
    #[snafu(display("UDP associate"))]
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Cmd {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        FromPrimitive::from_u8(val).ok_or(Error::Malformed)
    }
}

impl From<Cmd> for u8 {
    fn from(val: Cmd) -> Self {
        val as u8
    }
}

// Addressing
// In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
// the type of address contained within the field:
//
// o  X'01'
// the address is a version-4 IP address, with a length of 4 octets
//
// o  X'03'
// the address field contains a fully-qualified domain name.  The first
// octet of the address field contains the number of octets of name that
// follow, there is no terminating NUL octet.
//
// o  X'04'
// the address is a version-6 IP address, with a length of 16 octets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq, Serialize, Snafu)]
#[repr(u8)]
pub enum Atyp {
    #[snafu(display("IPv4"))]
    V4 = 0x01,
    #[snafu(display("Domain"))]
    Domain = 0x03,
    #[snafu(display("IPv6"))]
    V6 = 0x04,
}

impl TryFrom<u8> for Atyp {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        FromPrimitive::from_u8(val).ok_or(Error::Malformed)
    }
}

impl From<Atyp> for u8 {
    fn from(val: Atyp) -> Self {
        val as u8
    }
}

//     Where:
//
//          o  VER    protocol version: X'05'
//          o  REP    Reply field:
//             o  X'00' succeeded
//             o  X'01' general SOCKS server failure
//             o  X'02' connection not allowed by ruleset
//             o  X'03' Network unreachable
//             o  X'04' Host unreachable
//             o  X'05' Connection refused
//             o  X'06' TTL expired
//             o  X'07' Command not supported
//             o  X'08' Address type not supported
//             o  X'09' to X'FF' unassigned
//             o  RSV    RESERVED
//             o  ATYP   address type of following address
//             o  IP V4 address: X'01'
//             o  DOMAINNAME: X'03'
//             o  IP V6 address: X'04'
//          o  BND.ADDR       server bound address
//          o  BND.PORT       server bound port in network octet order
//
// Fields marked RESERVED (RSV) must be set to X'00'.
//
// If the chosen method includes encapsulation for purposes of
// authentication, integrity and/or confidentiality, the replies are
// encapsulated in the method-dependent encapsulation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq, Serialize, Snafu)]
#[repr(u8)]
pub enum Rep {
    #[snafu(display("Succeeded"))]
    Success = 0x00,
    #[snafu(display("General SOCKS server failure"))]
    Failure = 0x01,
    #[snafu(display("Connection not allowed by ruleset"))]
    RuleFailure = 0x02,
    #[snafu(display("Network unreachable"))]
    NetworkUnreachable = 0x03,
    #[snafu(display("Host unreachable"))]
    HostUnreachable = 0x04,
    #[snafu(display("Connection refused"))]
    ConnectionRefused = 0x05,
    #[snafu(display("TTL expired"))]
    TtlExpired = 0x06,
    #[snafu(display("Command not supported"))]
    CommandNotSupported = 0x07,
    #[snafu(display("Address type not supported"))]
    AddrTypeNotSupported = 0x08,
    // X'09' to X'FF' unassigned
}

impl TryFrom<u8> for Rep {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        FromPrimitive::from_u8(val).ok_or(Error::Malformed)
    }
}

impl From<Rep> for u8 {
    fn from(val: Rep) -> Self {
        val as u8
    }
}

pub(crate) trait Encodable {
    fn try_encode(&self, dst: &mut BytesMut) -> Result<()>;
}

pub trait Encoder<Item> {
    fn encode(item: &Item, dst: &mut BytesMut) -> Result<()>;
}

pub trait Decoder<Item> {
    fn decode(src: &mut BytesMut) -> Result<Option<Item>>;
}
