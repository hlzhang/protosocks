#[cfg_attr(test, macro_use)]
extern crate log;
#[macro_use]
extern crate serde_derive;

use core::convert::TryFrom;
use core::fmt;

use bytes::{Bytes, BytesMut};

pub use protocol::{
    Atyp, AuthReplyPacket,
    AuthReplyRepr, Cmd, CmdPacket, CmdRepr, Decoder as ProtocolDecoder, Encoder as ProtocolEncoder, Error as ProtocolError,
    HasAddr, Method, MethodPacket, MethodRepr, MethodsPacket, MethodsRepr,
    Rep, RepPacket, RepRepr, Rfc1929Ver, SocksAddr, Status, UdpFrag,
    UdpFragAssembler, UdpPacket, UdpRepr, UserPassPacket, UserPassRepr, Ver,
};
#[cfg(all(feature = "dns", feature = "std"))]
pub use protocol::DnsResolver;
#[cfg(all(feature = "dns", feature = "rt_tokio", feature = "std"))]
pub use protocol::resolve_domain_async;

pub(crate) mod protocol;

pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    TypeMismatch,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#?}", self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Method(MethodRepr),
    Auth(AuthReplyRepr),
    Rep(RepRepr),
    /// TCP data for CONNECT or BIND
    Bytes(Bytes),
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Reply::Method(val) => write!(f, "Reply::Method({})", val),
            Reply::Auth(val) => write!(f, "Reply::Auth({})", val),
            Reply::Rep(val) => write!(f, "Reply::Rep({})", val),
            Reply::Bytes(val) => write!(f, "Reply::Bytes({} bytes)", val.len()),
        }
    }
}

impl From<MethodRepr> for Reply {
    fn from(val: MethodRepr) -> Self {
        Reply::Method(val)
    }
}

impl From<AuthReplyRepr> for Reply {
    fn from(val: AuthReplyRepr) -> Self {
        Reply::Auth(val)
    }
}

impl From<RepRepr> for Reply {
    fn from(val: RepRepr) -> Self {
        Reply::Rep(val)
    }
}

impl From<Bytes> for Reply {
    fn from(val: Bytes) -> Self {
        Reply::Bytes(val)
    }
}

impl TryFrom<Reply> for MethodRepr {
    type Error = Error;

    fn try_from(val: Reply) -> Result<Self, Error> {
        match val {
            Reply::Method(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<Reply> for AuthReplyRepr {
    type Error = Error;

    fn try_from(val: Reply) -> Result<Self, Error> {
        match val {
            Reply::Auth(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<Reply> for RepRepr {
    type Error = Error;

    fn try_from(val: Reply) -> Result<Self, Error> {
        match val {
            Reply::Rep(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<Reply> for Bytes {
    type Error = Error;

    fn try_from(val: Reply) -> Result<Self, Error> {
        match val {
            Reply::Bytes(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Methods(MethodsRepr),
    Auth(UserPassRepr),
    Cmd(CmdRepr),
    /// TCP data for CONNECT or BIND
    Bytes(Bytes),
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Request::Methods(val) => write!(f, "Request::Methods({})", val),
            Request::Auth(val) => write!(f, "Request::Auth({})", val),
            Request::Cmd(val) => write!(f, "Request::Cmd({})", val),
            Request::Bytes(val) => write!(f, "Request::Bytes({} bytes)", val.len()),
        }
    }
}

impl From<MethodsRepr> for Request {
    fn from(val: MethodsRepr) -> Self {
        Request::Methods(val)
    }
}

impl From<UserPassRepr> for Request {
    fn from(val: UserPassRepr) -> Self {
        Request::Auth(val)
    }
}

impl From<CmdRepr> for Request {
    fn from(val: CmdRepr) -> Self {
        Request::Cmd(val)
    }
}

impl From<Bytes> for Request {
    fn from(val: Bytes) -> Self {
        Request::Bytes(val)
    }
}

impl TryFrom<Request> for MethodsRepr {
    type Error = Error;

    fn try_from(val: Request) -> Result<Self, Error> {
        match val {
            Request::Methods(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<Request> for UserPassRepr {
    type Error = Error;

    fn try_from(val: Request) -> Result<Self, Error> {
        match val {
            Request::Auth(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<Request> for CmdRepr {
    type Error = Error;

    fn try_from(val: Request) -> Result<Self, Error> {
        match val {
            Request::Cmd(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<Request> for Bytes {
    type Error = Error;

    fn try_from(val: Request) -> Result<Self, Error> {
        match val {
            Request::Bytes(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl ProtocolEncoder<Request> for Request {
    fn encode(item: &Request, mut dst: &mut BytesMut) {
        // item.encode_into(dst);
        match item {
            Request::Methods(req) => MethodsRepr::encode(req, &mut dst),
            Request::Auth(req) => UserPassRepr::encode(req, &mut dst),
            Request::Cmd(req) => CmdRepr::encode(req, &mut dst),
            Request::Bytes(req) => dst.extend(req),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
