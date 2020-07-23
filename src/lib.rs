#[cfg_attr(test, macro_use)]
extern crate log;
#[macro_use]
extern crate serde_derive;

use core::convert::TryFrom;
use core::fmt;

use bytes::{Bytes, BytesMut};

pub use protocol::{
    Atyp, AuthReplyPacket, AuthReplyRepr, Cmd, CmdPacket, CmdRepr, Decoder as ProtocolDecoder,
    Encoder as ProtocolEncoder, Error as ProtocolError, HasAddr, Method, MethodPacket, MethodRepr,
    MethodsPacket, MethodsRepr, Rep, RepPacket, RepRepr, Rfc1929Ver, SocksAddr, Status, UdpFrag,
    UdpPacket, UdpRepr, UserPassPacket, UserPassRepr, Ver,
};

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
pub enum SocksReply {
    Method(MethodRepr),
    Auth(AuthReplyRepr),
    Rep(RepRepr),
    /// TCP data for CONNECT or BIND
    Bytes(Bytes),
}

impl From<MethodRepr> for SocksReply {
    fn from(val: MethodRepr) -> Self {
        SocksReply::Method(val)
    }
}

impl From<AuthReplyRepr> for SocksReply {
    fn from(val: AuthReplyRepr) -> Self {
        SocksReply::Auth(val)
    }
}

impl From<RepRepr> for SocksReply {
    fn from(val: RepRepr) -> Self {
        SocksReply::Rep(val)
    }
}

impl From<Bytes> for SocksReply {
    fn from(val: Bytes) -> Self {
        SocksReply::Bytes(val)
    }
}

impl TryFrom<SocksReply> for MethodRepr {
    type Error = Error;

    fn try_from(val: SocksReply) -> Result<Self, Error> {
        match val {
            SocksReply::Method(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<SocksReply> for AuthReplyRepr {
    type Error = Error;

    fn try_from(val: SocksReply) -> Result<Self, Error> {
        match val {
            SocksReply::Auth(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<SocksReply> for RepRepr {
    type Error = Error;

    fn try_from(val: SocksReply) -> Result<Self, Error> {
        match val {
            SocksReply::Rep(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<SocksReply> for Bytes {
    type Error = Error;

    fn try_from(val: SocksReply) -> Result<Self, Error> {
        match val {
            SocksReply::Bytes(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocksRequest {
    Methods(MethodsRepr),
    Auth(UserPassRepr),
    Cmd(CmdRepr),
    /// TCP data for CONNECT or BIND
    Bytes(Bytes),
}

impl From<MethodsRepr> for SocksRequest {
    fn from(val: MethodsRepr) -> Self {
        SocksRequest::Methods(val)
    }
}

impl From<UserPassRepr> for SocksRequest {
    fn from(val: UserPassRepr) -> Self {
        SocksRequest::Auth(val)
    }
}

impl From<CmdRepr> for SocksRequest {
    fn from(val: CmdRepr) -> Self {
        SocksRequest::Cmd(val)
    }
}

impl From<Bytes> for SocksRequest {
    fn from(val: Bytes) -> Self {
        SocksRequest::Bytes(val)
    }
}

impl TryFrom<SocksRequest> for MethodsRepr {
    type Error = Error;

    fn try_from(val: SocksRequest) -> Result<Self, Error> {
        match val {
            SocksRequest::Methods(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<SocksRequest> for UserPassRepr {
    type Error = Error;

    fn try_from(val: SocksRequest) -> Result<Self, Error> {
        match val {
            SocksRequest::Auth(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<SocksRequest> for CmdRepr {
    type Error = Error;

    fn try_from(val: SocksRequest) -> Result<Self, Error> {
        match val {
            SocksRequest::Cmd(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl TryFrom<SocksRequest> for Bytes {
    type Error = Error;

    fn try_from(val: SocksRequest) -> Result<Self, Error> {
        match val {
            SocksRequest::Bytes(val) => Ok(val),
            _ => Err(Error::TypeMismatch),
        }
    }
}

impl ProtocolEncoder<SocksRequest> for SocksRequest {
    fn encode(item: &SocksRequest, mut dst: &mut BytesMut) {
        // item.encode_into(dst);
        match item {
            SocksRequest::Methods(req) => MethodsRepr::encode(req, &mut dst),
            SocksRequest::Auth(req) => UserPassRepr::encode(req, &mut dst),
            SocksRequest::Cmd(req) => CmdRepr::encode(req, &mut dst),
            SocksRequest::Bytes(req) => dst.extend(req),
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
