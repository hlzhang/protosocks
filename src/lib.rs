#[cfg_attr(test, macro_use)]
extern crate log;
#[macro_use]
extern crate serde_derive;

use core::convert::TryFrom;
use core::fmt;

use bytes::{Bytes, BytesMut};

pub use protocol::{
    Atyp, AuthReplyPacket,
    AuthReplyRepr, Cmd, CmdPacket, CmdRepr, Decoder as ProtocolDecoder, Encoder as ProtocolEncoder,
    HasAddr, Method, MethodPacket, MethodRepr, MethodsPacket, MethodsRepr,
    Rep, RepPacket, RepRepr, Rfc1929Ver, SocksAddr, Status, UdpFrag,
    UdpFragAssembler, UdpPacket, UdpRepr, UserPassPacket, UserPassRepr, Ver,
};

pub(crate) mod protocol;

pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Malformed,
    Truncated,
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
        Error::Malformed
    }
}

impl From<Error> for ::std::io::Error {
    fn from(val: Error) -> Self {
        match val {
            Error::Malformed => ::std::io::Error::new(::std::io::ErrorKind::InvalidData, val),
            Error::Truncated => ::std::io::Error::new(::std::io::ErrorKind::UnexpectedEof, val),
        }
    }
}

// pub(crate) type CrateOption<T> = core::result::Result<Option<T>, Error>;
pub(crate) type CrateResult<T> = core::result::Result<T, Error>;

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
            _ => Err(Error::Malformed),
        }
    }
}

impl TryFrom<Reply> for AuthReplyRepr {
    type Error = Error;

    fn try_from(val: Reply) -> Result<Self, Error> {
        match val {
            Reply::Auth(val) => Ok(val),
            _ => Err(Error::Malformed),
        }
    }
}

impl TryFrom<Reply> for RepRepr {
    type Error = Error;

    fn try_from(val: Reply) -> Result<Self, Error> {
        match val {
            Reply::Rep(val) => Ok(val),
            _ => Err(Error::Malformed),
        }
    }
}

impl TryFrom<Reply> for Bytes {
    type Error = Error;

    fn try_from(val: Reply) -> Result<Self, Error> {
        match val {
            Reply::Bytes(val) => Ok(val),
            _ => Err(Error::Malformed),
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
            _ => Err(Error::Malformed),
        }
    }
}

impl TryFrom<Request> for UserPassRepr {
    type Error = Error;

    fn try_from(val: Request) -> Result<Self, Error> {
        match val {
            Request::Auth(val) => Ok(val),
            _ => Err(Error::Malformed),
        }
    }
}

impl TryFrom<Request> for CmdRepr {
    type Error = Error;

    fn try_from(val: Request) -> Result<Self, Error> {
        match val {
            Request::Cmd(val) => Ok(val),
            _ => Err(Error::Malformed),
        }
    }
}

impl TryFrom<Request> for Bytes {
    type Error = Error;

    fn try_from(val: Request) -> Result<Self, Error> {
        match val {
            Request::Bytes(val) => Ok(val),
            _ => Err(Error::Malformed),
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
    use ::std::{env, sync::{Arc, Mutex}};
    use core::fmt;

    use bytes::BytesMut;
    use lazy_static::lazy_static;

    use smolsocket::SocketAddr;

    use crate::{AuthReplyRepr, CmdRepr, Error, MethodRepr, MethodsRepr, protocol::{Decoder, Encodable, Method}, RepRepr, SocksAddr, Status, UserPassRepr};

    lazy_static! {
        static ref INITIATED: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    }

    pub(crate) fn init_logger() {
        let mut initiated = INITIATED.lock().unwrap();
        if *initiated == false {
            if env::var("RUST_LOG").is_err() { env::set_var("RUST_LOG", "debug"); }
            let _ = pretty_env_logger::try_init_timed();
            *initiated = true;
        }
    }

    #[test]
    fn test_sticky_packets() {
        init_logger();

        let msg = MethodsRepr::new(vec![Method::NoAuth, Method::UserPass]);
        test_sticky(msg);

        let msg = MethodRepr::new(Method::NoAuth);
        test_sticky(msg);

        let msg = UserPassRepr::new("user", "pass");
        test_sticky(msg);

        let msg = AuthReplyRepr::new(Status::Success);
        test_sticky(msg);

        let msg = CmdRepr::new_connect(SocksAddr::DomainPort("google.com".to_string(), 443));
        test_sticky(msg);

        let msg = RepRepr::new_success(SocksAddr::SocketAddr(SocketAddr::new_v4_all_zeros()));
        test_sticky(msg);
    }

    fn test_sticky<T: Clone + fmt::Debug + Decoder<T> + Encodable + PartialEq>(msg: T) {
        let mut bytes_mut = BytesMut::new();
        msg.encode_into(&mut bytes_mut);
        debug!("encoded:           {:?}", bytes_mut);
        assert_eq!(T::decode(&mut bytes_mut.clone()), Ok(Some(msg.clone())));

        let mut without_last_byte = bytes_mut.clone().split_to(bytes_mut.len() - 1);
        debug!("without_last_byte: {:?}", without_last_byte);
        assert_eq!(T::decode(&mut without_last_byte), Ok(None));

        let mut one_byte_more = bytes_mut.clone();
        one_byte_more.extend_from_slice(&bytes_mut.as_ref()[0..1]);
        debug!("one_byte_more:     {:?}", one_byte_more);
        assert_eq!(T::decode(&mut one_byte_more), Ok(Some(msg.clone())));
        assert_eq!(T::decode(&mut one_byte_more), Ok(None));

        let mut double = bytes_mut.clone();
        double.extend_from_slice(bytes_mut.as_ref());
        debug!("double:            {:?}", double);
        assert_eq!(T::decode(&mut double), Ok(Some(msg.clone())));
        assert_eq!(T::decode(&mut double), Ok(Some(msg.clone())));
    }

    #[test]
    fn test_err_malformed() {
        init_logger();

        let io_err: ::std::io::Error = Error::Malformed.into();
        assert_eq!(io_err.kind(), ::std::io::ErrorKind::InvalidData);
        assert_eq!(io_err.to_string(), "Malformed".to_string());
    }

    #[test]
    fn test_err_truncated() {
        init_logger();

        let io_err: ::std::io::Error = Error::Truncated.into();
        assert_eq!(io_err.kind(), ::std::io::ErrorKind::UnexpectedEof);
        assert_eq!(io_err.to_string(), "Truncated".to_string());
    }
}
