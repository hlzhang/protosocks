#[cfg_attr(test, macro_use)]
extern crate log;
#[macro_use]
extern crate serde_derive;

pub use protocol::{
    SocksAddr, Atyp,
    AuthReplyPacket, AuthReplyRepr,
    Cmd, CmdPacket, CmdRepr,
    Decoder as ProtocolDecoder,
    Encoder as ProtocolEncoder,
    HasAddr,
    MethodPacket, MethodRepr,
    MethodsPacket, MethodsRepr,
    Rep, RepPacket, RepRepr,
    Status,
    UdpPacket, UdpRepr,
    UserPassPacket, UserPassRepr,
};
pub use protocol::{Error as ProtocolError, Method, Ver};

pub(crate) mod protocol;

pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}
