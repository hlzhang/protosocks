#[cfg_attr(test, macro_use)]
extern crate log;
#[macro_use]
extern crate serde_derive;

pub use protocol::{
    Atyp, AuthReplyPacket,
    AuthReplyRepr, Cmd,
    CmdPacket, CmdRepr, Decoder as ProtocolDecoder,
    Encoder as ProtocolEncoder,
    Error as ProtocolError,
    HasAddr,
    Method,
    MethodPacket,
    MethodRepr, MethodsPacket,
    MethodsRepr, Rep,
    RepPacket, RepRepr, Rfc1929Ver,
    SocksAddr,
    Status,
    UdpPacket, UdpRepr,
    UserPassPacket, UserPassRepr,
    Ver,
};

pub(crate) mod protocol;

pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}
