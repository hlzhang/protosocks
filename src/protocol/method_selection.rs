use core::convert::TryFrom;
use core::fmt;

use bytes::{Buf, BytesMut};

use super::{CrateResult, Decoder, Encodable, Encoder, Error, field, Method, ToU8Vec, Ver};

pub type Methods = Vec<Method>;

#[derive(Debug, PartialEq, Clone)]
pub struct RequestPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RequestPacket<T> {
    /// Imbue a raw octet buffer with RFC1928 packet structure.
    pub fn new_unchecked(buffer: T) -> RequestPacket<T> {
        RequestPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> CrateResult<RequestPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_methods]
    ///
    /// [set_methods]: #method.set_methods
    pub fn check_len(&self) -> CrateResult<()> {
        let len = self.buffer.as_ref().len();

        if len < field::METHODS_START || len < self.total_len() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Return the length.
    #[inline]
    pub fn total_len(&self) -> usize {
        field::METHODS_START + self.nmethods() as usize
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER]
    }

    /// Return the nmethods.
    #[inline]
    pub fn nmethods(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::NMETHODS]
    }

    /// Return the methods.
    #[inline]
    pub fn parse_methods(&self) -> CrateResult<Methods> {
        let data = self.buffer.as_ref();
        let methods = &data[field::methods(self.nmethods())];
        Method::try_from_slice(methods)
    }

    pub fn take_buffer(self) -> T {
        self.buffer
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> RequestPacket<&'a T> {
    /// Return a pointer to the methods.
    #[inline]
    pub fn methods(&self) -> &'a [u8] {
        let nmethods = self.nmethods();
        let data = self.buffer.as_ref();
        &data[field::methods(nmethods)]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RequestPacket<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER] = value;
    }

    /// Set the nmethods.
    #[inline]
    fn set_nmethods(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::NMETHODS] = value;
    }

    /// Set the methods field.
    #[inline]
    pub fn set_methods(&mut self, value: &[Method]) {
        let nmethods = value.len() as u8;
        self.set_nmethods(nmethods);

        let field_methods = field::methods(nmethods);
        let methods: &[Method] = &value[0..nmethods as usize];
        let methods_slice: &[u8] = &methods.to_u8_vec();
        let data = self.buffer.as_mut();
        data[field_methods].copy_from_slice(methods_slice);
    }

    /// Return a mutable pointer to the methods.
    #[inline]
    pub fn methods_mut(&mut self) -> &mut [u8] {
        let nmethods = self.nmethods();
        let data = self.buffer.as_mut();
        &mut data[field::methods(nmethods)]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for RequestPacket<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

// https://tools.ietf.org/html/rfc1928
//
// The client connects to the server, and sends a version
// identifier/method selection message:
//
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
//
// The VER field is set to X'05' for this version of the protocol.  The
// NMETHODS field contains the number of method identifier octets that
// appear in the METHODS field.
/// A high-level representation of a Method Selection Request packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestRepr {
    pub ver: Ver,
    pub methods: Methods,
}

impl RequestRepr {
    pub fn new(methods: Methods) -> Self {
        Self {
            ver: Ver::SOCKS5,
            methods,
        }
    }

    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &RequestPacket<&T>) -> CrateResult<RequestRepr> {
        // Length of methods must equals to nmethods
        packet.check_len()?;

        // Version 5 is expected.
        if packet.version() != Ver::SOCKS5 as u8 {
            return Err(Error::Malformed);
        }
        if packet.methods().len() > packet.nmethods() as usize {
            return Err(Error::Malformed);
        }
        if packet.methods().len() < packet.nmethods() as usize {
            return Err(Error::Truncated);
        }

        Ok(RequestRepr {
            ver: Ver::SOCKS5,
            methods: packet.parse_methods()?,
        })
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        field::METHODS_START + self.methods.len()
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut RequestPacket<T>) {
        packet.set_version(Ver::SOCKS5.into());
        packet.set_methods(&self.methods);
    }
}

impl fmt::Display for RequestRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SOCKS5 MethodSelection({:?})", self.methods)
    }
}

impl Decoder<RequestRepr> for RequestRepr {
    fn decode(src: &mut BytesMut) -> CrateResult<Option<Self>> {
        let pkt = RequestPacket::new_unchecked(src.as_ref());
        match RequestRepr::parse(&pkt) {
            Ok(repr) => {
                src.advance(repr.buffer_len());
                Ok(Some(repr))
            }
            Err(Error::Truncated) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Encodable for RequestRepr {
    fn encode_into(&self, dst: &mut BytesMut) {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = RequestPacket::new_unchecked(dst);
        self.emit(&mut pkt);
    }
}

impl Encoder<RequestRepr> for RequestRepr {
    fn encode(item: &RequestRepr, dst: &mut BytesMut) {
        item.encode_into(dst);
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ReplyPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ReplyPacket<T> {
    /// Imbue a raw octet buffer with RFC1928 packet structure.
    pub fn new_unchecked(buffer: T) -> ReplyPacket<T> {
        ReplyPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> CrateResult<ReplyPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> CrateResult<()> {
        match self.buffer.as_ref().len() {
            l if l < self.total_len() => Err(Error::Truncated),
            _ => Ok(()),
        }
    }

    /// Return the length.
    #[inline]
    pub fn total_len(&self) -> usize {
        field::METHOD + 1
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER]
    }

    /// Return the method.
    #[inline]
    pub fn method(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::METHOD]
    }

    pub fn take_buffer(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ReplyPacket<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER] = value;
    }

    /// Set the method.
    #[inline]
    pub fn set_method(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::METHOD] = value;
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for ReplyPacket<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

//
// The server selects from one of the methods given in METHODS, and
// sends a METHOD selection message:
//
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
//
// If the selected METHOD is X'FF', none of the methods listed by the
// client are acceptable, and the client MUST close the connection.
//
//
// The client and server then enter a method-specific sub-negotiation.
// Descriptions of the method-dependent sub-negotiations appear in
// separate memos.
//
// Developers of new METHOD support for this protocol should contact
// IANA for a METHOD number.  The ASSIGNED NUMBERS document should be
// referred to for a current list of METHOD numbers and their
// corresponding protocols.
//
// Compliant implementations MUST support GSSAPI and SHOULD support
// USERNAME/PASSWORD authentication methods.
/// A high-level representation of a Method Selection Reply packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ReplyRepr {
    pub method: Method,
}

impl ReplyRepr {
    pub fn new(method: Method) -> Self {
        ReplyRepr { method }
    }

    pub fn new_user_pass() -> Self {
        Self::new(Method::UserPass)
    }

    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &ReplyPacket<&T>) -> CrateResult<ReplyRepr> {
        packet.check_len()?;

        // Version 5 is expected.
        if packet.version() != Ver::SOCKS5 as u8 {
            return Err(Error::Malformed);
        }

        Ok(ReplyRepr {
            method: Method::try_from(packet.method())?,
        })
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        field::METHOD + 1
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut ReplyPacket<T>) {
        packet.set_version(Ver::SOCKS5.into());
        packet.set_method(self.method as u8);
    }

    pub fn is_no_auth(&self) -> bool {
        self.method == Method::NoAuth
    }

    pub fn is_no_methods(&self) -> bool {
        self.method == Method::NoMethods
    }
}

impl fmt::Display for ReplyRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SOCKS5 MethodSelection({})", self.method)
    }
}

impl Decoder<ReplyRepr> for ReplyRepr {
    fn decode(src: &mut BytesMut) -> CrateResult<Option<Self>> {
        let pkt = ReplyPacket::new_unchecked(src.as_ref());
        match ReplyRepr::parse(&pkt) {
            Ok(repr) => {
                src.advance(repr.buffer_len());
                Ok(Some(repr))
            }
            Err(Error::Truncated) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Encodable for ReplyRepr {
    fn encode_into(&self, dst: &mut BytesMut) {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = ReplyPacket::new_unchecked(dst);
        self.emit(&mut pkt);
    }
}

impl Encoder<ReplyRepr> for ReplyRepr {
    fn encode(item: &ReplyRepr, dst: &mut BytesMut) {
        item.encode_into(dst);
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};

    use super::*;

    #[test]
    fn test_request_repr_buffer_len() {
        let user_pass = RequestRepr {
            ver: Ver::SOCKS5,
            methods: vec![Method::UserPass],
        };
        assert_eq!(user_pass.buffer_len(), 3);

        let no_auth_user_pass = RequestRepr {
            ver: Ver::SOCKS5,
            methods: vec![Method::NoAuth, Method::UserPass],
        };
        assert_eq!(no_auth_user_pass.buffer_len(), 4);
    }

    #[test]
    fn test_request_repr_emit_parse_no_auth_user_pass() {
        let no_auth_user_pass = RequestRepr {
            ver: Ver::SOCKS5,
            methods: vec![Method::NoAuth, Method::UserPass],
        };
        assert_eq!(no_auth_user_pass.buffer_len(), 4);
        let mut bytes_mut = BytesMut::new();
        RequestRepr::encode(&no_auth_user_pass, &mut bytes_mut);
        let no_auth_user_pass_pkt =
            RequestPacket::new_checked(bytes_mut.as_ref()).expect("should success");
        assert_eq!(no_auth_user_pass_pkt.version(), no_auth_user_pass.ver as u8);
        assert_eq!(
            no_auth_user_pass_pkt.nmethods() as usize,
            no_auth_user_pass.methods.len()
        );
        let parsed_no_auth_user_pass = Method::try_from_slice(no_auth_user_pass_pkt.methods())
            .expect("should be [NoAuth, UserPass]");
        assert_eq!(parsed_no_auth_user_pass.len(), 2);
        assert_eq!(parsed_no_auth_user_pass[0], Method::NoAuth);
        assert_eq!(parsed_no_auth_user_pass[1], Method::UserPass);

        let decoded = RequestRepr::decode(&mut bytes_mut)
            .expect("should success")
            .expect("should present");
        assert_eq!(decoded.methods.len(), 2);
        assert_eq!(decoded.methods[0], Method::NoAuth);
        assert_eq!(decoded.methods[1], Method::UserPass);
    }

    #[test]
    fn test_request_repr_emit_parse_user_pass() {
        let user_pass = RequestRepr {
            ver: Ver::SOCKS5,
            methods: vec![Method::UserPass],
        };
        assert_eq!(user_pass.buffer_len(), 3);
        let mut vec = vec![0x00; user_pass.buffer_len()];
        let mut user_pass_pkt = RequestPacket::new_unchecked(&mut vec);
        user_pass.emit(&mut user_pass_pkt);
        assert_eq!(user_pass_pkt.version(), user_pass.ver as u8);
        assert_eq!(user_pass_pkt.nmethods() as usize, user_pass.methods.len());
        let parsed_user_pass =
            Method::try_from_slice(user_pass_pkt.methods_mut()).expect("should be [UserPass]");
        assert_eq!(parsed_user_pass.len(), 1);
        assert_eq!(parsed_user_pass[0], Method::UserPass);

        assert_eq!(user_pass_pkt.as_ref()[0], Ver::SOCKS5 as u8);
        assert_eq!(user_pass_pkt.as_ref()[1], 1);
        assert_eq!(user_pass_pkt.as_ref()[2], Method::UserPass as u8);
    }

    #[test]
    fn test_request_decoding() {
        let mut truncated_bytes = BytesMut::with_capacity(1);
        truncated_bytes.put_u8(0x00);
        let mut truncated = RequestPacket::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::SOCKS5 as u8);
        assert_eq!(RequestRepr::decode(&mut truncated_bytes), Ok(None));

        let mut truncated_bytes = BytesMut::new();
        truncated_bytes.extend(vec![0x00 as u8; 2]);
        let mut truncated = RequestPacket::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::SOCKS5 as u8);
        truncated.set_nmethods(1);
        assert_eq!(RequestRepr::decode(&mut truncated_bytes), Ok(None));

        let mut no_method_bytes = BytesMut::new();
        no_method_bytes.extend(vec![0x00 as u8; 2]);
        let mut no_method = RequestPacket::new_unchecked(&mut no_method_bytes);
        no_method.set_version(Ver::SOCKS5 as u8);
        no_method.set_nmethods(0);
        assert_eq!(
            RequestRepr::decode(&mut no_method_bytes),
            Ok(Some(RequestRepr {
                ver: Ver::SOCKS5,
                methods: Methods::new(),
            }))
        );

        let mut malformed_bytes = BytesMut::new();
        malformed_bytes.extend(vec![0x00 as u8; 2]);
        let mut malformed = RequestPacket::new_unchecked(&mut malformed_bytes);
        malformed.set_version(0x00);
        assert_eq!(
            RequestRepr::decode(&mut malformed_bytes),
            Err(Error::Malformed)
        );

        let mut malformed_bytes = BytesMut::new();
        malformed_bytes.extend(vec![0x00 as u8; 3]);
        let mut malformed = RequestPacket::new_unchecked(&mut malformed_bytes);
        malformed.set_version(Ver::SOCKS5 as u8);
        malformed.set_nmethods(1);
        malformed.methods_mut()[0] = 0xEF;
        assert_eq!(
            RequestRepr::decode(&mut malformed_bytes),
            Err(Error::Malformed)
        );

        let mut bytes_one_more = BytesMut::new();
        bytes_one_more.extend(vec![0x00 as u8; 4]);
        let mut one_more = RequestPacket::new_unchecked(&mut bytes_one_more);
        one_more.set_version(Ver::SOCKS5 as u8);
        one_more.set_nmethods(1);
        one_more.set_methods(&[Method::NoAuth]);
        assert_eq!(
            RequestRepr::decode(&mut bytes_one_more),
            Ok(Some(RequestRepr::new(vec![Method::NoAuth])))
        );
    }

    #[test]
    fn test_reply_repr_buffer_len() {
        let user_pass = ReplyRepr {
            method: Method::UserPass,
        };
        assert_eq!(user_pass.buffer_len(), 2);

        let no_auth = ReplyRepr {
            method: Method::NoAuth,
        };
        assert_eq!(no_auth.buffer_len(), 2);
    }

    #[test]
    fn test_reply_repr_emit_parse_no_auth() {
        let no_auth = ReplyRepr {
            method: Method::NoAuth,
        };
        assert_eq!(no_auth.buffer_len(), 2);
        let mut bytes_mut = BytesMut::new();
        ReplyRepr::encode(&no_auth, &mut bytes_mut);
        let no_auth_pkt = ReplyPacket::new_checked(bytes_mut.as_ref()).expect("should success");
        assert_eq!(no_auth_pkt.method(), no_auth.method as u8);

        let decoded = ReplyRepr::decode(&mut bytes_mut)
            .expect("should success")
            .expect("should present");
        assert_eq!(decoded.method, Method::NoAuth);
    }

    #[test]
    fn test_reply_repr_emit_parse_user_pass() {
        let repr = ReplyRepr {
            method: Method::UserPass,
        };
        assert_eq!(repr.buffer_len(), 2);

        let pkt = vec![0x00 as u8; repr.buffer_len()];
        assert_eq!(pkt.len(), 2);
        let mut pkt = ReplyPacket::new_unchecked(pkt);
        repr.emit(&mut pkt);
        assert_eq!(pkt.method(), repr.method as u8);

        let mut bytes_mut = BytesMut::new();
        ReplyRepr::encode(&repr, &mut bytes_mut);
        let encoded_pkt = ReplyPacket::new_checked(bytes_mut.as_ref()).expect("should success");
        assert_eq!(encoded_pkt.method(), repr.method as u8);

        let decoded = ReplyRepr::decode(&mut bytes_mut)
            .expect("should success")
            .expect("should present");
        assert_eq!(decoded.method, Method::UserPass);

        assert_eq!(pkt.as_ref()[0], Ver::SOCKS5 as u8);
        assert_eq!(pkt.as_ref()[1], Method::UserPass as u8);
    }

    #[test]
    fn test_reply_decoding() {
        let mut truncated_bytes = BytesMut::with_capacity(1);
        truncated_bytes.put_u8(0x00);
        let mut truncated = ReplyPacket::new_unchecked(&mut truncated_bytes);
        assert_eq!(truncated.total_len(), 2);
        truncated.set_version(Ver::SOCKS5 as u8);
        assert_eq!(ReplyRepr::decode(&mut truncated_bytes), Ok(None));

        let mut bytes_one_more = BytesMut::new();
        bytes_one_more.extend(vec![0x00 as u8; 3]);
        let mut one_more = ReplyPacket::new_unchecked(&mut bytes_one_more);
        assert_eq!(one_more.total_len(), 2);
        one_more.set_version(Ver::SOCKS5 as u8);
        one_more.set_method(Method::NoAuth as u8);
        assert_eq!(
            ReplyRepr::decode(&mut bytes_one_more),
            Ok(Some(ReplyRepr::new(Method::NoAuth)))
        );

        let mut malformed_bytes = BytesMut::new();
        malformed_bytes.extend(vec![0x00 as u8; 2]);
        let mut malformed = ReplyPacket::new_unchecked(&mut malformed_bytes);
        assert_eq!(malformed.total_len(), 2);
        malformed.set_version(0x00);
        assert_eq!(
            ReplyRepr::decode(&mut malformed_bytes),
            Err(Error::Malformed)
        );

        let mut malformed_bytes = BytesMut::new();
        malformed_bytes.extend(vec![0x00 as u8; 2]);
        let mut malformed = ReplyPacket::new_unchecked(&mut malformed_bytes);
        malformed.set_version(Ver::SOCKS5 as u8);
        malformed.set_method(0xEF);
        assert_eq!(
            ReplyRepr::decode(&mut malformed_bytes),
            Err(Error::Malformed)
        );
    }
}
