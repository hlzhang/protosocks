use core::cmp::min;
use core::convert::TryFrom;

use bytes::{Buf, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use snafu::Snafu;

use crate::field::Field;

use super::{Decoder, Encodable, Encoder, Error, field, Result};

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq, Serialize, Snafu)]
#[repr(u8)]
pub enum Ver {
    #[snafu(display("X'01'"))]
    X01 = 0x01,
}

impl TryFrom<u8> for Ver {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        FromPrimitive::from_u8(val).ok_or(Error::Malformed)
    }
}

impl From<Ver> for u8 {
    fn from(val: Ver) -> Self {
        val as u8
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq, Serialize, Snafu)]
#[repr(u8)]
pub enum Status {
    #[snafu(display("Success"))]
    Success = 0x00,
    #[snafu(display("Failure"))]
    Failure = 0x01,
}

impl TryFrom<u8> for Status {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        FromPrimitive::from_u8(val).ok_or(Error::Malformed)
    }
}

impl From<Status> for u8 {
    fn from(val: Status) -> Self {
        val as u8
    }
}

#[inline]
pub(crate) fn field_uname(ulen: u8) -> Field {
    field::UNAME_PLEN_PASSWD.start..field::UNAME_PLEN_PASSWD.start + ulen as usize
}

#[inline]
pub(crate) fn pos_passwd(ulen: u8) -> usize {
    field_uname(ulen).end + 1
}

#[inline]
pub(crate) fn field_passwd(ulen: u8, plen: u8) -> Field {
    let pos_passwd = pos_passwd(ulen);
    pos_passwd..pos_passwd + plen as usize
}

#[derive(Debug, PartialEq, Clone)]
pub struct RequestPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RequestPacket<T> {
    /// Imbue a raw octet buffer with RFC1929 packet structure.
    pub fn new_unchecked(buffer: T) -> RequestPacket<T> {
        RequestPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<RequestPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_uname] and [set_passwd]
    ///
    /// [set_methods]: #method.set_uname
    /// [set_methods]: #method.set_passwd
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();

        if len <= field::UNAME_PLEN_PASSWD.start {
            Err(Error::Truncated)
        } else {
            let ulen = self.ulen();
            let pos_passwd = pos_passwd(ulen);
            if len < pos_passwd {
                Err(Error::Truncated)
            } else {
                let plen = self.plen();
                let field_passwd = field_passwd(ulen, plen);
                if len < field_passwd.end {
                    Err(Error::Truncated)
                } else if len > self.total_len() {
                    Err(Error::Malformed)
                } else {
                    Ok(())
                }
            }
        }
    }

    #[inline]
    pub(crate) fn pos_plen(&self) -> usize {
        field_uname(self.ulen()).end
    }

    #[inline]
    pub(crate) fn pos_passwd(&self) -> usize {
        pos_passwd(self.ulen())
    }

    #[inline]
    pub(crate) fn field_uname(&self) -> Field {
        field_uname(self.ulen())
    }

    #[inline]
    pub(crate) fn field_passwd(&self) -> Field {
        field_passwd(self.ulen(), self.plen())
    }

    /// Return the length.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.pos_passwd() + self.plen() as usize
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER]
    }

    /// Return the ulen.
    #[inline]
    pub fn ulen(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::ULEN]
    }

    /// Return the plen.
    #[inline]
    pub fn plen(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[self.pos_plen()]
    }

    pub fn take_buffer(self) -> T {
        self.buffer
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> RequestPacket<&'a T> {
    /// Return a pointer to the uname.
    #[inline]
    pub fn uname(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.field_uname()]
    }

    /// Return a pointer to the passwd.
    #[inline]
    pub fn passwd(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.field_passwd()]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RequestPacket<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER] = value;
    }

    /// Set the uname.
    #[inline]
    pub fn set_uname(&mut self, value: &[u8]) {
        let data = self.buffer.as_mut();
        let ulen = if value.len() <= 255 {
            value.len() as u8
        } else {
            255
        };
        data[field::ULEN] = ulen;
        let field_uname = field_uname(ulen);
        let uname = &mut data[field_uname];
        uname.copy_from_slice(value);
    }

    /// Set the passwd.
    #[inline]
    pub fn set_passwd(&mut self, value: &[u8]) {
        let pos_plen = self.pos_plen();
        let ulen = self.ulen();
        let data = self.buffer.as_mut();
        let plen = if value.len() <= 255 {
            value.len() as u8
        } else {
            255
        };
        data[pos_plen] = plen;
        let field_passwd = field_passwd(ulen, plen);
        let passwd = &mut data[field_passwd];
        passwd.copy_from_slice(value);
    }

    /// Return a mutable pointer to the uname.
    #[inline]
    pub fn uname_mut(&mut self) -> &mut [u8] {
        let field = self.field_uname();
        let data = self.buffer.as_mut();
        &mut data[field]
    }

    /// Return a mutable pointer to the passwd.
    #[inline]
    pub fn passwd_mut(&mut self) -> &mut [u8] {
        let field = self.field_passwd();
        let data = self.buffer.as_mut();
        &mut data[field]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for RequestPacket<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

// https://tools.ietf.org/html/rfc1929
//
// Initial negotiation
//
// Once the SOCKS V5 server has started, and the client has selected the
// Username/Password Authentication protocol, the Username/Password
// subnegotiation begins.  This begins with the client producing a
// Username/Password request:
//
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+
//
// The VER field contains the current version of the subnegotiation,
// which is X'01'. The ULEN field contains the length of the UNAME field
// that follows. The UNAME field contains the username as known to the
// source operating system. The PLEN field contains the length of the
// PASSWD field that follows. The PASSWD field contains the password
// association with the given UNAME.
/// A high-level representation of a Request packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestRepr {
    pub uname: String,
    pub passwd: String,
}

impl RequestRepr {
    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &RequestPacket<&T>) -> Result<RequestRepr> {
        packet.check_len()?;

        // Version 5 is expected.
        if packet.version() != Ver::X01 as u8 {
            return Err(Error::Malformed);
        }

        let uname =
            String::from_utf8(packet.uname().to_vec()).map_err(|_utf8err| Error::Malformed)?;
        let passwd =
            String::from_utf8(packet.passwd().to_vec()).map_err(|_utf8err| Error::Malformed)?;
        Ok(RequestRepr { uname, passwd })
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let ulen = min(self.uname.as_bytes().len(), 255) as u8;
        let plen = min(self.passwd.as_bytes().len(), 255) as u8;
        field_passwd(ulen, plen).end
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut RequestPacket<T>) {
        packet.set_version(Ver::X01.into());
        packet.set_uname(self.uname.as_bytes());
        packet.set_passwd(self.passwd.as_bytes());
    }
}

impl Decoder<RequestRepr> for RequestRepr {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>> {
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
    fn try_encode(&self, dst: &mut BytesMut) -> Result<()> {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = RequestPacket::new_unchecked(dst);
        self.emit(&mut pkt);
        Ok(())
    }
}

impl Encoder<RequestRepr> for RequestRepr {
    fn encode(item: &RequestRepr, dst: &mut BytesMut) -> Result<()> {
        item.try_encode(dst)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ReplyPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ReplyPacket<T> {
    /// Imbue a raw octet buffer with RFC1929 packet structure.
    pub fn new_unchecked(buffer: T) -> ReplyPacket<T> {
        ReplyPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<ReplyPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        match self.buffer.as_ref().len() {
            l if l < self.total_len() => Err(Error::Truncated),
            l if l > self.total_len() => Err(Error::Malformed),
            _ => Ok(()),
        }
    }

    /// Return the length.
    #[inline]
    pub fn total_len(&self) -> usize {
        field::STATUS + 1
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER]
    }

    /// Return the status.
    #[inline]
    pub fn status(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::STATUS]
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

    /// Set the status.
    #[inline]
    pub fn set_status(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::STATUS] = value;
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for ReplyPacket<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

//
// The server verifies the supplied UNAME and PASSWD, and sends the
// following response:
//
// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+
//
// A STATUS field of X'00' indicates success. If the server returns a
// `failure' (STATUS value other than X'00') status, it MUST close the
// connection.
/// A high-level representation of a RFC1929 Reply packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ReplyRepr {
    pub status: Status,
}

impl ReplyRepr {
    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &ReplyPacket<&T>) -> Result<ReplyRepr> {
        packet.check_len()?;

        // Version 5 is expected.
        if packet.version() != Ver::X01 as u8 {
            return Err(Error::Malformed);
        }

        Ok(ReplyRepr {
            status: Status::try_from(packet.status())?,
        })
    }

    /// Return the length of that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        field::STATUS + 1
    }

    /// Emit a high-level representation into a packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut ReplyPacket<T>) {
        packet.set_version(Ver::X01.into());
        packet.set_status(self.status as u8);
    }
}

impl Decoder<ReplyRepr> for ReplyRepr {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>> {
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
    fn try_encode(&self, dst: &mut BytesMut) -> Result<()> {
        if dst.len() < self.buffer_len() {
            dst.resize(self.buffer_len(), 0);
        }
        let mut pkt = ReplyPacket::new_unchecked(dst);
        self.emit(&mut pkt);
        Ok(())
    }
}

impl Encoder<ReplyRepr> for ReplyRepr {
    fn encode(item: &ReplyRepr, dst: &mut BytesMut) -> Result<()> {
        item.try_encode(dst)
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    use super::*;

    #[test]
    fn test_ver() {
        assert_eq!(Ver::try_from(0x01 as u8), Ok(Ver::X01));
        assert_eq!(Ver::try_from(0x00 as u8), Err(Error::Malformed));
        assert_eq!(Ver::try_from(0x02 as u8), Err(Error::Malformed));
        assert_eq!(Ver::X01 as u8, 1);
        let ver: u8 = Ver::X01.into();
        assert_eq!(ver, 1);
        let ver = u8::from(Ver::X01);
        assert_eq!(ver, 1);
    }

    #[test]
    fn test_status() {
        assert_eq!(Status::try_from(0x00 as u8), Ok(Status::Success));
        assert_eq!(Status::try_from(0x01 as u8), Ok(Status::Failure));
        assert_eq!(Status::try_from(0x03 as u8), Err(Error::Malformed));
        assert_eq!(Status::Success as u8, 0);
        assert_eq!(Status::Failure as u8, 1);
        let status: u8 = Status::Success.into();
        assert_eq!(status, 0);
        let status = u8::from(Status::Success);
        assert_eq!(status, 0);
    }

    fn test_request(repr: &RequestRepr) -> RequestPacket<Vec<u8>> {
        assert_eq!(
            repr.buffer_len(),
            repr.uname.as_bytes().len() + repr.passwd.as_bytes().len() + 3
        );
        let mut bytes_mut = BytesMut::new();
        RequestRepr::encode(&repr, &mut bytes_mut).expect("should encode");
        let pkt = RequestPacket::new_checked(bytes_mut.as_ref()).expect("should success");
        assert_eq!(pkt.ulen() as usize, repr.uname.as_bytes().len());
        assert_eq!(pkt.uname(), repr.uname.as_bytes());
        assert_eq!(pkt.plen() as usize, repr.passwd.as_bytes().len());
        assert_eq!(pkt.passwd(), repr.passwd.as_bytes());

        let result = RequestPacket::new_unchecked(pkt.as_ref().to_vec());

        let decoded = RequestRepr::decode(&mut bytes_mut)
            .expect("should success")
            .expect("should present");
        assert_eq!(decoded.uname, repr.uname);
        assert_eq!(decoded.passwd, repr.passwd);

        result
    }

    #[test]
    fn test_request_decoding() {
        let mut truncated_bytes = BytesMut::new();
        truncated_bytes.extend(vec![0x00 as u8; 2]);
        let mut truncated = RequestPacket::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::X01 as u8);
        assert_eq!(truncated.check_len(), Err(Error::Truncated));
        assert_eq!(RequestRepr::decode(&mut truncated_bytes), Ok(None));

        let mut truncated_bytes = BytesMut::new();
        truncated_bytes.extend(vec![0x00 as u8; 4]);
        truncated_bytes[1] = 2; // set ulen to 2
        let mut truncated = RequestPacket::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::X01 as u8);
        assert_eq!(truncated.check_len(), Err(Error::Truncated));
        assert_eq!(RequestRepr::decode(&mut truncated_bytes), Ok(None));

        let mut truncated_bytes = BytesMut::new();
        truncated_bytes.extend(vec![0x00 as u8; 4]);
        truncated_bytes[1] = 1; // set ulen to 1
        truncated_bytes[3] = 1; // set plen to 1
        let mut truncated = RequestPacket::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::X01 as u8);
        assert_eq!(truncated.total_len(), 5); // total len should be 5
        assert_eq!(RequestRepr::decode(&mut truncated_bytes), Ok(None));

        let mut truncated_bytes = BytesMut::new();
        truncated_bytes.extend(vec![0x00 as u8; 4]);
        truncated_bytes[1] = 1; // set ulen to 1
        truncated_bytes[3] = 2; // set plen to 1
        let mut truncated = RequestPacket::new_unchecked(&mut truncated_bytes);
        truncated.set_version(Ver::X01 as u8);
        assert_eq!(truncated.total_len(), 6); // total len should be 6
        assert_eq!(truncated.check_len(), Err(Error::Truncated));
        assert_eq!(RequestRepr::decode(&mut truncated_bytes), Ok(None));

        let mut empty_bytes = BytesMut::new();
        empty_bytes.extend(vec![0x00 as u8; 3]);
        empty_bytes[1] = 0; // set ulen to 0
        empty_bytes[2] = 0; // set plen to 0
        let mut empty = RequestPacket::new_unchecked(&mut empty_bytes);
        empty.set_version(Ver::X01 as u8);
        assert_eq!(
            RequestRepr::decode(&mut empty_bytes),
            Ok(Some(RequestRepr {
                uname: "".to_string(),
                passwd: "".to_string(),
            }))
        );

        let mut empty_bytes = BytesMut::new();
        empty_bytes.extend(vec![0x00 as u8; 4]);
        empty_bytes[1] = 0; // set ulen to 0
        empty_bytes[2] = 0; // set plen to 0
        let mut empty = RequestPacket::new_unchecked(&mut empty_bytes);
        empty.set_version(Ver::X01 as u8);
        assert_eq!(empty.check_len(), Err(Error::Malformed));
        assert_eq!(RequestRepr::decode(&mut empty_bytes), Err(Error::Malformed));

        let mut truncated_bytes = BytesMut::new();
        truncated_bytes.extend(vec![0x00 as u8; 2]);
        let mut truncated = RequestPacket::new_unchecked(&mut truncated_bytes);
        truncated.set_version(0x00);
        assert_eq!(
            RequestRepr::decode(&mut truncated_bytes),
            Ok(None)
        );

        let mut malformed = test_request(&RequestRepr {
            uname: "".to_string(),
            passwd: "".to_string(),
        });
        malformed.set_version(0x00);
        let mut malformed_bytes = BytesMut::new();
        malformed_bytes.extend(malformed.take_buffer());
        assert_eq!(
            RequestRepr::decode(&mut malformed_bytes),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn test_empty() {
        let repr = RequestRepr {
            uname: "".to_string(),
            passwd: "".to_string(),
        };
        let mut pkt = test_request(&repr);
        assert_eq!(pkt.total_len(), 3);
        assert_eq!(pkt.as_ref()[1], 0);
        assert_eq!(pkt.as_ref()[2], 0);
        assert_eq!(pkt.as_ref().len(), 3);
        assert_eq!(pkt.ulen(), 0);
        assert_eq!(pkt.plen(), 0);
        assert_eq!(&pkt.uname_mut(), &b"");
        assert_eq!(&pkt.passwd_mut(), &b"");
    }

    #[test]
    fn test_empty_uname() {
        let repr = RequestRepr {
            uname: "".to_string(),
            passwd: "passwd".to_string(),
        };
        let mut pkt = test_request(&repr);
        assert_eq!(pkt.total_len(), 9);
        assert_eq!(pkt.as_ref()[1], 0);
        assert_eq!(pkt.as_ref()[2], 6);
        assert_eq!(pkt.as_ref().len(), 9);
        assert_eq!(pkt.ulen(), 0);
        assert_eq!(&pkt.uname_mut(), &b"");
        assert_eq!(&pkt.passwd_mut(), &b"passwd");
    }

    #[test]
    fn test_empty_passwd() {
        let repr = RequestRepr {
            uname: "uname".to_string(),
            passwd: "".to_string(),
        };
        let mut pkt = test_request(&repr);
        assert_eq!(pkt.total_len(), 8);
        assert_eq!(pkt.as_ref()[1], 5);
        assert_eq!(pkt.as_ref()[7], 0);
        assert_eq!(pkt.as_ref().len(), 8);
        assert_eq!(pkt.plen(), 0);
        assert_eq!(&pkt.uname_mut(), &b"uname");
        assert_eq!(&pkt.passwd_mut(), &b"");
    }

    #[test]
    fn test_uname_passwd() {
        let repr = RequestRepr {
            uname: "uname".to_string(),
            passwd: "passwd".to_string(),
        };
        let mut pkt = test_request(&repr);
        assert_eq!(pkt.total_len(), 14);
        assert_eq!(pkt.as_ref().len(), 14);
        assert_eq!(pkt.as_ref()[1], 5);
        assert_eq!(pkt.as_ref()[7], 6);
        assert_eq!(pkt.ulen(), 5);
        assert_eq!(pkt.plen(), 6);
        assert_eq!(&pkt.uname_mut(), &b"uname");
        assert_eq!(&pkt.passwd_mut(), &b"passwd");
    }

    #[test]
    fn test_reply_repr_emit_parse_failure() {
        let repr = ReplyRepr {
            status: Status::Failure,
        };
        assert_eq!(repr.buffer_len(), 2);
        let mut bytes_mut = BytesMut::new();
        ReplyRepr::encode(&repr, &mut bytes_mut).expect("should encode");
        let pkt = ReplyPacket::new_checked(bytes_mut.as_ref()).expect("new packet should success");
        assert_eq!(pkt.version(), Ver::X01 as u8);
        assert_eq!(pkt.status(), repr.status as u8);

        let decoded = ReplyRepr::decode(&mut bytes_mut)
            .expect("decode should success")
            .expect("should present");
        assert_eq!(decoded.status, Status::Failure);
    }

    #[test]
    fn test_reply_repr_emit_parse_success() {
        let repr = ReplyRepr {
            status: Status::Success,
        };
        assert_eq!(repr.buffer_len(), 2);
        let mut bytes_mut = BytesMut::new();
        ReplyRepr::encode(&repr, &mut bytes_mut).expect("should encode");
        let pkt = ReplyPacket::new_checked(bytes_mut.as_ref()).expect("new packet should success");
        assert_eq!(pkt.total_len(), 2);
        assert_eq!(pkt.version(), Ver::X01 as u8);
        assert_eq!(pkt.status(), repr.status as u8);
        assert_eq!(pkt.as_ref()[0], Ver::X01 as u8);
        assert_eq!(pkt.as_ref()[1], repr.status as u8);

        let decoded = ReplyRepr::decode(&mut bytes_mut)
            .expect("decode should success")
            .expect("should present");
        assert_eq!(decoded.status, Status::Success);
    }

    #[test]
    fn test_reply_decoding() {
        let mut truncated_bytes = BytesMut::with_capacity(1);
        truncated_bytes.put_u8(0x00);
        let mut truncated = ReplyPacket::new_unchecked(&mut truncated_bytes);
        assert_eq!(truncated.total_len(), 2);
        truncated.set_version(Ver::X01 as u8);
        assert_eq!(ReplyRepr::decode(&mut truncated_bytes), Ok(None));

        let mut malformed_bytes = BytesMut::new();
        malformed_bytes.extend(vec![0x00 as u8; 3]);
        let mut malformed = ReplyPacket::new_unchecked(&mut malformed_bytes);
        assert_eq!(malformed.total_len(), 2);
        malformed.set_version(Ver::X01 as u8);
        malformed.set_status(Status::Success as u8);
        assert_eq!(
            ReplyRepr::decode(&mut malformed_bytes),
            Err(Error::Malformed)
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
        malformed.set_version(Ver::X01 as u8);
        malformed.set_status(0x03);
        assert_eq!(
            ReplyRepr::decode(&mut malformed_bytes),
            Err(Error::Malformed)
        );
    }
}
