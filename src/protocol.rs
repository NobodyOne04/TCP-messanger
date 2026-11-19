//! Wire format.
//!
//! Every message is one frame:
//!
//! ```text
//! +-----+------------------+------------------+-----
//! | tag | field 1          | field 2          | ...
//! | u8  | u32 BE len + utf8| u32 BE len + utf8|
//! +-----+------------------+------------------+-----
//! ```
//!
//! The number of fields is fixed by the tag. Fields are capped at
//! [`MAX_FIELD_LEN`] bytes so a peer can't make us allocate unbounded memory.

use std::io::{self, Read, Write};

pub const MAX_FIELD_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// client -> server: first frame, carries the protector hash.
    Hello { hash: String },
    /// server -> client: handshake accepted, this is your user id.
    Welcome { id: u64 },
    /// client -> server: a chat line plus the current session key.
    Chat { key: String, text: String },
    /// server -> clients: someone said something.
    Broadcast { from: u64, text: String },
    /// server -> clients: join/leave and other informational events.
    Notice { text: String },
    /// server -> client: request refused; the server closes the connection.
    Rejected { reason: String },
}

mod tag {
    pub const HELLO: u8 = 1;
    pub const WELCOME: u8 = 2;
    pub const CHAT: u8 = 3;
    pub const BROADCAST: u8 = 4;
    pub const NOTICE: u8 = 5;
    pub const REJECTED: u8 = 6;
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let (tag, fields): (u8, Vec<String>) = match self {
            Message::Hello { hash } => (tag::HELLO, vec![hash.clone()]),
            Message::Welcome { id } => (tag::WELCOME, vec![id.to_string()]),
            Message::Chat { key, text } => (tag::CHAT, vec![key.clone(), text.clone()]),
            Message::Broadcast { from, text } => {
                (tag::BROADCAST, vec![from.to_string(), text.clone()])
            }
            Message::Notice { text } => (tag::NOTICE, vec![text.clone()]),
            Message::Rejected { reason } => (tag::REJECTED, vec![reason.clone()]),
        };
        let mut buf = vec![tag];
        for f in fields {
            buf.extend_from_slice(&(f.len() as u32).to_be_bytes());
            buf.extend_from_slice(f.as_bytes());
        }
        buf
    }
}

/// Write a single message and flush it.
pub fn write_message(w: &mut impl Write, msg: &Message) -> io::Result<()> {
    w.write_all(&msg.encode())?;
    w.flush()
}

/// Read a single message. Returns `Ok(None)` on a clean EOF between frames.
pub fn read_message(r: &mut impl Read) -> io::Result<Option<Message>> {
    let mut tag = [0u8; 1];
    match r.read_exact(&mut tag) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let msg = match tag[0] {
        tag::HELLO => Message::Hello {
            hash: read_field(r)?,
        },
        tag::WELCOME => Message::Welcome {
            id: parse_id(&read_field(r)?)?,
        },
        tag::CHAT => Message::Chat {
            key: read_field(r)?,
            text: read_field(r)?,
        },
        tag::BROADCAST => Message::Broadcast {
            from: parse_id(&read_field(r)?)?,
            text: read_field(r)?,
        },
        tag::NOTICE => Message::Notice {
            text: read_field(r)?,
        },
        tag::REJECTED => Message::Rejected {
            reason: read_field(r)?,
        },
        other => return Err(invalid(format!("unknown message tag {other}"))),
    };
    Ok(Some(msg))
}

fn read_field(r: &mut impl Read) -> io::Result<String> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FIELD_LEN {
        return Err(invalid(format!(
            "field of {len} bytes exceeds limit {MAX_FIELD_LEN}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|_| invalid("field is not valid UTF-8"))
}

fn parse_id(s: &str) -> io::Result<u64> {
    s.parse().map_err(|_| invalid(format!("bad user id {s:?}")))
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_all_variants() {
        let msgs = vec![
            Message::Hello {
                hash: "12345".into(),
            },
            Message::Welcome { id: 7 },
            Message::Chat {
                key: "1234567890".into(),
                text: "привет, 世界 👋".into(),
            },
            Message::Broadcast {
                from: 3,
                text: "".into(),
            },
            Message::Notice {
                text: "user#3 joined".into(),
            },
            Message::Rejected {
                reason: "nope".into(),
            },
        ];
        let mut wire = Vec::new();
        for m in &msgs {
            write_message(&mut wire, m).unwrap();
        }
        let mut r = Cursor::new(wire);
        for m in &msgs {
            assert_eq!(read_message(&mut r).unwrap().as_ref(), Some(m));
        }
        assert_eq!(read_message(&mut r).unwrap(), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(read_message(&mut Cursor::new(vec![99])).is_err());
        let mut huge = vec![tag::NOTICE];
        huge.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert!(read_message(&mut Cursor::new(huge)).is_err());
        let bad_utf8 = vec![tag::NOTICE, 0, 0, 0, 1, 0xff];
        assert!(read_message(&mut Cursor::new(bad_utf8)).is_err());
        // truncated mid-frame is an error, not a clean EOF
        assert!(read_message(&mut Cursor::new(vec![tag::NOTICE, 0, 0])).is_err());
    }
}
