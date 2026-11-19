use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::protector::{validate_key, SessionProtector};
use crate::protocol::{read_message, write_message, Message};

/// How long a fresh connection has to send its `Hello`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A client that can't absorb a broadcast within this time gets dropped,
/// so one stuck peer can't stall the whole room.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run(addr: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("Listening on {}", listener.local_addr()?);
    serve(listener)
}

/// Accept connections forever, one thread per client.
pub fn serve(listener: TcpListener) -> io::Result<()> {
    let hub = Arc::new(Hub::default());
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        let hub = Arc::clone(&hub);
        thread::spawn(move || {
            let peer = match stream.peer_addr() {
                Ok(a) => a,
                Err(e) => return eprintln!("peer_addr failed: {e}"),
            };
            if let Err(e) = handle_client(&hub, stream, peer) {
                eprintln!("[{peer}] connection error: {e}");
            }
        });
    }
    Ok(())
}

#[derive(Default)]
struct Hub {
    next_id: AtomicU64,
    /// Write halves of connected clients. Holding the lock while writing keeps
    /// frames from different broadcasts from interleaving on the wire.
    clients: Mutex<HashMap<u64, TcpStream>>,
}

impl Hub {
    /// Register a client and send it `Welcome`. Done under the lock so no
    /// broadcast can reach the client before its Welcome does.
    fn join(&self, mut stream: TcpStream) -> io::Result<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let mut clients = self.clients.lock().unwrap();
        write_message(&mut stream, &Message::Welcome { id })?;
        clients.insert(id, stream);
        Ok(id)
    }

    /// Returns true if the client was still registered.
    fn leave(&self, id: u64) -> bool {
        self.clients.lock().unwrap().remove(&id).is_some()
    }

    fn online(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    fn broadcast(&self, msg: &Message, except: Option<u64>) {
        let mut clients = self.clients.lock().unwrap();
        let dead: Vec<u64> = clients
            .iter_mut()
            .filter(|(id, _)| Some(**id) != except)
            .filter_map(|(id, stream)| write_message(stream, msg).err().map(|_| *id))
            .collect();
        for id in dead {
            if let Some(s) = clients.remove(&id) {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
}

/// Why the server is ending a session on its own initiative.
type Rejection = &'static str;

fn reject(stream: &mut TcpStream, reason: &str) {
    let _ = write_message(
        stream,
        &Message::Rejected {
            reason: reason.to_string(),
        },
    );
    let _ = stream.shutdown(Shutdown::Both);
}

fn handle_client(hub: &Hub, mut stream: TcpStream, peer: SocketAddr) -> io::Result<()> {
    stream.set_nodelay(true)?;

    // --- handshake -------------------------------------------------------
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let protector = match read_message(&mut stream)? {
        Some(Message::Hello { hash }) => match SessionProtector::new(&hash) {
            Ok(p) => p,
            Err(e) => {
                reject(&mut stream, &e.to_string());
                println!("[{peer}] handshake rejected: {e}");
                return Ok(());
            }
        },
        Some(_) => {
            reject(&mut stream, "expected Hello");
            println!("[{peer}] handshake rejected: expected Hello");
            return Ok(());
        }
        None => return Ok(()),
    };
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;

    // --- session ---------------------------------------------------------
    let id = hub.join(stream.try_clone()?)?;
    println!("[{peer}] user#{id} joined");
    hub.broadcast(
        &Message::Notice {
            text: format!("user#{id} joined ({} online)", hub.online()),
        },
        Some(id),
    );

    let outcome = chat_loop(hub, &mut stream, id, &protector);

    // Unregister before writing a rejection so no broadcast interleaves with it.
    hub.leave(id);
    match &outcome {
        Ok(None) => println!("[{peer}] user#{id} disconnected"),
        Ok(Some(reason)) => {
            reject(&mut stream, reason);
            println!("[{peer}] user#{id} rejected: {reason}");
        }
        Err(e) => println!("[{peer}] user#{id} dropped: {e}"),
    }
    hub.broadcast(
        &Message::Notice {
            text: format!("user#{id} left ({} online)", hub.online()),
        },
        None,
    );
    Ok(())
}

/// Relay chat messages until the client disconnects (`Ok(None)`) or breaks
/// protocol (`Ok(Some(reason))`).
fn chat_loop(
    hub: &Hub,
    stream: &mut TcpStream,
    id: u64,
    protector: &SessionProtector,
) -> io::Result<Option<Rejection>> {
    // The first key establishes the chain; every later one must match.
    let mut expected: Option<String> = None;

    while let Some(msg) = read_message(stream)? {
        let Message::Chat { key, text } = msg else {
            return Ok(Some("expected Chat"));
        };

        let key_ok = match &expected {
            None => validate_key(&key).is_ok(),
            Some(exp) => *exp == key,
        };
        if !key_ok {
            return Ok(Some("session key mismatch: possible session hijack"));
        }
        expected = Some(
            protector
                .next_session_key(&key)
                .expect("key validated above"),
        );

        let text = text.trim();
        if !text.is_empty() {
            hub.broadcast(
                &Message::Broadcast {
                    from: id,
                    text: text.to_string(),
                },
                Some(id),
            );
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protector::{generate_hash, generate_session_key};

    struct TestClient {
        stream: TcpStream,
        protector: SessionProtector,
        key: String,
        id: u64,
    }

    impl TestClient {
        fn connect(addr: SocketAddr) -> Self {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let hash = generate_hash();
            write_message(&mut stream, &Message::Hello { hash: hash.clone() }).unwrap();
            let Some(Message::Welcome { id }) = read_message(&mut stream).unwrap() else {
                panic!("expected Welcome")
            };
            Self {
                stream,
                protector: SessionProtector::new(&hash).unwrap(),
                key: generate_session_key(),
                id,
            }
        }

        fn say(&mut self, text: &str) {
            let msg = Message::Chat {
                key: self.key.clone(),
                text: text.into(),
            };
            write_message(&mut self.stream, &msg).unwrap();
            self.key = self.protector.next_session_key(&self.key).unwrap();
        }

        fn recv(&mut self) -> Option<Message> {
            read_message(&mut self.stream).unwrap()
        }
    }

    fn start_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || serve(listener));
        addr
    }

    #[test]
    fn messages_are_relayed_to_other_clients() {
        let addr = start_server();
        let mut alice = TestClient::connect(addr);
        let mut bob = TestClient::connect(addr);
        assert_eq!(
            alice.recv(),
            Some(Message::Notice {
                text: format!("user#{} joined (2 online)", bob.id)
            })
        );

        for i in 0..5 {
            alice.say(&format!("hello {i}"));
            assert_eq!(
                bob.recv(),
                Some(Message::Broadcast {
                    from: alice.id,
                    text: format!("hello {i}")
                })
            );
        }
        // long + non-ASCII messages survive intact (old version truncated at 32 bytes)
        let long = "ж".repeat(1000);
        bob.say(&long);
        assert_eq!(
            alice.recv(),
            Some(Message::Broadcast {
                from: bob.id,
                text: long
            })
        );

        drop(bob);
        let Some(Message::Notice { text }) = alice.recv() else {
            panic!()
        };
        assert!(text.contains("left"), "{text}");
    }

    #[test]
    fn wrong_session_key_is_rejected() {
        let addr = start_server();
        let mut mallory = TestClient::connect(addr);
        let mut alice = TestClient::connect(addr);
        let _join = mallory.recv();

        alice.say("first");
        assert!(matches!(mallory.recv(), Some(Message::Broadcast { .. })));

        // Replay a stale key, as a hijacker without the hash would.
        alice.key = "1111111111".into();
        alice.say("hijacked");
        assert!(matches!(alice.recv(), Some(Message::Rejected { .. })));
        assert_eq!(alice.recv(), None, "server should close the connection");

        // The hijacked text never reached anyone; only the leave notice did.
        let Some(Message::Notice { text }) = mallory.recv() else {
            panic!()
        };
        assert!(text.contains("left"), "{text}");
    }

    #[test]
    fn bad_handshake_is_rejected() {
        let addr = start_server();
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_message(
            &mut s,
            &Message::Hello {
                hash: "not-digits".into(),
            },
        )
        .unwrap();
        assert!(matches!(
            read_message(&mut s).unwrap(),
            Some(Message::Rejected { .. })
        ));
    }
}
