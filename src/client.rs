use std::error::Error;
use std::io::{self, BufRead};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::protector::{generate_hash, generate_session_key, SessionProtector};
use crate::protocol::{read_message, write_message, Message, MAX_FIELD_LEN};

const QUIT_COMMANDS: [&str; 2] = ["/quit", ":q"];

pub fn run(addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut stream =
        TcpStream::connect(addr).map_err(|e| format!("could not connect to {addr}: {e}"))?;
    stream.set_nodelay(true)?;

    let protector = SessionProtector::new(&generate_hash())?;
    let mut key = generate_session_key();

    write_message(
        &mut stream,
        &Message::Hello {
            hash: protector.hash(),
        },
    )?;
    let id = match read_message(&mut stream)? {
        Some(Message::Welcome { id }) => id,
        Some(Message::Rejected { reason }) => {
            return Err(format!("server refused: {reason}").into())
        }
        Some(other) => return Err(format!("unexpected handshake reply: {other:?}").into()),
        None => return Err("server closed the connection during handshake".into()),
    };

    println!("Connected to {addr} as user#{id}.");
    println!(
        "Type a message and press Enter. {} to exit.",
        QUIT_COMMANDS.join(" or ")
    );

    let quitting = Arc::new(AtomicBool::new(false));
    spawn_receiver(stream.try_clone()?, Arc::clone(&quitting));

    for line in io::stdin().lock().lines() {
        let line = line?;
        let text = line.trim();
        if QUIT_COMMANDS.contains(&text) {
            break;
        }
        if text.is_empty() {
            continue;
        }
        if text.len() > MAX_FIELD_LEN {
            eprintln!(
                "! message too long ({} bytes, max {MAX_FIELD_LEN})",
                text.len()
            );
            continue;
        }
        let msg = Message::Chat {
            key: key.clone(),
            text: text.to_string(),
        };
        write_message(&mut stream, &msg).map_err(|e| format!("send failed: {e}"))?;
        key = protector.next_session_key(&key)?;
    }

    // stdin closed or user quit
    quitting.store(true, Ordering::SeqCst);
    let _ = stream.shutdown(Shutdown::Both);
    println!("Bye.");
    Ok(())
}

/// Print everything the server sends. Exits the process if the server goes
/// away, since the stdin loop would otherwise sit blocked forever.
fn spawn_receiver(mut stream: TcpStream, quitting: Arc<AtomicBool>) {
    thread::spawn(move || loop {
        let msg = read_message(&mut stream);
        if quitting.load(Ordering::SeqCst) {
            return;
        }
        match msg {
            Ok(Some(Message::Broadcast { from, text })) => println!("user#{from}: {text}"),
            Ok(Some(Message::Notice { text })) => println!("* {text}"),
            Ok(Some(Message::Rejected { reason })) => {
                eprintln!("! disconnected by server: {reason}");
                process::exit(1);
            }
            Ok(Some(other)) => eprintln!("! ignoring unexpected message: {other:?}"),
            Ok(None) => {
                eprintln!("! server closed the connection");
                process::exit(1);
            }
            Err(e) => {
                eprintln!("! connection error: {e}");
                process::exit(1);
            }
        }
    });
}
