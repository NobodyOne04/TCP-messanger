mod client;
mod protector;
mod protocol;
mod server;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

/// TCP chat with a rotating session-key protector.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run the chat server.
    Server(Endpoint),
    /// Connect to a chat server.
    Client(Endpoint),
}

#[derive(Args)]
struct Endpoint {
    /// Address to bind (server) or connect to (client).
    #[arg(short = 'H', long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    host: IpAddr,
    /// TCP port.
    #[arg(short, long, default_value_t = 9090)]
    port: u16,
}

impl Endpoint {
    fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().mode {
        Mode::Server(ep) => server::run(ep.addr()).map_err(Into::into),
        Mode::Client(ep) => client::run(ep.addr()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
