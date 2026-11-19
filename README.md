# tcp-messenger

A multi-user TCP chat (server + terminal client) in Rust, with a **session
protector**: every message carries a rotating session key, and the server drops
any client whose key doesn't match the expected next value — a simple guard
against session hijacking.

## Usage

```sh
cargo run -- server                    # listens on 127.0.0.1:9090
cargo run -- client                    # connects to 127.0.0.1:9090
cargo run -- server -H 0.0.0.0 -p 7000
cargo run -- client -H 192.168.1.10 -p 7000
```

In the client, type a line and press Enter to send it. `/quit`, `:q` or
Ctrl-D exits.

```
Connected to 127.0.0.1:9090 as user#2.
Type a message and press Enter. /quit or :q to exit.
* user#3 joined (3 online)
user#1: hi all
```

## How it works

```
src/
  main.rs       CLI (clap): `server` / `client` subcommands
  protocol.rs   framed wire format + Message enum
  protector.rs  session-key derivation, hash/key generation
  server.rs     accept loop, per-client threads, broadcast hub
  client.rs     stdin -> server, server -> stdout
```

**Protocol.** Each frame is a 1-byte tag followed by a fixed number of
`u32 big-endian length + UTF-8` fields (max 4 KiB per field).

| Tag | Message     | Direction        | Fields         |
|-----|-------------|------------------|----------------|
| 1   | `Hello`     | client → server  | hash           |
| 2   | `Welcome`   | server → client  | user id        |
| 3   | `Chat`      | client → server  | key, text      |
| 4   | `Broadcast` | server → clients | from id, text  |
| 5   | `Notice`    | server → clients | text           |
| 6   | `Rejected`  | server → client  | reason         |

**Session protector.** On connect the client generates a hash (5 digits, 1–6)
and an initial key (10 digits, 1–9) and sends the hash in `Hello`. The first
`Chat` key establishes the chain; after each message both sides compute
`next_session_key(key)` and the server rejects + disconnects on mismatch.

> This is a teaching scheme, not cryptography: the hash is sent in plaintext.
> Use TLS for anything real.

## Development

```sh
cargo test     # protocol round-trips, protector vs. original algorithm, server integration
cargo clippy --all-targets
```

## Decisions

Why it is built this way: [docs/adr](docs/adr/README.md).
