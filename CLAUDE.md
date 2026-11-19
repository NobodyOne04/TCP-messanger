# TCP-messanger (tcp-messenger)

Multi-user TCP chat in Rust (server + terminal client) with a rotating session-key "protector".
A 2020 lab, redesigned in 2026. Usage and wire protocol: `README.md`.

## Commands
```sh
cargo run -- server [-H host] [-p port]   # default 127.0.0.1:9090
cargo run -- client [-H host] [-p port]
cargo test                                 # protocol round-trips, protector vs. original, server integration
cargo clippy --all-targets                 # keep it clean
```

## Layout
- `src/main.rs`: clap CLI, `server` / `client` subcommands.
- `src/protocol.rs`: framed wire format (1-byte tag + `u32` BE length-prefixed UTF-8 fields,
  max 4 KiB each) and the `Message` enum.
- `src/protector.rs`: session-key derivation, hash/key generation.
- `src/server.rs`: accept loop, a blocking thread per client, broadcast hub, timeouts.
- `src/client.rs`: stdin → server, server → stdout; `/quit`, `:q` or Ctrl-D exits.
- `docs/adr/`: decision records (`.adr`), index in `docs/adr/README.md`.

## Conventions
- Read the ADR before changing a recorded decision; commit subjects carry its number.
- The protector is a teaching scheme, not security: never describe it as encryption.
- No panics or `unwrap` on network input; bad frames reject and disconnect.
- `Cargo.lock` is committed (it's a binary).
