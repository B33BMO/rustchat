# rustchat

An end-to-end encrypted chatroom in your terminal.

One shared key is the whole access model: anyone holding it can join, pick a
name, and talk. Messages are sealed on your machine and opened on everyone
else's, so the relay carrying them only ever handles ciphertext — it cannot
read the room it serves.

```
 rustchat relay.bmo.guru                                          ● online · 3 here

bmo (you)  09:23
   hey, did the relay deploy land?

sam  09:23
   yeah, it's behind the tunnel now

bmo (you)  09:24
   nice. the relay can't read any of this, right?

sam  09:24
   right — it only ever sees ciphertext
 · 3 connections in the room. The relay can't tell you who — it doesn't know.

╭ message ──────────────────────────────────────────────────────────────────────────╮
│ good                                                                             │
╰──────────────────────────────────────────────────────────────────────────────────╯
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/B33BMO/rustchat/main/install.sh | sh
```

That fetches a prebuilt binary, checks it against the release's `SHA256SUMS`,
and drops it on your `PATH`. If there's no prebuilt binary for your platform it
builds from source instead, provided you have Rust.

Then just:

```sh
rustchat
```

The first run walks you through creating or joining a room, and seals what it
needs into an encrypted vault. After that it only asks for your passphrase.

<details>
<summary>Other ways to install</summary>

```sh
# With the relay, for hosting your own room
curl -fsSL .../install.sh | sh -s -- --relay

# A specific version, or a specific directory
curl -fsSL .../install.sh | sh -s -- --version v0.2.0 --dir ~/bin

# From source
cargo install --git https://github.com/B33BMO/rustchat rustchat

# Remove it again
curl -fsSL .../install.sh | sh -s -- --uninstall
```
</details>

## The two secrets

Keeping these straight is most of understanding rustchat.

| | Room key | Your passphrase |
|---|---|---|
| Who has it | everyone in the room | only you |
| What it does | encrypts and decrypts messages | unlocks your vault on this machine |
| Where it goes | shared with people you invite | nowhere, ever |
| If it leaks | the room is readable — rotate it | your local vault is readable |

The room key looks like `rc1-EXAMPLEA-EXAMPLEB-…`. It is the only credential: there are
no accounts, no passwords, no server-side identity. Usernames are picked
client-side and nobody verifies them, so two people can be `sam` at once.

Your passphrase is separate and local. It encrypts a small vault holding the
room key and your scrollback, so you don't have to paste a long key every
launch. Forgetting it costs you that vault, not your access — rejoin with the
room key and set a new one.

## Hosting a room

Generate a key pair for the room:

```sh
$ rustchat keygen
Room key   rc1-EXAMPLEA-EXAMPLEB-EXAMPLEC-EXAMPLED-EXAMPLEE-EXAMPLEF-EXAM

Relay auth key (for the relay's --auth-key / RUSTCHAT_AUTH_KEY):
  0000example0auth0key00000000000000000000000000000000000000000000
```

Hand the **room key** to the people you want in the room. Give the **auth key**
to the relay. If you already have a room key and need its auth key again — to
check a relay is configured for the room you think it is, or to add a second
relay — `rustchat authkey <room key>` derives it.

The auth key is derived one-way from the room key: it is enough
to turn away clients who don't know the room key, and useless for reading
anything. A relay operator who is entirely untrustworthy still learns nothing
but message sizes and timing.

On a systemd host:

```sh
sudo sh deploy/setup-relay.sh --auth-key <auth key> --port 7777
```

That installs the binary, writes a locked-down unit, and starts it on
loopback. The relay speaks plain HTTP on purpose — put something in front of it
that terminates TLS. With Cloudflare Tunnel, add to your ingress list:

```yaml
  - hostname: relay.example.com
    service: http://localhost:7777
```

```sh
cloudflared tunnel route dns <tunnel> relay.example.com
sudo systemctl restart cloudflared
```

Then anyone runs `rustchat --relay wss://relay.example.com/ws`.

## Using it

Type to talk. Enter sends.

| | |
|---|---|
| `↑` `↓` `PgUp` `PgDn` | scroll the transcript |
| `Esc` | clear the input, jump back to newest |
| `Ctrl-A` / `Ctrl-E` | start / end of line |
| `Ctrl-U` | clear the line |
| `Ctrl-L` | clear the view |
| `Ctrl-C` | quit |

| Command | |
|---|---|
| `/key` | show the room key, to invite someone |
| `/nick <name>` | change your name |
| `/who` | how many connections are in the room |
| `/clear` | wipe the view |
| `/forget` | erase saved history from your vault |
| `/quit` | leave |

Useful flags:

```sh
rustchat --relay wss://elsewhere/ws     # a different relay, just this once
rustchat --room-key rc1-…               # skip the vault entirely
rustchat --no-vault                     # touch no disk at all
rustchat where                          # where the vault lives
rustchat reset                          # delete the vault and start over
rustchat authkey <room key>             # the auth key a relay needs for that room
```

`RUSTCHAT_ROOM_KEY` does the same as `--room-key` without putting the key in
your shell history or in `ps` output.

### "the relay turned us away"

The relay only accepts clients that can prove they hold the room key it was
configured for. If you see this, the key you are using is not that key. Most
often the key was created rather than joined — a brand-new room key is
perfectly valid and matches no existing relay.

Check whether your key and the relay belong together:

```sh
rustchat authkey <your room key>     # compare with RUSTCHAT_AUTH_KEY on the relay
```

If they differ, the rejected key is already saved in your vault, so relaunching
fails identically. Clear it and rejoin:

```sh
rustchat reset
rustchat          # choose "Join a room" and paste the key you were given
```

## How it works

```
  you                         relay                        everyone else
  ───                         ─────                        ─────────────
  seal(msg_key, payload) ──▶  ciphertext in, ciphertext out  ──▶ open(msg_key, …)
                              holds auth_key only
                              cannot derive msg_key
```

A room key is 32 random bytes. Two independent subkeys come off it via BLAKE3's
key-derivation mode:

- `auth_key` — the relay's copy. Clients prove membership by answering a fresh
  random challenge with `BLAKE3(auth_key, challenge)`, compared in constant
  time. Fresh challenges mean a captured proof can't be replayed.
- `msg_key` — clients only. Payloads are sealed with XChaCha20-Poly1305 under a
  random 192-bit nonce, wide enough that independent senders can generate them
  without coordinating.

Because `auth_key` and `msg_key` are siblings rather than parent and child, the
relay holding one tells it nothing about the other. Usernames, message bodies
and timestamps all live *inside* the sealed payload, so the relay's whole view
of a room is a socket count and a pile of opaque bytes.

Your vault is XChaCha20-Poly1305 under an Argon2id stretch of your passphrase,
written `0600` via a temp-file rename so an interrupted save can't corrupt it.

### What this does not protect against

Worth being straight about:

- **A leaked room key.** It's the only credential. Anyone with it reads
  everything, including the relay's replay buffer. Rotating means a new key and
  telling everyone.
- **Impersonation inside the room.** Names aren't authenticated. If you're in
  the room, you can send as anyone. The key gets you in the door; it doesn't
  distinguish people once inside.
- **Traffic analysis.** The relay sees who connects from where, when, and how
  big each message is. It just can't read them.
- **No forward secrecy.** One long-lived key. Someone who records ciphertext
  today and gets the key later can read it all. A ratchet would fix this and
  would also break "hand out one key and anyone can join", which is the point.
- **Your own machine.** The vault resists someone reading your disk, not
  someone running code as you.

Sensible for a private room among people who already trust each other. Not a
replacement for Signal.

## Development

```
crates/core    crypto, key derivation, wire protocol, vault format
crates/client  the TUI
crates/relay   the broadcast hub
```

```sh
cargo test --workspace   # unit tests + end-to-end against the real relay binary
cargo clippy --workspace --all-targets
```

The integration tests in `crates/relay/tests/` drive the actual relay binary
over a real socket, including the cases that matter: a wrong key gets turned
away, unauthenticated sends are refused, and what the relay forwards stays
unreadable.

To try it locally, in three terminals:

```sh
eval "$(cargo run -q --bin rustchat -- keygen | awk '/^Room key/{print "K="$3} /^  [0-9a-f]/{print "A=" $1}')"
cargo run --bin rustchat-relay -- --auth-key "$A" --bind 127.0.0.1:7777
cargo run --bin rustchat -- --room-key "$K" --relay ws://127.0.0.1:7777 --no-vault -u alice
cargo run --bin rustchat -- --room-key "$K" --relay ws://127.0.0.1:7777 --no-vault -u bob
```

## License

MIT
