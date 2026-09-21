//! rustchat — an encrypted TUI chatroom.
//!
//! Everyone with a room's key is in that room. Messages are sealed on your
//! machine and opened on theirs; the relay in between only ever handles
//! ciphertext, and is configured with no room keys at all — it routes by a
//! one-way room id, so one relay carries any number of rooms it cannot read.
//! See `rustchat-core` for the details.

mod app;
mod net;
mod ui;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use app::{Action, App, DEFAULT_RELAY, Level, Screen, Setup, Status, Unlock};
use clap::{Parser, Subcommand};
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use net::{NetCmd, NetEvent};
use rustchat_core::vault::{VaultData, open_vault, seal_vault};
use rustchat_core::{AccessKey, Invite, Payload, RoomKey, proto};

#[derive(Parser, Debug)]
#[command(
    name = "rustchat",
    version,
    about = "An end-to-end encrypted TUI chatroom.",
    long_about = "An end-to-end encrypted TUI chatroom.\n\nAnyone holding a room's key can \
                  join it and talk. Messages are sealed before they leave your machine, so \
                  the relay that carries them cannot read them. One relay carries any number \
                  of rooms and is configured for none of them."
)]
struct Cli {
    /// Relay to connect to. Overrides the one saved in your vault.
    #[arg(long, short)]
    relay: Option<String>,

    /// Use this room key for this session only, skipping the vault entirely.
    /// Requires --access-key too.
    ///
    /// Prefer the `RUSTCHAT_ROOM_KEY` environment variable: an argument is
    /// visible to anyone who can list processes on this machine.
    #[arg(long, env = "RUSTCHAT_ROOM_KEY", hide_env_values = true)]
    room_key: Option<String>,

    /// The relay's access key, which decides who may connect at all.
    #[arg(long, env = "RUSTCHAT_ACCESS_KEY", hide_env_values = true)]
    access_key: Option<String>,

    /// Join straight from an invite, skipping the vault. Carries the relay,
    /// its access key and a room key in one value.
    #[arg(long, env = "RUSTCHAT_INVITE", hide_env_values = true)]
    invite: Option<String>,

    /// Username for this session. Overrides the saved one.
    #[arg(long, short)]
    username: Option<String>,

    /// Touch no disk: no vault is read or written, and nothing is remembered.
    #[arg(long)]
    no_vault: bool,

    /// Path to the vault file.
    #[arg(long)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a room key to share with the people you want in a room.
    Keygen,
    /// Generate a relay's access key, and the auth key to configure it with.
    ///
    /// Run this once per relay. Everyone who uses that relay needs the access
    /// key; it says nothing about which rooms exist or what is in them.
    Relaykey,
    /// Print the auth key a relay needs for an access key you already have.
    Authkey {
        /// The relay access key. Omit it to read from stdin, which keeps the
        /// key out of your shell history and out of `ps`.
        access_key: Option<String>,
    },
    /// Build a one-paste invite from a relay, its access key and a room key.
    Invite {
        /// Relay address, e.g. relay.example.com.
        #[arg(long, short)]
        relay: String,
        /// The relay's access key.
        #[arg(long, short)]
        access_key: String,
        /// The room key. Omit for an invite that grants relay access only,
        /// letting the holder create or join whichever room they like.
        #[arg(long, short = 'k')]
        room_key: Option<String>,
    },
    /// Print where the vault lives.
    Where,
    /// Delete the vault. The room itself is unaffected.
    Reset,
}

fn main() -> Result<()> {
    install_tls_backend();
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Keygen) => keygen(),
        Some(Command::Relaykey) => relaykey(),
        Some(Command::Authkey { ref access_key }) => authkey(access_key.as_deref()),
        Some(Command::Invite {
            ref relay,
            ref access_key,
            ref room_key,
        }) => make_invite(relay, access_key, room_key.as_deref()),
        Some(Command::Where) => {
            println!("{}", vault_path(&cli)?.display());
            Ok(())
        }
        Some(Command::Reset) => reset(&vault_path(&cli)?),
        None => {
            // The runtime is only built for the chat path; the subcommands
            // above are synchronous and shouldn't pay for it.
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(chat(cli))
        }
    }
}

/// Selects the TLS backend rustls will use, before anything can use TLS.
///
/// rustls 0.23 declines to guess a backend, and panics on the first `wss://`
/// connection if exactly one isn't enabled across the whole dependency graph —
/// a condition any unrelated crate can silently change. Installing it here
/// makes the choice ours and turns a would-be runtime panic into a decision
/// visible in the source.
fn install_tls_backend() {
    // An `Err` means a provider was already installed, which is equally fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Prints a fresh room key.
fn keygen() -> Result<()> {
    let key = RoomKey::generate();
    println!("Room key   {}", key.encode());
    println!();
    println!("Give that to anyone you want in this room. It is what encrypts the");
    println!("messages, so send it over something you already trust.");
    println!();
    println!("No relay needs configuring for it: the relay routes by a one-way id");
    println!("derived from this key, and never learns the key itself. The room exists");
    println!("as soon as somebody joins it.");
    println!();
    println!("People also need the relay's access key. `rustchat invite` bundles both");
    println!("with the relay address into a single value to paste.");
    Ok(())
}

/// Prints a fresh relay access key and the auth key to configure a relay with.
fn relaykey() -> Result<()> {
    let key = AccessKey::generate();
    println!("Relay access key   {}", key.encode());
    println!();
    println!("Give this to everyone who should be able to use your relay. It decides");
    println!("who may connect, and nothing else — it cannot read any room.");
    println!();
    println!("Relay auth key (for the relay's --auth-key / RUSTCHAT_AUTH_KEY):");
    println!("  {}", key.auth_hex());
    println!();
    println!("The relay only ever needs that second value, which is derived one-way");
    println!("from the access key. Configure it with:");
    println!();
    println!(
        "  sudo sh deploy/setup-relay.sh --auth-key {}",
        key.auth_hex()
    );
    Ok(())
}

/// Prints the relay auth key derived from an existing relay access key.
fn authkey(access_key: Option<&str>) -> Result<()> {
    let raw = match access_key {
        Some(key) => key.to_string(),
        None => {
            eprint!("Relay access key: ");
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("reading the access key from stdin")?;
            line
        }
    };
    let key = AccessKey::parse_or_derive(&raw).context("that is not a usable access key")?;
    println!("{}", key.auth_hex());
    Ok(())
}

/// Builds a one-paste invite.
fn make_invite(relay: &str, access_key: &str, room_key: Option<&str>) -> Result<()> {
    let relay_url = app::normalize_relay(relay).map_err(|e| anyhow::anyhow!(e))?;
    let access = AccessKey::parse_or_derive(access_key).context("--access-key")?;
    let room = match room_key {
        Some(raw) => Some(RoomKey::parse_or_derive(raw).context("--room-key")?),
        None => None,
    };
    let scoped = room.is_some();
    let invite = Invite {
        relay_url,
        access_key: access,
        room_key: room,
    };
    println!("{}", invite.encode());
    eprintln!();
    if scoped {
        eprintln!("That gets someone into this exact room in one paste.");
    } else {
        eprintln!("That grants access to the relay, but no particular room — the holder");
        eprintln!("picks or creates one.");
    }
    eprintln!("It contains the keys, so treat it as secret.");
    Ok(())
}

fn reset(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        println!("No vault at {} — nothing to remove.", path.display());
        return Ok(());
    }
    std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    println!("Removed {}.", path.display());
    println!("Your saved history is gone. Rejoin with the room key to start again.");
    Ok(())
}

fn vault_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = &cli.vault {
        return Ok(path.clone());
    }
    let dir = dirs::config_dir()
        .context("could not work out your config directory; pass --vault")?
        .join("rustchat");
    Ok(dir.join("vault"))
}

/// Runs the TUI.
async fn chat(cli: Cli) -> Result<()> {
    let path = vault_path(&cli)?;

    // An explicit invite or room key means "just connect": the vault is
    // skipped entirely rather than created or consulted.
    let direct = cli.invite.is_some() || cli.room_key.is_some();
    let ephemeral = cli.no_vault || direct;
    let vault_exists = path.exists() && !cli.no_vault && !direct;
    let relay_hint = cli
        .relay
        .clone()
        .unwrap_or_else(|| DEFAULT_RELAY.to_string());

    // Resolved before the TUI starts, so a bad key or invite fails on a plain
    // terminal with a readable message instead of inside the alternate screen.
    let direct_conn = resolve_direct(&cli, &relay_hint)?;

    let screen = if vault_exists {
        Screen::Unlock(Unlock::new())
    } else if direct_conn.is_some() {
        Screen::Chat
    } else {
        Screen::Setup(Box::new(Setup::new(
            app::normalize_relay(&relay_hint).unwrap_or(relay_hint.clone()),
        )))
    };

    let mut app = App::new(path, screen, relay_hint.clone(), ephemeral);

    let mut pending = None;
    if let Some((conn, room_key, access_key)) = direct_conn {
        app.relay = conn.relay_url.clone();
        app.username = proto::sanitize_username(cli.username.as_deref().unwrap_or("anon"));
        app.room_key_display = Some(room_key.encode());
        app.invite_display = Some(
            Invite {
                relay_url: conn.relay_url.clone(),
                access_key,
                room_key: Some(room_key),
            }
            .encode(),
        );
        pending = Some(conn);
    }

    let mut terminal = ratatui::try_init().context("setting up the terminal")?;
    let result = run(&mut terminal, &mut app, cli, pending).await;
    ratatui::restore();

    // Persisting after the terminal is restored means a failure here is
    // actually readable instead of being swallowed by the alternate screen.
    if let Err(err) = app.save_vault() {
        eprintln!("warning: could not save your vault: {err:#}");
    }
    result
}

/// A connection resolved from the command line, with the keys kept alongside
/// so the caller can display them; [`net::Connection`] consumes what it needs.
type Direct = (net::Connection, RoomKey, AccessKey);

/// Turns `--invite`, or `--room-key` plus `--access-key`, into a connection.
fn resolve_direct(cli: &Cli, relay_hint: &str) -> Result<Option<Direct>> {
    if let Some(raw) = &cli.invite {
        let invite = Invite::decode(raw).context("--invite / RUSTCHAT_INVITE")?;
        let room = invite
            .room_key
            .context("that invite carries no room key, so there is no room to join")?;
        // An explicit --relay still wins, so one invite can be pointed at a
        // different address for the same relay.
        let relay_url = match &cli.relay {
            Some(relay) => app::normalize_relay(relay).map_err(|e| anyhow::anyhow!(e))?,
            None => app::normalize_relay(&invite.relay_url).map_err(|e| anyhow::anyhow!(e))?,
        };
        let conn = net::Connection {
            relay_url,
            access: AccessKey::from_bytes(*invite.access_key.as_bytes()),
            room: room.derive(),
        };
        return Ok(Some((conn, room, invite.access_key)));
    }

    let Some(raw_room) = &cli.room_key else {
        return Ok(None);
    };
    let access_raw = cli.access_key.as_deref().context(
        "--room-key needs --access-key too (the relay's access key). \
         `rustchat invite` bundles both into a single value to paste.",
    )?;
    let room = RoomKey::parse_or_derive(raw_room).context("--room-key / RUSTCHAT_ROOM_KEY")?;
    let access =
        AccessKey::parse_or_derive(access_raw).context("--access-key / RUSTCHAT_ACCESS_KEY")?;
    let conn = net::Connection {
        relay_url: app::normalize_relay(relay_hint).map_err(|e| anyhow::anyhow!(e))?,
        access: AccessKey::from_bytes(*access.as_bytes()),
        room: room.derive(),
    };
    Ok(Some((conn, room, access)))
}

async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    cli: Cli,
    pending: Option<net::Connection>,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut net_tx: Option<tokio::sync::mpsc::Sender<NetCmd>> = None;
    let mut net_rx: Option<tokio::sync::mpsc::Receiver<NetEvent>> = None;

    if let Some(conn) = pending {
        let (tx, rx) = net::spawn(conn);
        net_tx = Some(tx);
        net_rx = Some(rx);
        app.status = Status::Connecting;
    }

    // Redraws on a timer as well as on input, so the status line and
    // reconnect messages stay current while nothing is being typed.
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;
        if app.should_quit {
            break;
        }

        let action = tokio::select! {
            input = events.next() => match input {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => app.on_key(key),
                // A resize or a paste just needs the redraw at the top of the
                // loop; anything else we ignore.
                Some(Ok(_)) => Action::None,
                Some(Err(err)) => return Err(err).context("reading terminal input"),
                None => break,
            },

            event = recv(&mut net_rx) => {
                match event {
                    Some(event) => { handle_net_event(app, event, &net_tx).await; Action::None }
                    // The net task is gone for good; without it there is no
                    // room left to sit in.
                    None => { app.status = Status::Offline; Action::None }
                }
            }

            _ = tick.tick() => Action::None,
        };

        match action {
            Action::None => {}
            Action::Quit => {
                if let (Some(tx), false) = (&net_tx, app.username.is_empty()) {
                    let _ = tx
                        .send(NetCmd::Send(Payload::Leave {
                            user: app.username.clone(),
                            ts: proto::now_ms(),
                        }))
                        .await;
                    let _ = tx.send(NetCmd::Shutdown).await;
                }
                break;
            }
            Action::Send(payload) => match &net_tx {
                Some(tx) => {
                    if tx.send(NetCmd::Send(payload)).await.is_err() {
                        app.system("Not connected — that didn't go out.", Level::Bad);
                    }
                }
                None => app.system("Not connected yet.", Level::Warn),
            },
            Action::TryUnlock => {
                do_unlock(terminal, app, &cli, &mut net_tx, &mut net_rx).await?;
            }
            Action::FinishSetup => {
                do_finish_setup(terminal, app, &mut net_tx, &mut net_rx).await?;
            }
        }
    }
    Ok(())
}

/// Awaits the next network event, or parks forever if there is no connection.
///
/// Parking matters twice over. Before a connection exists there is no receiver
/// to poll, and once the network task has exited for good its channel returns
/// `None` immediately and permanently — so the slot is cleared on the way out.
/// Without that, this `select!` arm completes instantly on every iteration and
/// the event loop spins at 100% CPU redrawing forever, which is exactly what
/// happens after the relay turns a client away.
async fn recv(rx: &mut Option<tokio::sync::mpsc::Receiver<NetEvent>>) -> Option<NetEvent> {
    match rx.as_mut() {
        Some(inner) => match inner.recv().await {
            Some(event) => Some(event),
            None => {
                *rx = None;
                None
            }
        },
        None => std::future::pending().await,
    }
}

async fn handle_net_event(
    app: &mut App,
    event: NetEvent,
    net_tx: &Option<tokio::sync::mpsc::Sender<NetCmd>>,
) {
    match event {
        NetEvent::Connecting => {
            if app.status != Status::Connecting {
                app.status = Status::Connecting;
            }
        }
        NetEvent::Connected { occupants } => {
            let reconnected = matches!(app.status, Status::Retrying(_));
            app.status = Status::Online;
            app.occupants = occupants;
            app.system(
                if reconnected {
                    "Back online.".to_string()
                } else {
                    format!(
                        "Connected to {}. {} here. /help for commands.",
                        app.relay, occupants
                    )
                },
                Level::Good,
            );
            // Announcing after every connect is what makes a reconnect
            // re-introduce you without any special handling.
            if let Some(tx) = net_tx {
                let _ = tx
                    .send(NetCmd::Send(Payload::Join {
                        user: app.username.clone(),
                        ts: proto::now_ms(),
                    }))
                    .await;
            }
        }
        NetEvent::History(payloads) => {
            let count = payloads.len();
            for payload in payloads {
                app.absorb(payload, true);
            }
            if count > 0 {
                app.system(
                    format!(
                        "— {count} recent line{} from the relay —",
                        app::plural(count)
                    ),
                    Level::Info,
                );
            }
        }
        NetEvent::Payload(payload) => app.absorb(payload, false),
        NetEvent::Occupants(n) => app.occupants = n,
        NetEvent::Notice(text) => app.system(text, Level::Info),
        NetEvent::Disconnected(why) => {
            app.status = Status::Retrying(why.clone());
            app.occupants = 0;
            app.system(format!("Disconnected: {why}. Retrying…"), Level::Warn);
        }
        NetEvent::Fatal(why) => {
            app.status = Status::Offline;
            let key_problem = why.contains("room key");
            app.system(format!("Giving up: {why}"), Level::Bad);
            // A rejected key is saved in the vault, so relaunching reproduces
            // this exactly. Without a way out this screen is a dead end.
            if key_problem && !app.ephemeral {
                app.system(
                    "That key is stored in your vault, so relaunching will fail the same \
                     way. Run `rustchat reset` and rejoin with the key you were given.",
                    Level::Info,
                );
            } else if key_problem {
                app.system(
                    "Check the key against the one you were sent — `rustchat authkey <key>` \
                     prints what the relay would need to accept it.",
                    Level::Info,
                );
            }
        }
    }
}

/// Tries the entered passphrase against the vault, then connects.
async fn do_unlock(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    cli: &Cli,
    net_tx: &mut Option<tokio::sync::mpsc::Sender<NetCmd>>,
    net_rx: &mut Option<tokio::sync::mpsc::Receiver<NetEvent>>,
) -> Result<()> {
    let Screen::Unlock(unlock) = &mut app.screen else {
        return Ok(());
    };
    let passphrase = unlock.passphrase.clone();

    // Show the "deriving" frame before the work starts, since Argon2 is
    // deliberately slow enough to notice.
    terminal.draw(|frame| ui::draw(frame, app))?;

    let bytes = std::fs::read(&app.vault_path)
        .with_context(|| format!("reading {}", app.vault_path.display()))?;
    let attempt = {
        let passphrase = passphrase.clone();
        tokio::task::spawn_blocking(move || open_vault(&passphrase, &bytes)).await?
    };

    let data = match attempt {
        Ok(data) => data,
        Err(err) => {
            let Screen::Unlock(unlock) = &mut app.screen else {
                return Ok(());
            };
            unlock.busy = false;
            unlock.attempts += 1;
            unlock.passphrase.clear();
            unlock.error = Some(format!("{err:#}"));
            return Ok(());
        }
    };

    let key = decode_room_key(&data.room_key_b64)?;
    // A vault from before relay access keys existed cannot connect, and no
    // amount of retrying the passphrase will change that — say so plainly.
    if data.access_key_b64.is_empty() {
        let Screen::Unlock(unlock) = &mut app.screen else {
            return Ok(());
        };
        unlock.busy = false;
        unlock.passphrase.clear();
        unlock.error = Some(
            "This vault predates relay access keys. Run `rustchat reset` and set up again.".into(),
        );
        return Ok(());
    }
    let access = decode_access_key(&data.access_key_b64)?;
    app.passphrase = passphrase;
    app.username = proto::sanitize_username(cli.username.as_deref().unwrap_or(
        if data.username.is_empty() {
            "anon"
        } else {
            &data.username
        },
    ));
    // A --relay flag wins over the saved value, but doesn't overwrite it.
    app.relay = match &cli.relay {
        Some(relay) => app::normalize_relay(relay).map_err(|e| anyhow::anyhow!(e))?,
        None if !data.relay_url.is_empty() => data.relay_url.clone(),
        None => app::normalize_relay(DEFAULT_RELAY).map_err(|e| anyhow::anyhow!(e))?,
    };
    app.room_key_display = Some(key.encode());
    app.invite_display = Some(
        Invite {
            relay_url: app.relay.clone(),
            access_key: AccessKey::from_bytes(*access.as_bytes()),
            room_key: Some(RoomKey::from_bytes(*key.as_bytes())),
        }
        .encode(),
    );
    app.vault = data;
    app.screen = Screen::Chat;
    app.load_history();

    let (tx, rx) = net::spawn(net::Connection {
        relay_url: app.relay.clone(),
        access,
        room: key.derive(),
    });
    *net_tx = Some(tx);
    *net_rx = Some(rx);
    app.status = Status::Connecting;
    Ok(())
}

/// Seals a brand-new vault, then connects.
async fn do_finish_setup(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    net_tx: &mut Option<tokio::sync::mpsc::Sender<NetCmd>>,
    net_rx: &mut Option<tokio::sync::mpsc::Receiver<NetEvent>>,
) -> Result<()> {
    terminal.draw(|frame| ui::draw(frame, app))?;

    let Screen::Setup(setup) = &mut app.screen else {
        return Ok(());
    };
    let Some(room_key) = setup.room_key.as_ref() else {
        setup.busy = false;
        setup.error = Some("No room key — go back and set one.".into());
        return Ok(());
    };
    let Some(access_key) = setup.access_key.as_ref() else {
        setup.busy = false;
        setup.error = Some("No relay access key — go back and set one.".into());
        return Ok(());
    };

    let passphrase = setup.passphrase.clone();
    let data = VaultData {
        room_key_b64: encode_b64(room_key.as_bytes()),
        access_key_b64: encode_b64(access_key.as_bytes()),
        relay_url: setup.relay.clone(),
        username: setup.username.clone(),
        history: Vec::new(),
    };
    let conn = net::Connection {
        relay_url: setup.relay.clone(),
        access: AccessKey::from_bytes(*access_key.as_bytes()),
        room: room_key.derive(),
    };
    let key_display = room_key.encode();
    let invite_display = Invite {
        relay_url: setup.relay.clone(),
        access_key: AccessKey::from_bytes(*access_key.as_bytes()),
        room_key: Some(RoomKey::from_bytes(*room_key.as_bytes())),
    }
    .encode();
    let relay = setup.relay.clone();
    let username = setup.username.clone();

    if !app.ephemeral {
        let sealed = {
            let passphrase = passphrase.clone();
            let data = data.clone();
            tokio::task::spawn_blocking(move || seal_vault(&passphrase, &data)).await??
        };
        let path = app.vault_path.clone();
        app::write_private(&path, &sealed)?;
    }

    app.passphrase = passphrase;
    app.vault = data;
    app.username = username;
    app.relay = relay;
    app.room_key_display = Some(key_display);
    app.invite_display = Some(invite_display);
    app.screen = Screen::Chat;
    if !app.ephemeral {
        app.system(
            format!("Vault sealed at {}.", app.vault_path.display()),
            Level::Good,
        );
    }

    let (tx, rx) = net::spawn(conn);
    *net_tx = Some(tx);
    *net_rx = Some(rx);
    app.status = Status::Connecting;
    Ok(())
}

fn encode_b64(bytes: &[u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(b64: &str, what: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .with_context(|| format!("the vault's {what} is malformed"))?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("the vault's {what} is the wrong length"))
}

fn decode_room_key(b64: &str) -> Result<RoomKey> {
    Ok(RoomKey::from_bytes(decode_b64(b64, "room key")?))
}

fn decode_access_key(b64: &str) -> Result<AccessKey> {
    Ok(AccessKey::from_bytes(decode_b64(b64, "access key")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recv_parks_once_the_network_task_is_gone() {
        // The bug this guards: a closed channel returns None instantly and
        // forever, so the select! arm completed every iteration and the event
        // loop burned 100% CPU after the relay rejected a client.
        let (tx, rx) = tokio::sync::mpsc::channel::<NetEvent>(1);
        let mut slot = Some(rx);
        drop(tx);

        assert!(
            recv(&mut slot).await.is_none(),
            "a closed channel yields None once"
        );
        assert!(slot.is_none(), "the receiver slot must be cleared");

        assert!(
            tokio::time::timeout(Duration::from_millis(50), recv(&mut slot))
                .await
                .is_err(),
            "recv must park when there is no receiver; returning immediately spins the event loop"
        );
    }

    #[tokio::test]
    async fn recv_parks_before_any_connection_exists() {
        let mut slot: Option<tokio::sync::mpsc::Receiver<NetEvent>> = None;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), recv(&mut slot))
                .await
                .is_err()
        );
    }

    #[test]
    fn a_tls_backend_is_available() {
        // Guards against the dependency graph losing its rustls backend, which
        // would otherwise only surface as a panic on the first wss:// connect.
        install_tls_backend();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "no rustls crypto provider is installed; wss:// would panic"
        );
    }

    #[test]
    fn installing_the_tls_backend_twice_is_harmless() {
        install_tls_backend();
        install_tls_backend();
    }

    #[test]
    fn relaykey_and_authkey_agree() {
        // `relaykey` prints an access key plus the auth key to configure a
        // relay with; `authkey` re-derives it from the access key later. If
        // they ever disagreed, a relay set up from one would reject clients
        // holding the other.
        let key = AccessKey::generate();
        let printed = key.auth_hex();
        let reparsed = AccessKey::decode(&key.encode()).unwrap();
        assert_eq!(reparsed.auth_hex(), printed);
    }

    #[test]
    fn a_room_key_is_not_accepted_as_an_access_key() {
        // The two are pasted into adjacent prompts, so mixing them up must
        // fail loudly rather than silently deriving a key from the wrong one.
        let room = RoomKey::generate();
        assert!(AccessKey::decode(&room.encode()).is_err());
    }

    #[test]
    fn a_direct_room_key_without_an_access_key_is_refused() {
        // Otherwise the failure would surface as a confusing relay rejection.
        let cli = Cli {
            relay: None,
            room_key: Some(RoomKey::generate().encode()),
            access_key: None,
            invite: None,
            username: None,
            no_vault: true,
            vault: None,
            command: None,
        };
        let err = resolve_direct(&cli, DEFAULT_RELAY).unwrap_err().to_string();
        assert!(err.contains("--access-key"), "got: {err}");
    }

    #[test]
    fn an_invite_resolves_to_a_connection() {
        let access = AccessKey::generate();
        let room = RoomKey::generate();
        let token = Invite {
            relay_url: "wss://relay.example.com/ws".into(),
            access_key: AccessKey::from_bytes(*access.as_bytes()),
            room_key: Some(RoomKey::from_bytes(*room.as_bytes())),
        }
        .encode();
        let cli = Cli {
            relay: None,
            room_key: None,
            access_key: None,
            invite: Some(token),
            username: None,
            no_vault: true,
            vault: None,
            command: None,
        };
        let (conn, room_back, access_back) = resolve_direct(&cli, DEFAULT_RELAY).unwrap().unwrap();
        assert_eq!(conn.relay_url, "wss://relay.example.com/ws");
        assert_eq!(room_back.as_bytes(), room.as_bytes());
        assert_eq!(access_back.as_bytes(), access.as_bytes());
        assert_eq!(conn.room.room_id, room.derive().room_id);
    }

    #[test]
    fn an_explicit_relay_overrides_the_invites() {
        let token = Invite {
            relay_url: "wss://from-invite.example/ws".into(),
            access_key: AccessKey::generate(),
            room_key: Some(RoomKey::generate()),
        }
        .encode();
        let cli = Cli {
            relay: Some("override.example".into()),
            room_key: None,
            access_key: None,
            invite: Some(token),
            username: None,
            no_vault: true,
            vault: None,
            command: None,
        };
        let (conn, _, _) = resolve_direct(&cli, DEFAULT_RELAY).unwrap().unwrap();
        assert_eq!(conn.relay_url, "wss://override.example/ws");
    }

    #[test]
    fn an_invite_without_a_room_is_refused_for_a_direct_join() {
        // Relay-access-only invites are valid, but there is no room to enter,
        // so the wizard has to ask — a direct join cannot.
        let token = Invite {
            relay_url: "wss://relay.example/ws".into(),
            access_key: AccessKey::generate(),
            room_key: None,
        }
        .encode();
        let cli = Cli {
            relay: None,
            room_key: None,
            access_key: None,
            invite: Some(token),
            username: None,
            no_vault: true,
            vault: None,
            command: None,
        };
        let err = resolve_direct(&cli, DEFAULT_RELAY).unwrap_err().to_string();
        assert!(err.contains("no room key"), "got: {err}");
    }

    #[test]
    fn room_keys_survive_the_vault_encoding() {
        let key = RoomKey::generate();
        let back = decode_room_key(&encode_b64(key.as_bytes())).unwrap();
        assert_eq!(key.as_bytes(), back.as_bytes());
    }

    #[test]
    fn malformed_vault_keys_are_rejected() {
        assert!(decode_room_key("!!!").is_err());
        assert!(decode_room_key("dG9vIHNob3J0").is_err());
    }
}
