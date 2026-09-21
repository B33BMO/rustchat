//! rustchat — an encrypted TUI chatroom.
//!
//! Everyone with the room key is in the room. Messages are sealed on your
//! machine and opened on theirs; the relay in between only ever handles
//! ciphertext. See `rustchat-core` for the details.

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
use rustchat_core::{Payload, RoomKey, proto};

#[derive(Parser, Debug)]
#[command(
    name = "rustchat",
    version,
    about = "An end-to-end encrypted TUI chatroom.",
    long_about = "An end-to-end encrypted TUI chatroom.\n\nAnyone holding the room key can \
                  join and talk. Messages are sealed before they leave your machine, so the \
                  relay that carries them cannot read them."
)]
struct Cli {
    /// Relay to connect to. Overrides the one saved in your vault.
    #[arg(long, short)]
    relay: Option<String>,

    /// Use this room key for this session only, skipping the vault entirely.
    ///
    /// Prefer the `RUSTCHAT_ROOM_KEY` environment variable: an argument is
    /// visible to anyone who can list processes on this machine.
    #[arg(long, env = "RUSTCHAT_ROOM_KEY", hide_env_values = true)]
    room_key: Option<String>,

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
    /// Generate a room key, and the auth key its relay needs.
    Keygen,
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

/// Prints a fresh room key alongside the auth key to configure a relay with.
fn keygen() -> Result<()> {
    let key = RoomKey::generate();
    let keys = key.derive();
    println!("Room key   {}", key.encode());
    println!();
    println!("Give that to anyone you want in the room. It is the only credential,");
    println!("so treat it like a door key: send it over something you already trust.");
    println!();
    println!("Relay auth key (for the relay's --auth-key / RUSTCHAT_AUTH_KEY):");
    println!("  {}", keys.auth_hex());
    println!();
    println!("The relay only ever needs that second value. It is derived one-way from");
    println!("the room key, so a compromised relay still cannot read any message.");
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
    let vault_exists = path.exists() && !cli.no_vault && cli.room_key.is_none();
    let relay_hint = cli
        .relay
        .clone()
        .unwrap_or_else(|| DEFAULT_RELAY.to_string());

    // An explicit --room-key (or the env var) means "just connect", so the
    // vault is skipped entirely rather than created or consulted.
    let ephemeral = cli.no_vault || cli.room_key.is_some();

    let screen = if vault_exists {
        Screen::Unlock(Unlock::new())
    } else if cli.room_key.is_some() {
        // Nothing left to ask: the key came in on the command line, so setup
        // is skipped and the session goes straight to the room.
        Screen::Chat
    } else {
        Screen::Setup(Setup::new(
            app::normalize_relay(&relay_hint).unwrap_or(relay_hint.clone()),
        ))
    };

    let mut app = App::new(path, screen, relay_hint.clone(), ephemeral);

    // The direct-key path has no setup or unlock screen to go through, so it
    // is wired up before the loop starts.
    let mut pending_keys = None;
    if let Some(raw) = &cli.room_key {
        let key = RoomKey::parse_or_derive(raw).context("--room-key / RUSTCHAT_ROOM_KEY")?;
        app.relay = app::normalize_relay(&relay_hint).map_err(|e| anyhow::anyhow!(e))?;
        app.username = proto::sanitize_username(cli.username.as_deref().unwrap_or("anon"));
        app.room_key_display = Some(key.encode());
        pending_keys = Some(key.derive());
    }

    let mut terminal = ratatui::try_init().context("setting up the terminal")?;
    let result = run(&mut terminal, &mut app, cli, pending_keys).await;
    ratatui::restore();

    // Persisting after the terminal is restored means a failure here is
    // actually readable instead of being swallowed by the alternate screen.
    if let Err(err) = app.save_vault() {
        eprintln!("warning: could not save your vault: {err:#}");
    }
    result
}

async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    cli: Cli,
    pending_keys: Option<rustchat_core::Keys>,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut net_tx: Option<tokio::sync::mpsc::Sender<NetCmd>> = None;
    let mut net_rx: Option<tokio::sync::mpsc::Receiver<NetEvent>> = None;

    if let Some(keys) = pending_keys {
        let (tx, rx) = net::spawn(app.relay.clone(), keys);
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

/// Awaits the next network event, or blocks forever if there is no connection.
///
/// Returning `None` eagerly would make `select!` spin at full speed whenever
/// the client isn't connected, which is most of setup.
async fn recv(rx: &mut Option<tokio::sync::mpsc::Receiver<NetEvent>>) -> Option<NetEvent> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
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
            app.system(format!("Giving up: {why}"), Level::Bad);
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
    app.vault = data;
    app.screen = Screen::Chat;
    app.load_history();

    let (tx, rx) = net::spawn(app.relay.clone(), key.derive());
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

    let passphrase = setup.passphrase.clone();
    let data = VaultData {
        room_key_b64: encode_room_key(room_key),
        relay_url: setup.relay.clone(),
        username: setup.username.clone(),
        history: Vec::new(),
    };
    let keys = room_key.derive();
    let key_display = room_key.encode();
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
    app.screen = Screen::Chat;
    if !app.ephemeral {
        app.system(
            format!("Vault sealed at {}.", app.vault_path.display()),
            Level::Good,
        );
    }

    let (tx, rx) = net::spawn(app.relay.clone(), keys);
    *net_tx = Some(tx);
    *net_rx = Some(rx);
    app.status = Status::Connecting;
    Ok(())
}

fn encode_room_key(key: &RoomKey) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

fn decode_room_key(b64: &str) -> Result<RoomKey> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("the vault's room key is malformed")?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("the vault's room key is the wrong length"))?;
    Ok(RoomKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn room_keys_survive_the_vault_encoding() {
        let key = RoomKey::generate();
        let back = decode_room_key(&encode_room_key(&key)).unwrap();
        assert_eq!(key.as_bytes(), back.as_bytes());
    }

    #[test]
    fn malformed_vault_keys_are_rejected() {
        assert!(decode_room_key("!!!").is_err());
        assert!(decode_room_key("dG9vIHNob3J0").is_err());
    }
}
