//! Client state and key handling. Knows nothing about drawing or sockets.

use std::path::PathBuf;

use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use rustchat_core::vault::{StoredLine, VaultData};
use rustchat_core::{Payload, RoomKey, proto};

/// Default relay, overridable at setup or with `--relay`.
pub const DEFAULT_RELAY: &str = "wss://relay.bmo.guru/ws";

/// One line in the transcript.
#[derive(Debug, Clone)]
pub enum Entry {
    Msg {
        user: String,
        body: String,
        ts: i64,
        /// Ours, so the UI can mark it. Nothing is authenticated here: any
        /// room member can put any name on a message, so this is a display
        /// nicety, not a claim about who sent what.
        own: bool,
    },
    Presence {
        user: String,
        joined: bool,
        ts: i64,
    },
    /// Local commentary — connection state, command output, errors.
    System {
        body: String,
        level: Level,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Good,
    Warn,
    Bad,
}

/// Connection state, as far as the UI is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Offline,
    Connecting,
    Online,
    Retrying(String),
}

/// Which screen is in front of the user.
pub enum Screen {
    /// First run: no vault yet.
    Setup(Setup),
    /// A vault exists; it needs a passphrase.
    Unlock(Unlock),
    Chat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Create a new room or join an existing one.
    Mode,
    /// Showing a freshly generated key, so it can be written down.
    ShowKey,
    EnterKey,
    Relay,
    Username,
    Passphrase,
    Confirm,
}

pub struct Setup {
    pub step: Step,
    /// Index of the highlighted choice on [`Step::Mode`].
    pub mode_cursor: usize,
    /// Set once a key is generated or successfully parsed.
    pub room_key: Option<RoomKey>,
    pub key_input: String,
    pub relay: String,
    pub username: String,
    pub passphrase: String,
    pub confirm: String,
    pub error: Option<String>,
    pub busy: bool,
}

impl Setup {
    pub fn new(relay: String) -> Self {
        Self {
            step: Step::Mode,
            mode_cursor: 0,
            room_key: None,
            key_input: String::new(),
            relay,
            username: String::new(),
            passphrase: String::new(),
            confirm: String::new(),
            error: None,
            busy: false,
        }
    }

    /// The field the current step is editing, if it edits one.
    fn field_mut(&mut self) -> Option<&mut String> {
        match self.step {
            Step::EnterKey => Some(&mut self.key_input),
            Step::Relay => Some(&mut self.relay),
            Step::Username => Some(&mut self.username),
            Step::Passphrase => Some(&mut self.passphrase),
            Step::Confirm => Some(&mut self.confirm),
            Step::Mode | Step::ShowKey => None,
        }
    }
}

pub struct Unlock {
    pub passphrase: String,
    pub error: Option<String>,
    pub busy: bool,
    /// Consecutive wrong passphrases, shown so a typo doesn't read as a
    /// corrupted vault.
    pub attempts: u32,
}

impl Unlock {
    pub fn new() -> Self {
        Self {
            passphrase: String::new(),
            error: None,
            busy: false,
            attempts: 0,
        }
    }
}

/// What the event loop should do after handling a key.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing beyond a redraw.
    None,
    /// Seal the vault and start connecting.
    FinishSetup,
    /// Try the entered passphrase against the vault.
    TryUnlock,
    /// Publish this payload to the room.
    Send(Payload),
    Quit,
}

pub struct App {
    pub screen: Screen,
    pub entries: Vec<Entry>,
    pub input: String,
    /// Caret position in `input`, in characters.
    pub cursor: usize,
    /// Lines scrolled up from the bottom. 0 means pinned to newest.
    pub scroll: u16,
    pub occupants: usize,
    pub status: Status,
    pub username: String,
    pub relay: String,
    pub vault_path: PathBuf,
    pub vault: VaultData,
    /// Held so the vault can be re-sealed on exit. Zeroed when `App` drops.
    pub passphrase: String,
    pub room_key_display: Option<String>,
    /// True when `--no-vault` was passed: nothing is written to disk.
    pub ephemeral: bool,
    pub should_quit: bool,
}

impl App {
    pub fn new(vault_path: PathBuf, screen: Screen, relay: String, ephemeral: bool) -> Self {
        Self {
            screen,
            entries: Vec::new(),
            input: String::new(),
            cursor: 0,
            scroll: 0,
            occupants: 0,
            status: Status::Offline,
            username: String::new(),
            relay,
            vault_path,
            vault: VaultData::default(),
            passphrase: String::new(),
            room_key_display: None,
            ephemeral,
            should_quit: false,
        }
    }

    pub fn system(&mut self, body: impl Into<String>, level: Level) {
        self.entries.push(Entry::System {
            body: body.into(),
            level,
        });
        self.trim();
    }

    /// Records an incoming payload, remembering chat lines for next launch.
    pub fn absorb(&mut self, payload: Payload, from_history: bool) {
        match payload {
            Payload::Msg { user, body, ts } => {
                let own = user == self.username;
                if !from_history && !self.ephemeral {
                    self.vault.push_line(StoredLine {
                        user: user.clone(),
                        body: body.clone(),
                        ts,
                    });
                }
                self.entries.push(Entry::Msg {
                    user,
                    body,
                    ts,
                    own,
                });
            }
            // Presence is noise in a replayed backlog: "bmo joined" from two
            // hours ago tells you nothing about who is here now.
            Payload::Join { user, ts } if !from_history => {
                self.entries.push(Entry::Presence {
                    user,
                    joined: true,
                    ts,
                });
            }
            Payload::Leave { user, ts } if !from_history => {
                self.entries.push(Entry::Presence {
                    user,
                    joined: false,
                    ts,
                });
            }
            _ => return,
        }
        self.trim();
    }

    /// Caps the in-memory transcript so a long session can't grow unbounded.
    fn trim(&mut self) {
        const MAX_ENTRIES: usize = 2000;
        if self.entries.len() > MAX_ENTRIES {
            let excess = self.entries.len() - MAX_ENTRIES;
            self.entries.drain(..excess);
        }
    }

    /// Seeds the transcript from the vault's remembered lines.
    pub fn load_history(&mut self) {
        let lines: Vec<StoredLine> = self.vault.history.clone();
        if lines.is_empty() {
            return;
        }
        let count = lines.len();
        for line in lines {
            let own = line.user == self.username;
            self.entries.push(Entry::Msg {
                user: line.user,
                body: line.body,
                ts: line.ts,
                own,
            });
        }
        self.system(
            format!("— {count} earlier line{} from your vault —", plural(count)),
            Level::Info,
        );
    }

    /// Routes a key press to whichever screen is in front.
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        // Ctrl-C always quits, on every screen. Nothing here is important
        // enough to trap someone in.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d'))
        {
            self.should_quit = true;
            return Action::Quit;
        }

        match &mut self.screen {
            Screen::Setup(_) => self.on_key_setup(key),
            Screen::Unlock(_) => self.on_key_unlock(key),
            Screen::Chat => self.on_key_chat(key),
        }
    }

    fn on_key_unlock(&mut self, key: KeyEvent) -> Action {
        let Screen::Unlock(unlock) = &mut self.screen else {
            return Action::None;
        };
        if unlock.busy {
            return Action::None;
        }
        match key.code {
            KeyCode::Enter => {
                if unlock.passphrase.is_empty() {
                    unlock.error = Some("Enter your passphrase.".into());
                    return Action::None;
                }
                unlock.busy = true;
                unlock.error = None;
                Action::TryUnlock
            }
            KeyCode::Backspace => {
                unlock.passphrase.pop();
                Action::None
            }
            KeyCode::Esc => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                unlock.passphrase.push(c);
                Action::None
            }
            _ => Action::None,
        }
    }

    fn on_key_setup(&mut self, key: KeyEvent) -> Action {
        let Screen::Setup(setup) = &mut self.screen else {
            return Action::None;
        };
        if setup.busy {
            return Action::None;
        }
        setup.error = None;

        match key.code {
            KeyCode::Esc => {
                self.should_quit = true;
                return Action::Quit;
            }
            KeyCode::Up if setup.step == Step::Mode => {
                setup.mode_cursor = setup.mode_cursor.saturating_sub(1);
                return Action::None;
            }
            KeyCode::Down if setup.step == Step::Mode => {
                setup.mode_cursor = (setup.mode_cursor + 1).min(1);
                return Action::None;
            }
            KeyCode::Backspace => {
                if let Some(field) = setup.field_mut() {
                    field.pop();
                } else if setup.step == Step::ShowKey {
                    setup.step = Step::Mode;
                    setup.room_key = None;
                }
                return Action::None;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(field) = setup.field_mut() {
                    field.push(c);
                }
                return Action::None;
            }
            KeyCode::Enter => {}
            _ => return Action::None,
        }

        // Enter: validate the current step and move on.
        match setup.step {
            Step::Mode => {
                // Joining is first and default: most people arrive holding a
                // key somebody sent them. Creating a room generates a *new*
                // key, which silently will not match a relay configured for a
                // different room — so it must be chosen deliberately, never
                // landed on by pressing Enter.
                if setup.mode_cursor == 0 {
                    setup.step = Step::EnterKey;
                } else {
                    setup.room_key = Some(RoomKey::generate());
                    setup.step = Step::ShowKey;
                }
            }
            Step::ShowKey => setup.step = Step::Relay,
            Step::EnterKey => match RoomKey::parse_or_derive(&setup.key_input) {
                Ok(key) => {
                    setup.room_key = Some(key);
                    setup.step = Step::Relay;
                }
                Err(err) => setup.error = Some(format!("{err:#}")),
            },
            Step::Relay => match normalize_relay(&setup.relay) {
                Ok(url) => {
                    setup.relay = url;
                    setup.step = Step::Username;
                }
                Err(err) => setup.error = Some(err),
            },
            Step::Username => {
                let name = proto::sanitize_username(&setup.username);
                if name == "anon" && setup.username.trim().is_empty() {
                    setup.error = Some("Pick a username.".into());
                } else {
                    setup.username = name;
                    setup.step = Step::Passphrase;
                }
            }
            Step::Passphrase => {
                if setup.passphrase.chars().count() < 8 {
                    setup.error = Some("Use at least 8 characters.".into());
                } else {
                    setup.step = Step::Confirm;
                }
            }
            Step::Confirm => {
                if setup.confirm != setup.passphrase {
                    setup.error = Some("Those don't match.".into());
                    setup.confirm.clear();
                } else {
                    setup.busy = true;
                    return Action::FinishSetup;
                }
            }
        }
        Action::None
    }

    fn on_key_chat(&mut self, key: KeyEvent) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => return self.submit_input(),
            KeyCode::Char('u') if ctrl => {
                self.input.clear();
                self.cursor = 0;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.input.chars().count(),
            KeyCode::Char('l') if ctrl => self.entries.clear(),
            KeyCode::Char(c) if !ctrl => {
                let byte_at = char_to_byte(&self.input, self.cursor);
                self.input.insert(byte_at, c);
                self.cursor += 1;
                // Typing means you want to see what you're replying to.
                self.scroll = 0;
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let byte_at = char_to_byte(&self.input, self.cursor - 1);
                    self.input.remove(byte_at);
                    self.cursor -= 1;
                }
            }
            KeyCode::Delete => {
                let count = self.input.chars().count();
                if self.cursor < count {
                    let byte_at = char_to_byte(&self.input, self.cursor);
                    self.input.remove(byte_at);
                }
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.input.chars().count()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.input.chars().count(),
            KeyCode::Up => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Down => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Esc => {
                self.input.clear();
                self.cursor = 0;
                self.scroll = 0;
            }
            _ => {}
        }
        Action::None
    }

    /// Handles Enter in the chat input: a slash command, or a message.
    fn submit_input(&mut self) -> Action {
        let raw = std::mem::take(&mut self.input);
        self.cursor = 0;
        self.scroll = 0;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Action::None;
        }

        if let Some(rest) = trimmed.strip_prefix('/') {
            return self.run_command(rest);
        }

        let body = proto::sanitize_body(trimmed);
        if body.is_empty() {
            return Action::None;
        }
        Action::Send(Payload::Msg {
            user: self.username.clone(),
            body,
            ts: proto::now_ms(),
        })
    }

    fn run_command(&mut self, rest: &str) -> Action {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let cmd = parts.next().unwrap_or("").to_lowercase();
        let arg = parts.next().unwrap_or("").trim().to_string();

        match cmd.as_str() {
            "quit" | "q" | "exit" => {
                self.should_quit = true;
                Action::Quit
            }
            "help" | "h" | "?" => {
                self.system(
                    "/key show the room key · /nick <name> rename · /who occupancy \
                     · /clear wipe the view · /forget erase saved history · /quit",
                    Level::Info,
                );
                Action::None
            }
            "key" => {
                match self.room_key_display.clone() {
                    Some(key) => {
                        self.system(
                            format!("Room key: {key}  (anyone with this can read the room)"),
                            Level::Warn,
                        );
                    }
                    None => self.system("Room key unavailable.", Level::Bad),
                }
                Action::None
            }
            "who" => {
                let n = self.occupants;
                self.system(
                    format!(
                        "{n} connection{} in the room. The relay can't tell you who — it \
                         doesn't know.",
                        plural(n)
                    ),
                    Level::Info,
                );
                Action::None
            }
            "clear" => {
                self.entries.clear();
                Action::None
            }
            "forget" => {
                self.vault.history.clear();
                self.entries.clear();
                self.system(
                    "Saved history cleared. It's gone from the vault on next save.",
                    Level::Good,
                );
                Action::None
            }
            "nick" => {
                if arg.is_empty() {
                    self.system("Usage: /nick <name>", Level::Bad);
                    return Action::None;
                }
                let old = std::mem::replace(&mut self.username, proto::sanitize_username(&arg));
                self.vault.username = self.username.clone();
                self.system(format!("You are now {}.", self.username), Level::Good);
                // Announced as a leave-then-join so other clients, which only
                // ever see names inside payloads, keep a coherent picture.
                Action::Send(Payload::Join {
                    user: format!("{} (was {old})", self.username),
                    ts: proto::now_ms(),
                })
            }
            other => {
                self.system(format!("Unknown command /{other}. Try /help."), Level::Bad);
                Action::None
            }
        }
    }

    /// Seals the vault to disk. A no-op in ephemeral mode.
    pub fn save_vault(&mut self) -> Result<()> {
        if self.ephemeral || self.passphrase.is_empty() {
            return Ok(());
        }
        self.vault.username = self.username.clone();
        self.vault.relay_url = self.relay.clone();
        let bytes = rustchat_core::vault::seal_vault(&self.passphrase, &self.vault)?;
        write_private(&self.vault_path, &bytes)
    }
}

impl Drop for App {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.passphrase.zeroize();
        self.vault.room_key_b64.zeroize();
    }
}

/// Writes `bytes` to `path` with owner-only permissions.
///
/// The file is created private from the start rather than chmod'ed afterwards,
/// so there is no window in which the vault sits on disk world-readable.
pub fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("opening {}", tmp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    // Rename last, so an interrupted save leaves the previous vault intact
    // rather than a half-written one.
    std::fs::rename(&tmp, path)
        .with_context(|| format!("moving the new vault into {}", path.display()))?;
    Ok(())
}

/// Turns what someone typed into a relay URL into a usable `ws(s)://…/ws`.
pub fn normalize_relay(input: &str) -> Result<String, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("Enter a relay address.".into());
    }
    if raw.contains(char::is_whitespace) {
        return Err("A relay address can't contain spaces.".into());
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        // Bare hostnames get TLS. Defaulting to plaintext here would be a
        // quiet downgrade at exactly the moment someone is being careless.
        format!("wss://{raw}")
    };
    let rest = match with_scheme.split_once("://") {
        Some(("ws", rest)) | Some(("wss", rest)) => rest,
        Some(("http", rest)) => return Ok(format!("ws://{}", ensure_path(rest))),
        Some(("https", rest)) => return Ok(format!("wss://{}", ensure_path(rest))),
        Some((scheme, _)) => return Err(format!("Don't know what to do with `{scheme}://`.")),
        None => unreachable!("a scheme was just ensured"),
    };
    if rest.is_empty() {
        return Err("That address has no host.".into());
    }
    let scheme = with_scheme
        .split_once("://")
        .map(|(s, _)| s)
        .unwrap_or("wss");
    Ok(format!("{scheme}://{}", ensure_path(rest)))
}

/// Appends the relay's `/ws` route if no path was given.
fn ensure_path(host_and_path: &str) -> String {
    if host_and_path.contains('/') {
        host_and_path.trim_end_matches('/').to_string()
    } else {
        format!("{host_and_path}/ws")
    }
}

/// Byte offset of character `index`, or the end of the string.
fn char_to_byte(s: &str, index: usize) -> usize {
    s.char_indices()
        .nth(index)
        .map(|(byte, _)| byte)
        .unwrap_or(s.len())
}

pub fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut app = App::new(
            PathBuf::from("/tmp/nope"),
            Screen::Chat,
            "wss://x/ws".into(),
            true,
        );
        app.username = "bmo".into();
        app
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn relay_addresses_are_normalized() {
        assert_eq!(
            normalize_relay("relay.bmo.guru").unwrap(),
            "wss://relay.bmo.guru/ws"
        );
        assert_eq!(normalize_relay("wss://x.io/ws").unwrap(), "wss://x.io/ws");
        assert_eq!(
            normalize_relay("ws://localhost:7777").unwrap(),
            "ws://localhost:7777/ws"
        );
        assert_eq!(
            normalize_relay("https://x.io/chat").unwrap(),
            "wss://x.io/chat"
        );
        assert_eq!(
            normalize_relay("http://localhost:7777").unwrap(),
            "ws://localhost:7777/ws"
        );
    }

    #[test]
    fn bare_hostnames_default_to_tls() {
        assert!(
            normalize_relay("example.com")
                .unwrap()
                .starts_with("wss://")
        );
    }

    #[test]
    fn relay_addresses_are_validated() {
        assert!(normalize_relay("").is_err());
        assert!(normalize_relay("   ").is_err());
        assert!(normalize_relay("has space.com").is_err());
        assert!(normalize_relay("ftp://x.io").is_err());
        assert!(normalize_relay("wss://").is_err());
    }

    #[test]
    fn typing_builds_a_message() {
        let mut app = app();
        for c in "hi".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.input, "hi");
        let action = app.on_key(key(KeyCode::Enter));
        match action {
            Action::Send(Payload::Msg { user, body, .. }) => {
                assert_eq!(user, "bmo");
                assert_eq!(body, "hi");
            }
            other => panic!("expected a send, got {other:?}"),
        }
        assert!(app.input.is_empty(), "input should clear after sending");
    }

    #[test]
    fn editing_respects_multibyte_characters() {
        let mut app = app();
        for c in "héllo".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Home));
        app.on_key(key(KeyCode::Right));
        app.on_key(key(KeyCode::Backspace)); // delete 'h'
        assert_eq!(app.input, "éllo");
        app.on_key(key(KeyCode::Delete)); // delete 'é'
        assert_eq!(app.input, "llo");
    }

    #[test]
    fn blank_input_sends_nothing() {
        let mut app = app();
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None);
        for c in "   ".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None);
    }

    #[test]
    fn ctrl_c_quits_from_any_screen() {
        for screen in [
            Screen::Chat,
            Screen::Unlock(Unlock::new()),
            Screen::Setup(Setup::new("x".into())),
        ] {
            let mut app = App::new(PathBuf::from("/tmp/nope"), screen, "x".into(), true);
            let action = app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
            assert_eq!(action, Action::Quit);
            assert!(app.should_quit);
        }
    }

    #[test]
    fn slash_quit_quits() {
        let mut app = app();
        for c in "/quit".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::Quit);
    }

    #[test]
    fn unknown_commands_are_reported_not_sent() {
        let mut app = app();
        for c in "/frobnicate".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None);
        assert!(matches!(
            app.entries.last(),
            Some(Entry::System {
                level: Level::Bad,
                ..
            })
        ));
    }

    #[test]
    fn setup_rejects_a_mismatched_passphrase() {
        let mut app = App::new(
            PathBuf::from("/tmp/nope"),
            Screen::Setup(Setup::new("x".into())),
            "x".into(),
            true,
        );
        let Screen::Setup(s) = &mut app.screen else {
            unreachable!()
        };
        s.step = Step::Confirm;
        s.passphrase = "hunter2hunter2".into();
        s.confirm = "something else".into();
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None);
        let Screen::Setup(s) = &app.screen else {
            unreachable!()
        };
        assert!(s.error.is_some());
        assert!(
            s.confirm.is_empty(),
            "a mismatched confirmation should reset"
        );
    }

    #[test]
    fn setup_requires_a_long_enough_passphrase() {
        let mut app = App::new(
            PathBuf::from("/tmp/nope"),
            Screen::Setup(Setup::new("x".into())),
            "x".into(),
            true,
        );
        let Screen::Setup(s) = &mut app.screen else {
            unreachable!()
        };
        s.step = Step::Passphrase;
        s.passphrase = "short".into();
        app.on_key(key(KeyCode::Enter));
        let Screen::Setup(s) = &app.screen else {
            unreachable!()
        };
        assert_eq!(s.step, Step::Passphrase, "should not advance");
        assert!(s.error.is_some());
    }

    #[test]
    fn replayed_history_hides_stale_presence() {
        let mut app = app();
        app.absorb(
            Payload::Join {
                user: "x".into(),
                ts: 0,
            },
            true,
        );
        assert!(app.entries.is_empty(), "old join notices are noise");
        app.absorb(
            Payload::Join {
                user: "x".into(),
                ts: 0,
            },
            false,
        );
        assert_eq!(app.entries.len(), 1);
    }

    #[test]
    fn own_messages_are_marked() {
        let mut app = app();
        app.absorb(
            Payload::Msg {
                user: "bmo".into(),
                body: "a".into(),
                ts: 0,
            },
            false,
        );
        app.absorb(
            Payload::Msg {
                user: "sam".into(),
                body: "b".into(),
                ts: 0,
            },
            false,
        );
        assert!(matches!(app.entries[0], Entry::Msg { own: true, .. }));
        assert!(matches!(app.entries[1], Entry::Msg { own: false, .. }));
    }

    #[test]
    fn ephemeral_mode_records_nothing_to_the_vault() {
        let mut app = app();
        app.absorb(
            Payload::Msg {
                user: "bmo".into(),
                body: "secret".into(),
                ts: 0,
            },
            false,
        );
        assert!(app.vault.history.is_empty());
    }

    #[test]
    fn transcript_is_capped() {
        let mut app = app();
        for i in 0..2500 {
            app.absorb(
                Payload::Msg {
                    user: "x".into(),
                    body: i.to_string(),
                    ts: 0,
                },
                false,
            );
        }
        assert!(app.entries.len() <= 2000);
    }
}
