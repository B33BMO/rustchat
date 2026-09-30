//! Client state and key handling. Knows nothing about drawing or sockets.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use rustchat_core::vault::{StoredLine, VaultData};
use rustchat_core::{AccessKey, Invite, Payload, RoomKey, proto};

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
        /// Addresses you by `@name`, so the UI can make it stand out.
        mention: bool,
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

/// Which incoming messages ring the bell and raise a desktop notification
/// while the terminal isn't focused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notify {
    /// Only messages that say `@you`.
    Mentions,
    All,
    Off,
}

impl Notify {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mentions" | "mention" | "" => Some(Self::Mentions),
            "all" => Some(Self::All),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mentions => "mentions",
            Self::All => "all",
            Self::Off => "off",
        }
    }
}

/// An open `Ctrl-F` search over the transcript.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Search {
    pub query: String,
    /// Which match is in view, counted back from the newest: 0 is the most
    /// recent, because what you're after is usually recent.
    pub current: usize,
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
    /// First run: no vault yet. Boxed because it is far larger than the other
    /// variants, and `Screen` is moved around as one value.
    Setup(Box<Setup>),
    /// A vault exists; it needs a passphrase.
    Unlock(Unlock),
    Chat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// One paste that carries the relay, its access key and a room key.
    /// Leaving it blank falls through to entering each part by hand.
    Invite,
    Relay,
    /// The relay's access key — who may connect at all.
    Access,
    /// Create a new room or join an existing one.
    Mode,
    EnterKey,
    /// Showing a freshly generated key, so it can be handed out.
    ShowKey,
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
    /// Set from an invite, or parsed from [`Setup::access_input`].
    pub access_key: Option<AccessKey>,
    pub invite_input: String,
    pub access_input: String,
    pub key_input: String,
    pub relay: String,
    pub username: String,
    pub passphrase: String,
    pub confirm: String,
    pub error: Option<String>,
    pub busy: bool,
    /// True when the relay and keys came from an invite, so the UI can say so
    /// rather than showing fields the person never filled in.
    pub from_invite: bool,
}

impl Setup {
    pub fn new(relay: String) -> Self {
        Self {
            step: Step::Invite,
            mode_cursor: 0,
            room_key: None,
            access_key: None,
            invite_input: String::new(),
            access_input: String::new(),
            key_input: String::new(),
            relay,
            username: String::new(),
            passphrase: String::new(),
            confirm: String::new(),
            error: None,
            busy: false,
            from_invite: false,
        }
    }

    /// The field the current step is editing, if it edits one.
    fn field_mut(&mut self) -> Option<&mut String> {
        match self.step {
            Step::Invite => Some(&mut self.invite_input),
            Step::Access => Some(&mut self.access_input),
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
    /// Kept so `/invite` can mint a one-paste invite for someone else.
    pub invite_display: Option<String>,
    /// True when `--no-vault` was passed: nothing is written to disk.
    pub ephemeral: bool,
    pub should_quit: bool,
    pub notify: Notify,
    /// Whether the terminal has focus. `None` until the terminal says, and
    /// forever in one that never reports focus — treated as unfocused, since
    /// an unwanted bell beats a missed mention.
    pub focused: Option<bool>,
    /// A notification waiting to be written to the terminal. Taken by the
    /// event loop, which owns stdout; the app only decides one is due.
    pub alert: Option<String>,
    /// Set while searching; the input box edits the query instead.
    pub search: Option<Search>,
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
            invite_display: None,
            ephemeral,
            should_quit: false,
            notify: Notify::Mentions,
            focused: None,
            alert: None,
            search: None,
        }
    }

    /// Indices into `entries` of every chat line matching the open search,
    /// oldest first. Matches on the text or the sender's name.
    pub fn search_matches(&self) -> Vec<usize> {
        let Some(search) = &self.search else {
            return Vec::new();
        };
        if search.query.is_empty() {
            return Vec::new();
        }
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| match entry {
                Entry::Msg { user, body, .. }
                    if find_ci(body, &search.query).is_some()
                        || find_ci(user, &search.query).is_some() =>
                {
                    Some(i)
                }
                _ => None,
            })
            .collect()
    }

    /// The entry the search is sitting on, if any.
    pub fn search_focus(&self) -> Option<usize> {
        let current = self.search.as_ref()?.current;
        let matches = self.search_matches();
        matches.len().checked_sub(current + 1).map(|i| matches[i])
    }

    fn on_key_search(&mut self, key: KeyEvent) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let total = self.search_matches().len();
        let Some(search) = self.search.as_mut() else {
            return Action::None;
        };
        match key.code {
            KeyCode::Esc => {
                self.search = None;
                self.scroll = 0;
            }
            // Older: Enter and Ctrl-F again, like most find bars.
            KeyCode::Up | KeyCode::Enter | KeyCode::PageUp => {
                search.current = (search.current + 1).min(total.saturating_sub(1));
            }
            KeyCode::Char('f') if ctrl => {
                search.current = (search.current + 1).min(total.saturating_sub(1));
            }
            KeyCode::Down | KeyCode::PageDown => {
                search.current = search.current.saturating_sub(1);
            }
            KeyCode::Backspace => {
                search.query.pop();
                search.current = 0;
            }
            KeyCode::Char('u') if ctrl => {
                search.query.clear();
                search.current = 0;
            }
            KeyCode::Char(c) if !ctrl => {
                search.query.push(c);
                search.current = 0;
            }
            _ => {}
        }
        Action::None
    }

    /// Adds a chat line to the transcript, working out how to mark it.
    fn push_msg(&mut self, user: String, body: String, ts: i64) {
        let own = user == self.username;
        let mention = !own && mentions(&body, &self.username);
        self.entries.push(Entry::Msg {
            user,
            body,
            ts,
            own,
            mention,
        });
    }

    /// Decides whether a message that just arrived live deserves a
    /// notification. Never for replayed history, never for your own lines.
    fn maybe_alert(&mut self, user: &str, body: &str) {
        if user == self.username || self.focused == Some(true) {
            return;
        }
        let mention = mentions(body, &self.username);
        let due = match self.notify {
            Notify::Off => false,
            Notify::Mentions => mention,
            Notify::All => true,
        };
        if due {
            // The body is left out on purpose: a notification lands in the
            // OS notification centre and on the lock screen, which is exactly
            // where an end-to-end encrypted message shouldn't be sitting.
            self.alert = Some(if mention {
                format!("{user} mentioned you")
            } else {
                format!("new message from {user}")
            });
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
                if !from_history {
                    self.maybe_alert(&user, &body);
                    if !self.ephemeral {
                        self.vault.push_line(StoredLine {
                            user: user.clone(),
                            body: body.clone(),
                            ts,
                        });
                    }
                }
                self.push_msg(user, body, ts);
            }
            // Presence is noise in a replayed backlog: "bmo joined" from two
            // hours ago tells you nothing about who is here now. Your own
            // arrival is noise too — the connection line above already said
            // it, and "you joined" reads oddly in your own transcript.
            Payload::Join { user, ts } if !from_history && user != self.username => {
                self.entries.push(Entry::Presence {
                    user,
                    joined: true,
                    ts,
                });
            }
            Payload::Leave { user, ts } if !from_history && user != self.username => {
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

    /// Takes the backlog the relay replays on every connect.
    ///
    /// That backlog overlaps whatever is already here — lines from the vault,
    /// and after a reconnect, lines already on screen — so only chat not seen
    /// before is shown. Those lines are also kept in the vault, which is what
    /// lets a device that first caught up from the relay keep that history
    /// once the relay has moved on.
    pub fn absorb_backlog(&mut self, payloads: Vec<Payload>) {
        let mut seen: HashSet<(String, i64, String)> = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Msg { user, body, ts, .. } => Some((user.clone(), *ts, body.clone())),
                _ => None,
            })
            .chain(
                self.vault
                    .history
                    .iter()
                    .map(|line| (line.user.clone(), line.ts, line.body.clone())),
            )
            .collect();
        // Presence is dropped from a replay anyway (see `absorb`), and a line
        // identical in sender, millisecond and text is the same line.
        let fresh: Vec<(String, String, i64)> = payloads
            .into_iter()
            .filter_map(|payload| match payload {
                Payload::Msg { user, body, ts } => Some((user, body, ts)),
                _ => None,
            })
            .filter(|(user, body, ts)| seen.insert((user.clone(), *ts, body.clone())))
            .collect();
        if fresh.is_empty() {
            return;
        }
        // Before the lines, not after: it is a heading for what follows.
        self.system(
            format!(
                "— {} earlier line{} from the relay —",
                fresh.len(),
                plural(fresh.len())
            ),
            Level::Info,
        );
        for (user, body, ts) in fresh {
            if !self.ephemeral {
                self.vault.push_line(StoredLine {
                    user: user.clone(),
                    body: body.clone(),
                    ts,
                });
            }
            self.push_msg(user, body, ts);
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
        // Before the lines, not after: it is a heading for what follows.
        self.system(
            format!("— {count} earlier line{} from your vault —", plural(count)),
            Level::Info,
        );
        for line in lines {
            self.push_msg(line.user, line.body, line.ts);
        }
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
                    // Going back discards the generated key; a fresh one is
                    // made if they choose to create again.
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
            Step::Invite => {
                let raw = setup.invite_input.trim().to_string();
                if raw.is_empty() {
                    // Nothing pasted: fall through to entering each part by
                    // hand, which is what the relay's operator does.
                    setup.step = Step::Relay;
                } else {
                    match Invite::decode(&raw) {
                        Ok(inv) => match normalize_relay(&inv.relay_url) {
                            Ok(url) => {
                                setup.relay = url;
                                setup.access_key = Some(inv.access_key);
                                setup.from_invite = true;
                                // An invite may carry a room or just relay
                                // access, so only skip ahead if it had a room.
                                match inv.room_key {
                                    Some(room) => {
                                        setup.room_key = Some(room);
                                        setup.step = Step::Username;
                                    }
                                    None => setup.step = Step::Mode,
                                }
                            }
                            Err(err) => {
                                setup.error =
                                    Some(format!("that invite's relay looks wrong: {err}"))
                            }
                        },
                        Err(err) => setup.error = Some(format!("{err:#}")),
                    }
                }
            }
            Step::Relay => match normalize_relay(&setup.relay) {
                Ok(url) => {
                    setup.relay = url;
                    setup.step = Step::Access;
                }
                Err(err) => setup.error = Some(err),
            },
            Step::Access => match AccessKey::parse_or_derive(&setup.access_input) {
                Ok(key) => {
                    setup.access_key = Some(key);
                    setup.step = Step::Mode;
                }
                Err(err) => setup.error = Some(format!("{err:#}")),
            },
            Step::Mode => {
                // Joining is first and default: most people arrive holding a
                // key somebody sent them. Creating a room is now a real option
                // — the relay carries any number of rooms — but it still means
                // nobody else is there until you hand the key out.
                if setup.mode_cursor == 0 {
                    setup.step = Step::EnterKey;
                } else {
                    setup.room_key = Some(RoomKey::generate());
                    setup.step = Step::ShowKey;
                }
            }
            Step::ShowKey => setup.step = Step::Username,
            Step::EnterKey => match RoomKey::parse_or_derive(&setup.key_input) {
                Ok(key) => {
                    setup.room_key = Some(key);
                    setup.step = Step::Username;
                }
                Err(err) => setup.error = Some(format!("{err:#}")),
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
        if self.search.is_some() {
            return self.on_key_search(key);
        }
        match key.code {
            KeyCode::Char('f') if ctrl => self.search = Some(Search::default()),
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
        let payload = Payload::Msg {
            user: self.username.clone(),
            body,
            ts: proto::now_ms(),
        };
        // The relay would drop it without a word, so say so here — and hand
        // the draft back rather than losing it.
        if !proto::fits(&payload) || trimmed.len() > rustchat_core::MAX_BODY_BYTES {
            self.cursor = raw.chars().count();
            self.input = raw;
            self.system(
                "Too long to send — shorten it or split it up. (Quotes, backslashes and \
                 line breaks count double.)",
                Level::Bad,
            );
            return Action::None;
        }
        Action::Send(payload)
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
                    "/invite one-paste invite · /key show the room key · /nick <name> rename \
                     · /who occupancy · /notify mentions|all|off · Ctrl-F search \
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
                        self.system(
                            "They also need this relay's access key — or use /invite, which \
                             bundles both with the relay address.",
                            Level::Info,
                        );
                    }
                    None => self.system("Room key unavailable.", Level::Bad),
                }
                Action::None
            }
            "invite" => {
                match self.invite_display.clone() {
                    Some(invite) => {
                        self.system(format!("Invite: {invite}"), Level::Warn);
                        self.system(
                            "One paste gets someone into this exact room. It contains both \
                             keys, so treat it like the room key itself.",
                            Level::Info,
                        );
                    }
                    None => self.system("Invite unavailable.", Level::Bad),
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
            "notify" => {
                if arg.is_empty() {
                    self.system(
                        format!(
                            "Notifications: {}. /notify mentions|all|off to change.",
                            self.notify.as_str()
                        ),
                        Level::Info,
                    );
                    return Action::None;
                }
                match Notify::parse(&arg) {
                    Some(mode) => {
                        self.notify = mode;
                        self.vault.notify = mode.as_str().to_string();
                        let detail = match mode {
                            Notify::Mentions => "a bell and a notification when someone says @you",
                            Notify::All => "a bell and a notification for every message",
                            Notify::Off => "no bells, no notifications",
                        };
                        self.system(
                            format!(
                                "Notifications: {} — {detail}, while this window isn't focused.",
                                mode.as_str()
                            ),
                            Level::Good,
                        );
                    }
                    None => self.system("Usage: /notify mentions|all|off", Level::Bad),
                }
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
        self.vault.access_key_b64.zeroize();
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

/// Where `needle` first occurs in `hay` ignoring case, as a range of *char*
/// indices. Char-wise rather than lowercasing whole strings, because
/// lowercasing can change byte lengths and the UI needs positions that line
/// up with the original text.
pub fn find_ci(hay: &str, needle: &str) -> Option<std::ops::Range<usize>> {
    let fold = |c: char| c.to_lowercase().next().unwrap_or(c);
    let hay: Vec<char> = hay.chars().map(fold).collect();
    let needle: Vec<char> = needle.chars().map(fold).collect();
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .find(|&i| hay[i..i + needle.len()] == needle[..])
        .map(|i| i..i + needle.len())
}

/// Whether `body` addresses `name` as `@name`, ignoring case. The mention
/// must end at a word boundary, so `@bmo` doesn't fire for `@bmobile`.
pub fn mentions(body: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let body = body.to_lowercase();
    let needle = format!("@{}", name.to_lowercase());
    body.match_indices(&needle).any(|(at, _)| {
        body[at + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '-'))
    })
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
            Screen::Setup(Box::new(Setup::new("x".into()))),
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
            Screen::Setup(Box::new(Setup::new("x".into()))),
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
            Screen::Setup(Box::new(Setup::new("x".into()))),
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

    #[test]
    fn your_own_presence_is_not_shown_to_you() {
        let mut app = app(); // username is "bmo"
        app.absorb(
            Payload::Join {
                user: "bmo".into(),
                ts: 0,
            },
            false,
        );
        app.absorb(
            Payload::Leave {
                user: "bmo".into(),
                ts: 0,
            },
            false,
        );
        assert!(app.entries.is_empty(), "you already know you joined");
        app.absorb(
            Payload::Join {
                user: "sam".into(),
                ts: 0,
            },
            false,
        );
        assert_eq!(app.entries.len(), 1, "other people's presence still shows");
    }

    fn said(user: &str, body: &str, ts: i64) -> Payload {
        Payload::Msg {
            user: user.into(),
            body: body.into(),
            ts,
        }
    }

    #[test]
    fn a_reconnect_does_not_replay_what_is_already_on_screen() {
        let mut app = app();
        app.absorb_backlog(vec![said("sam", "a", 1), said("sam", "b", 2)]);
        let before = app.entries.len();
        // The relay replays its whole buffer on every connect.
        app.absorb_backlog(vec![said("sam", "a", 1), said("sam", "b", 2)]);
        assert_eq!(app.entries.len(), before, "nothing new, so nothing shown");
        app.absorb_backlog(vec![
            said("sam", "a", 1),
            said("sam", "b", 2),
            said("sam", "c", 3),
        ]);
        let bodies: Vec<&str> = app
            .entries
            .iter()
            .filter_map(|e| match e {
                Entry::Msg { body, .. } => Some(body.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(bodies, ["a", "b", "c"]);
    }

    #[test]
    fn the_backlog_skips_lines_the_vault_already_has() {
        let mut app = app();
        app.vault.push_line(StoredLine {
            user: "sam".into(),
            body: "old".into(),
            ts: 1,
        });
        app.load_history();
        app.absorb_backlog(vec![said("sam", "old", 1), said("sam", "new", 2)]);
        assert!(matches!(
            app.entries.iter().rev().nth(1),
            Some(Entry::System { body, .. }) if body.contains("1 earlier line")
        ));
    }

    #[test]
    fn a_new_device_keeps_what_it_caught_up_on() {
        let mut app = app();
        app.ephemeral = false;
        app.absorb_backlog(vec![said("sam", "from before", 1)]);
        assert_eq!(app.vault.history.len(), 1);
        // And a second replay doesn't save it twice.
        app.absorb_backlog(vec![said("sam", "from before", 1)]);
        assert_eq!(app.vault.history.len(), 1);
    }

    #[test]
    fn mentions_need_the_at_and_a_word_boundary() {
        assert!(mentions("hey @bmo look", "bmo"));
        assert!(mentions("@BMO!", "bmo"), "case doesn't matter");
        assert!(mentions("ping @bmo", "bmo"), "end of text counts");
        assert!(
            !mentions("hey bmo", "bmo"),
            "the @ is what makes it a mention"
        );
        assert!(!mentions("@bmobile", "bmo"), "not a prefix match");
        assert!(mentions("@bmobile and @bmo", "bmo"));
        assert!(!mentions("@", ""));
    }

    #[test]
    fn a_live_mention_raises_an_alert_without_the_text() {
        let mut app = app();
        app.absorb(said("sam", "@bmo the secret plan", 1), false);
        let alert = app.alert.take().expect("a mention should alert");
        assert!(alert.contains("sam"));
        assert!(
            !alert.contains("secret"),
            "message text must stay out of the OS"
        );
        assert!(matches!(
            app.entries.last(),
            Some(Entry::Msg { mention: true, .. })
        ));
    }

    #[test]
    fn alerts_respect_focus_mode_and_history() {
        let mut app = app();
        app.absorb(said("sam", "no mention here", 1), false);
        assert!(app.alert.is_none(), "mentions mode ignores ordinary lines");

        app.absorb(said("sam", "@bmo from before", 2), true);
        assert!(app.alert.is_none(), "replayed history never alerts");

        app.absorb(said("bmo", "@bmo talking to myself", 3), false);
        assert!(app.alert.is_none(), "your own lines never alert");

        app.focused = Some(true);
        app.absorb(said("sam", "@bmo while you're looking", 4), false);
        assert!(app.alert.is_none(), "no need while the window has focus");

        app.focused = Some(false);
        app.notify = Notify::All;
        app.absorb(said("sam", "anything", 5), false);
        assert!(app.alert.take().is_some());

        app.notify = Notify::Off;
        app.absorb(said("sam", "@bmo", 6), false);
        assert!(app.alert.is_none());
    }

    #[test]
    fn notify_is_set_by_command_and_saved() {
        let mut app = app();
        assert_eq!(app.run_command("notify all"), Action::None);
        assert_eq!(app.notify, Notify::All);
        assert_eq!(app.vault.notify, "all");
        app.run_command("notify nonsense");
        assert_eq!(app.notify, Notify::All, "a typo changes nothing");
    }

    fn type_keys(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn case_insensitive_find_reports_char_positions() {
        assert_eq!(find_ci("Hello World", "world"), Some(6..11));
        assert_eq!(find_ci("héllo", "LLO"), Some(2..5), "chars, not bytes");
        assert_eq!(find_ci("abc", ""), None);
        assert_eq!(find_ci("ab", "abc"), None);
    }

    #[test]
    fn search_walks_from_newest_to_oldest() {
        let mut app = app();
        for (i, body) in ["deploy failed", "lunch?", "Deploy fixed", "ok"]
            .iter()
            .enumerate()
        {
            app.absorb(said("sam", body, i as i64), false);
        }
        app.on_key(ctrl('f'));
        type_keys(&mut app, "deploy");
        assert_eq!(app.search_matches().len(), 2);
        assert_eq!(app.search_focus(), Some(2), "starts on the newest match");
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.search_focus(), Some(0));
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.search_focus(), Some(0), "stops at the oldest");
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.search_focus(), Some(2));
    }

    #[test]
    fn search_typing_edits_the_query_not_the_message() {
        let mut app = app();
        app.input = "half a message".into();
        app.on_key(ctrl('f'));
        type_keys(&mut app, "x");
        assert_eq!(app.input, "half a message", "the draft is left alone");
        assert_eq!(
            app.on_key(key(KeyCode::Enter)),
            Action::None,
            "Enter doesn't send"
        );
        app.on_key(key(KeyCode::Esc));
        assert!(app.search.is_none());
        assert_eq!(app.input, "half a message");
    }

    #[test]
    fn search_matches_names_too() {
        let mut app = app();
        app.absorb(said("sam", "hi", 1), false);
        app.absorb(said("alex", "hi", 2), false);
        app.on_key(ctrl('f'));
        type_keys(&mut app, "SAM");
        assert_eq!(app.search_matches(), vec![0]);
    }

    #[test]
    fn an_over_long_message_keeps_the_draft() {
        let mut app = app();
        let draft = "\"".repeat(rustchat_core::MAX_BODY_BYTES);
        app.input = draft.clone();
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None, "not sent");
        assert_eq!(app.input, draft, "and not lost");
        assert!(matches!(
            app.entries.last(),
            Some(Entry::System {
                level: Level::Bad,
                ..
            })
        ));
    }

    #[test]
    fn the_vault_history_marker_precedes_its_lines() {
        let mut app = app();
        app.vault.push_line(StoredLine {
            user: "sam".into(),
            body: "older".into(),
            ts: 1,
        });
        app.load_history();
        assert!(
            matches!(app.entries.first(), Some(Entry::System { .. })),
            "the marker should head the lines it describes, not trail them"
        );
        assert!(matches!(app.entries.last(), Some(Entry::Msg { .. })));
    }
}
