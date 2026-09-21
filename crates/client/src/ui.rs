//! Rendering. Reads [`App`] and draws; never mutates state.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};

use crate::app::{App, Entry, Level, Screen, Setup, Status, Step, Unlock};

// A small, deliberate palette. The terminal's own background is left alone so
// rustchat sits inside whatever theme someone already likes.
const ACCENT: Color = Color::Rgb(126, 231, 209);
const OWN: Color = Color::Rgb(244, 196, 140);
const DIM: Color = Color::Rgb(122, 132, 148);
const BAD: Color = Color::Rgb(231, 111, 81);
const GOOD: Color = Color::Rgb(146, 209, 125);
const WARN: Color = Color::Rgb(240, 200, 110);

/// Colors usernames are drawn in, chosen by hashing the name so that the same
/// person keeps the same color for everyone in the room.
const NAME_COLORS: [Color; 6] = [
    Color::Rgb(129, 184, 239),
    Color::Rgb(197, 154, 232),
    Color::Rgb(126, 231, 209),
    Color::Rgb(232, 165, 196),
    Color::Rgb(159, 214, 138),
    Color::Rgb(238, 186, 128),
];

/// Left margin for message bodies, in columns.
const BODY_INDENT: usize = 3;

pub fn draw(frame: &mut Frame, app: &App) {
    match &app.screen {
        Screen::Setup(setup) => draw_setup(frame, setup),
        Screen::Unlock(unlock) => draw_unlock(frame, unlock, app),
        Screen::Chat => draw_chat(frame, app),
    }
}

// ---------------------------------------------------------------- chat

fn draw_chat(frame: &mut Frame, app: &App) {
    let [header, body, input] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .areas(frame.area());

    draw_header(frame, header, app);

    // The transcript is wrapped to the exact body width here rather than left
    // to Paragraph's own wrapping, because scrolling needs to be in units of
    // *rendered* lines for the view to move predictably.
    let width = body.width.saturating_sub(1) as usize;
    let lines = build_transcript(app, width.max(8));
    let height = body.height as usize;
    let max_scroll = lines.len().saturating_sub(height);
    let scroll = (app.scroll as usize).min(max_scroll);
    let start = lines.len().saturating_sub(height + scroll);
    let end = lines.len().saturating_sub(scroll);
    let window: Vec<Line> = lines[start..end].to_vec();

    frame.render_widget(Paragraph::new(window), body);
    draw_input(frame, input, app, scroll > 0);
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let (dot, label, color) = match &app.status {
        Status::Online => ("●", "online".to_string(), GOOD),
        Status::Connecting => ("◐", "connecting".to_string(), WARN),
        Status::Retrying(_) => ("○", "reconnecting".to_string(), BAD),
        Status::Offline => ("○", "offline".to_string(), DIM),
    };

    let left = Line::from(vec![
        Span::styled(
            " rustchat ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(host_of(&app.relay), Style::default().fg(DIM)),
    ]);
    let right = Line::from(vec![
        Span::styled(format!("{dot} "), Style::default().fg(color)),
        Span::styled(label, Style::default().fg(color)),
        Span::styled(
            format!(" · {} here ", app.occupants),
            Style::default().fg(DIM),
        ),
    ]);

    frame.render_widget(Paragraph::new(left), area);
    frame.render_widget(Paragraph::new(right).alignment(Alignment::Right), area);
}

fn draw_input(frame: &mut Frame, area: Rect, app: &App, scrolled: bool) {
    let title = if scrolled {
        " scrolled up — End or Esc to jump back "
    } else if app.input.starts_with('/') {
        " command "
    } else {
        " message "
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if scrolled { WARN } else { DIM }))
        .title_top(Span::styled(title, Style::default().fg(DIM)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Scroll the input horizontally so the caret stays visible on long lines.
    let width = inner.width as usize;
    let caret = display_width(&app.input, app.cursor);
    let offset = caret.saturating_sub(width.saturating_sub(1));
    let visible: String = app
        .input
        .chars()
        .skip(char_at_width(&app.input, offset))
        .collect();

    frame.render_widget(Paragraph::new(visible), inner);
    frame.set_cursor_position((
        inner.x + (caret - offset).min(width.saturating_sub(1)) as u16,
        inner.y,
    ));
}

/// Renders the transcript into exactly-wrapped lines, oldest first.
fn build_transcript(app: &App, width: usize) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    // Consecutive messages from one person share a single name header, which
    // keeps a back-and-forth readable without repeating the name every line.
    let mut last_speaker: Option<String> = None;

    for entry in &app.entries {
        match entry {
            Entry::Msg {
                user,
                body,
                ts,
                own,
            } => {
                if last_speaker.as_deref() != Some(user.as_str()) {
                    if !out.is_empty() {
                        out.push(Line::default());
                    }
                    let color = if *own { OWN } else { name_color(user) };
                    let mut spans = vec![Span::styled(
                        user.clone(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )];
                    if *own {
                        spans.push(Span::styled(" (you)", Style::default().fg(DIM)));
                    }
                    spans.push(Span::styled(
                        format!("  {}", clock(*ts)),
                        Style::default().fg(DIM),
                    ));
                    out.push(Line::from(spans));
                    last_speaker = Some(user.clone());
                }
                for chunk in wrap(body, width.saturating_sub(BODY_INDENT)) {
                    out.push(Line::from(vec![
                        Span::raw(" ".repeat(BODY_INDENT)),
                        Span::raw(chunk),
                    ]));
                }
            }
            Entry::Presence { user, joined, ts } => {
                last_speaker = None;
                let (arrow, verb) = if *joined {
                    ("→", "joined")
                } else {
                    ("←", "left")
                };
                out.push(Line::from(vec![
                    Span::styled(format!(" {arrow} "), Style::default().fg(DIM)),
                    Span::styled(user.clone(), Style::default().fg(name_color(user))),
                    Span::styled(format!(" {verb}  {}", clock(*ts)), Style::default().fg(DIM)),
                ]));
            }
            Entry::System { body, level } => {
                last_speaker = None;
                let color = match level {
                    Level::Info => DIM,
                    Level::Good => GOOD,
                    Level::Warn => WARN,
                    Level::Bad => BAD,
                };
                for (i, chunk) in wrap(body, width.saturating_sub(3)).into_iter().enumerate() {
                    let prefix = if i == 0 { " · " } else { "   " };
                    out.push(Line::from(vec![
                        Span::styled(prefix, Style::default().fg(color)),
                        Span::styled(
                            chunk,
                            Style::default().fg(color).add_modifier(Modifier::ITALIC),
                        ),
                    ]));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------- unlock

fn draw_unlock(frame: &mut Frame, unlock: &Unlock, app: &App) {
    let area = centered(frame.area(), 54, 11);
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title_top(Span::styled(
            " rustchat ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![
        Line::from(Span::styled(
            "Unlock your vault",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("{} · {}", host_of(&app.relay), short_path(&app.vault_path)),
            Style::default().fg(DIM),
        )),
        Line::default(),
    ];

    if unlock.busy {
        lines.push(Line::from(Span::styled(
            "Deriving your key…",
            Style::default().fg(WARN),
        )));
    } else {
        lines.push(Line::from(vec![
            Span::styled("passphrase  ", Style::default().fg(DIM)),
            Span::raw("•".repeat(unlock.passphrase.chars().count().min(32))),
            Span::styled("▌", Style::default().fg(ACCENT)),
        ]));
    }

    lines.push(Line::default());
    if let Some(err) = &unlock.error {
        for chunk in wrap(err, inner.width as usize) {
            lines.push(Line::from(Span::styled(chunk, Style::default().fg(BAD))));
        }
        if unlock.attempts >= 3 {
            lines.push(Line::from(Span::styled(
                "Forgotten it? `rustchat reset` starts over with the room key.",
                Style::default().fg(DIM),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "This is your own passphrase, not the room key.",
            Style::default().fg(DIM),
        )));
    }
    lines.push(Line::from(Span::styled(
        "Enter to unlock · Esc to quit",
        Style::default().fg(DIM),
    )));

    frame.render_widget(Paragraph::new(lines), inner);
}

// ---------------------------------------------------------------- setup

fn draw_setup(frame: &mut Frame, setup: &Setup) {
    let area = centered(frame.area(), 66, 17);
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title_top(Span::styled(
            " rustchat · first run ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line<'static>> = Vec::new();
    let heading = |text: &str| {
        Line::from(Span::styled(
            text.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ))
    };
    let note = |text: &str| Line::from(Span::styled(text.to_string(), Style::default().fg(DIM)));

    match setup.step {
        Step::Invite => {
            lines.push(heading("Paste your invite"));
            lines.push(Line::default());
            lines.push(field(&setup.invite_input, false, inner.width));
            // Only the tail of a long value fits on screen, so a copy that
            // lost its opening characters looks perfectly fine. The count is
            // the one thing that makes a clipped paste visible before Enter.
            let pasted = setup.invite_input.trim().chars().count();
            if pasted > 0 {
                lines.push(Line::from(Span::styled(
                    format!("  {pasted} characters"),
                    Style::default().fg(DIM),
                )));
            }
            lines.push(Line::default());
            lines.push(note("One value carrying the relay, its access key and a"));
            lines.push(note(
                "room key. Whoever runs the relay can make you one with",
            ));
            lines.push(note("`rustchat invite`, or /invite from inside a room."));
            lines.push(Line::default());
            lines.push(note(
                "No invite? Leave this blank and press Enter to fill in",
            ));
            lines.push(note("each part yourself."));
        }
        Step::Access => {
            lines.push(heading("Relay access key"));
            lines.push(Line::default());
            lines.push(field(&setup.access_input, false, inner.width));
            lines.push(Line::default());
            lines.push(note(
                "Starts with `rca1`. It decides who may use the relay at",
            ));
            lines.push(note("all — it is not a room key and cannot read any room."));
            lines.push(Line::default());
            lines.push(note(
                "Running the relay yourself? `rustchat relaykey` makes one.",
            ));
        }
        Step::Mode => {
            lines.push(heading("Join a room, or start one"));
            lines.push(Line::default());
            for (i, (label, detail)) in [
                ("Join a room", "paste the key someone sent you"),
                ("Create a new room", "generates a brand-new key"),
            ]
            .iter()
            .enumerate()
            {
                let selected = i == setup.mode_cursor;
                let marker = if selected { "▸ " } else { "  " };
                let style = if selected {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                lines.push(Line::from(vec![
                    Span::styled(marker, style),
                    Span::styled((*label).to_string(), style),
                    Span::styled(format!("  — {detail}"), Style::default().fg(DIM)),
                ]));
            }
            lines.push(Line::default());
            if setup.mode_cursor == 1 {
                lines.push(note("Makes a fresh, empty room on this relay. Nobody else"));
                lines.push(note("is in it until you send them the key or an invite."));
            } else {
                lines.push(note(
                    "The key looks like rc1-XXXXXXXX-… — whoever is already",
                ));
                lines.push(note("in the room will have sent you one."));
            }
            lines.push(Line::default());
            lines.push(note("↑↓ to choose · Enter to continue"));
        }
        Step::ShowKey => {
            lines.push(heading("Your room key"));
            lines.push(Line::default());
            let key = setup
                .room_key
                .as_ref()
                .map(|k| k.encode())
                .unwrap_or_default();
            for chunk in wrap(&key, inner.width.saturating_sub(2) as usize) {
                lines.push(Line::from(Span::styled(
                    chunk,
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )));
            }
            lines.push(Line::default());
            lines.push(note("Anyone with this key can read the room. Send it over"));
            lines.push(note("something you already trust — not the room itself."));
            lines.push(Line::default());
            lines.push(note(
                "You can get it back later with /key, or /invite for a",
            ));
            lines.push(note("single value carrying the relay details too."));
            lines.push(Line::default());
            lines.push(note("Enter to continue · Backspace to go back."));
        }
        Step::EnterKey => {
            lines.push(heading("Paste the room key"));
            lines.push(Line::default());
            lines.push(field(&setup.key_input, false, inner.width));
            lines.push(Line::default());
            lines.push(note(
                "Starts with `rc1`. Dashes, spaces and case don't matter.",
            ));
        }
        Step::Relay => {
            lines.push(heading("Which relay?"));
            lines.push(Line::default());
            lines.push(field(&setup.relay, false, inner.width));
            lines.push(Line::default());
            lines.push(note("The relay passes messages along. It can't read them,"));
            lines.push(note(
                "so it needn't be one you trust. One relay carries any",
            ));
            lines.push(note("number of rooms."));
        }
        Step::Username => {
            lines.push(heading("Pick a username"));
            lines.push(Line::default());
            lines.push(field(&setup.username, false, inner.width));
            lines.push(Line::default());
            lines.push(note("Nobody verifies this — the room key is the only"));
            lines.push(note("credential. Two people can pick the same name."));
        }
        Step::Passphrase => {
            lines.push(heading("Set a passphrase for this machine"));
            lines.push(Line::default());
            lines.push(field(&setup.passphrase, true, inner.width));
            lines.push(Line::default());
            lines.push(note(
                "Yours alone. It encrypts the room key and your history",
            ));
            lines.push(note("on this disk, and never leaves the machine."));
            lines.push(Line::default());
            lines.push(note("At least 8 characters."));
        }
        Step::Confirm => {
            lines.push(heading("Type it once more"));
            lines.push(Line::default());
            lines.push(field(&setup.confirm, true, inner.width));
            lines.push(Line::default());
            if setup.busy {
                lines.push(Line::from(Span::styled(
                    "Sealing your vault…",
                    Style::default().fg(WARN),
                )));
            } else {
                lines.push(note("There's no recovery if you forget it — but you can"));
                lines.push(note("always start over with the room key."));
            }
        }
    }

    if let Some(err) = &setup.error {
        lines.push(Line::default());
        // Wrapped, not a single line: an error long enough to be genuinely
        // useful is longer than this card is wide, and an unwrapped one gets
        // silently cut off at the border with the explanation lost.
        for chunk in wrap(err, inner.width as usize) {
            lines.push(Line::from(Span::styled(chunk, Style::default().fg(BAD))));
        }
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

/// A single-line input row, optionally masked.
fn field(value: &str, secret: bool, width: u16) -> Line<'static> {
    let shown = if secret {
        "•".repeat(value.chars().count().min(40))
    } else {
        let budget = width.saturating_sub(4) as usize;
        let count = value.chars().count();
        if count > budget {
            value.chars().skip(count - budget).collect()
        } else {
            value.to_string()
        }
    };
    Line::from(vec![
        Span::styled("› ", Style::default().fg(ACCENT)),
        Span::raw(shown),
        Span::styled("▌", Style::default().fg(ACCENT)),
    ])
}

// ---------------------------------------------------------------- helpers

/// A centered rect of at most `w`×`h`, shrinking to fit a small terminal.
fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// Greedy word wrap that honours existing newlines and splits words too long
/// to fit on any line.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for paragraph in text.split('\n') {
        let emitted_before = out.len();
        let mut line = String::new();
        let mut line_width = 0usize;
        for word in paragraph.split(' ') {
            let w = str_width(word);
            if w > width {
                // A single unbreakable run (a URL, a pasted key) — hard-split
                // it rather than letting it overflow the pane.
                if !line.is_empty() {
                    out.push(std::mem::take(&mut line));
                    line_width = 0;
                }
                for piece in hard_split(word, width) {
                    out.push(piece);
                }
                continue;
            }
            let needed = if line.is_empty() { w } else { w + 1 };
            if line_width + needed > width {
                out.push(std::mem::take(&mut line));
                line_width = 0;
            }
            if !line.is_empty() {
                line.push(' ');
                line_width += 1;
            }
            line.push_str(word);
            line_width += w;
        }
        // Push the partial line, but not an empty remainder left behind by a
        // hard-split word — unless the paragraph produced nothing at all, in
        // which case it really was a blank line and should stay one.
        if !line.is_empty() || out.len() == emitted_before {
            out.push(line);
        }
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Splits a run with no spaces into `width`-wide pieces.
fn hard_split(word: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;
    for ch in word.chars() {
        let w = char_width(ch);
        if current_width + w > width && !current.is_empty() {
            out.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push(ch);
        current_width += w;
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn str_width(s: &str) -> usize {
    use unicode_width::UnicodeWidthStr;
    s.width()
}

fn char_width(c: char) -> usize {
    use unicode_width::UnicodeWidthChar;
    c.width().unwrap_or(0)
}

/// Display columns taken by the first `chars` characters of `s`.
fn display_width(s: &str, chars: usize) -> usize {
    s.chars().take(chars).map(char_width).sum()
}

/// Inverse of [`display_width`]: how many characters fit in `cols` columns.
fn char_at_width(s: &str, cols: usize) -> usize {
    let mut used = 0;
    for (i, ch) in s.chars().enumerate() {
        if used >= cols {
            return i;
        }
        used += char_width(ch);
    }
    s.chars().count()
}

/// Stable per-name color, so the same person looks the same to everybody.
fn name_color(name: &str) -> Color {
    let hash = name
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    NAME_COLORS[(hash as usize) % NAME_COLORS.len()]
}

/// Formats a Unix-millisecond timestamp as local `HH:MM`.
fn clock(ts: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(ts).single() {
        Some(dt) => dt.format("%H:%M").to_string(),
        // A sender can put anything in a timestamp, so an unrepresentable one
        // is shown as unknown rather than allowed to panic the renderer.
        None => "--:--".to_string(),
    }
}

/// The host part of a relay URL, for the header.
fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

/// Abbreviates the home directory in a path for display.
fn short_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    match dirs::home_dir() {
        Some(home) => text
            .strip_prefix(&home.display().to_string())
            .map(|rest| format!("~{rest}"))
            .unwrap_or(text),
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_on_word_boundaries() {
        assert_eq!(
            wrap("the quick brown fox", 9),
            vec!["the quick", "brown fox"]
        );
    }

    #[test]
    fn preserves_explicit_newlines() {
        assert_eq!(wrap("a\nb", 20), vec!["a", "b"]);
    }

    #[test]
    fn splits_runs_that_cannot_fit() {
        let wrapped = wrap("aaaaaaaaaa", 4);
        assert_eq!(wrapped, vec!["aaaa", "aaaa", "aa"]);
    }

    #[test]
    fn wrapping_never_exceeds_the_width() {
        let text = "short words and one entirely_unreasonable_token_of_great_length here";
        for width in 3..40 {
            for line in wrap(text, width) {
                assert!(
                    str_width(&line) <= width,
                    "width {width} produced an over-long line: {line:?}"
                );
            }
        }
    }

    #[test]
    fn blank_lines_are_preserved() {
        assert_eq!(wrap("a\n\nb", 20), vec!["a", "", "b"]);
    }

    #[test]
    fn a_split_word_leaves_no_trailing_blank() {
        assert_eq!(wrap("hi aaaaaaaaaa", 4), vec!["hi", "aaaa", "aaaa", "aa"]);
        assert_eq!(wrap("aaaaaaaa", 4), vec!["aaaa", "aaaa"]);
    }

    #[test]
    fn handles_empty_input() {
        assert_eq!(wrap("", 10), vec![String::new()]);
        assert_eq!(wrap("x", 0), vec!["x".to_string()]);
    }

    #[test]
    fn wide_characters_count_double() {
        for line in wrap("日本語のテキストです", 6) {
            assert!(str_width(&line) <= 6, "{line:?}");
        }
    }

    #[test]
    fn name_colors_are_stable() {
        assert_eq!(name_color("bmo"), name_color("bmo"));
    }

    #[test]
    fn extracts_hosts() {
        assert_eq!(host_of("wss://relay.bmo.guru/ws"), "relay.bmo.guru");
        assert_eq!(host_of("ws://localhost:7777/ws"), "localhost:7777");
        assert_eq!(host_of("relay.bmo.guru"), "relay.bmo.guru");
    }

    #[test]
    fn bad_timestamps_do_not_panic() {
        assert_eq!(clock(i64::MAX), "--:--");
        assert_eq!(clock(i64::MIN), "--:--");
    }

    #[test]
    fn caret_math_is_consistent() {
        let s = "héllo wörld";
        let chars = s.chars().count();
        assert_eq!(char_at_width(s, display_width(s, chars)), chars);
        assert_eq!(char_at_width(s, 0), 0);
    }

    #[test]
    fn centering_survives_a_tiny_terminal() {
        let tiny = Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 4,
        };
        let r = centered(tiny, 66, 17);
        assert!(r.width <= tiny.width && r.height <= tiny.height);
    }
}
