//! Putting a value on the system clipboard, for `/invite copy` and friends.
//!
//! Selecting text with the mouse is unreliable here: rustchat captures the
//! mouse so hovering can unscramble messages, and a long invite wraps across
//! several lines of the transcript anyway. So the value is handed to the
//! clipboard directly, two ways at once, because neither reaches everyone:
//!
//! * The OS clipboard tool, where there is one we know: `clip.exe` under WSL,
//!   `pbcopy` on macOS. These report success, so we can say whether it
//!   worked.
//! * An OSC 52 escape, which asks the terminal itself to set the clipboard.
//!   Windows Terminal, iTerm2 (once allowed), kitty, WezTerm, Alacritty and
//!   foot honour it, and it works over SSH, where no local tool can help. A
//!   terminal never says whether it obeyed, so on its own it is a best guess.

use std::io::Write;
use std::process::{Command, Stdio};

/// How the copy went, as far as can be told.
#[derive(Debug, PartialEq, Eq)]
pub enum Copied {
    /// A clipboard tool took it.
    Confirmed,
    /// Only the terminal was asked; it may or may not have obeyed.
    Requested,
}

/// Copies `text` to the clipboard. Only ever called with keys and invites,
/// which are plain ASCII, but anything is safe: OSC 52 carries it as base64.
pub fn copy(text: &str) -> Copied {
    let mut out = std::io::stdout();
    let _ = out.write_all(osc52(text, std::env::var_os("TMUX").is_some()).as_bytes());
    let _ = out.flush();
    if native(text) {
        Copied::Confirmed
    } else {
        Copied::Requested
    }
}

/// The OSC 52 escape that sets the clipboard to `text`.
///
/// Under tmux it is wrapped so it reaches the outer terminal, which needs
/// `set -g allow-passthrough on` — or tmux's own `set-clipboard on`, which
/// handles the unwrapped form.
fn osc52(text: &str, in_tmux: bool) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let osc = format!("\x1b]52;c;{encoded}\x07");
    if in_tmux {
        format!("\x1bPtmux;{}\x1b\\", osc.replace('\x1b', "\x1b\x1b"))
    } else {
        osc
    }
}

/// Hands `text` to the platform's clipboard tool, if there is one we know.
fn native(text: &str) -> bool {
    let program = if crate::notify::running_under_wsl() {
        "clip.exe"
    } else if cfg!(target_os = "macos") {
        "pbcopy"
    } else {
        return false;
    };
    let Ok(mut child) = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let wrote = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
    // Dropping stdin above closes it, which is what tells the tool to finish.
    child.wait().is_ok_and(|status| status.success()) && wrote
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_carries_the_text_as_base64() {
        assert_eq!(osc52("hi", false), "\x1b]52;c;aGk=\x07");
    }

    #[test]
    fn under_tmux_it_is_wrapped_for_passthrough() {
        let wrapped = osc52("hi", true);
        assert!(wrapped.starts_with("\x1bPtmux;\x1b\x1b]52;c;aGk="));
        assert!(wrapped.ends_with("\x1b\\"));
    }
}
