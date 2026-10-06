//! Getting someone's attention when they are looking elsewhere.
//!
//! Two independent mechanisms, because no single one reaches everybody:
//!
//! * The terminal bell and an OSC 9 escape. iTerm2, WezTerm, Ghostty, kitty
//!   and foot turn that into a desktop notification; anything else ignores
//!   the escape and still rings.
//! * A real OS notification, for terminals that ignore the escape. Windows
//!   Terminal is the case that matters here: it implements ConEmu's numbered
//!   OSC 9 subcommands rather than iTerm2's free-text form, so under WSL the
//!   escape does nothing at all and the bell is the only signal.
//!
//! Message bodies are deliberately never included. A notification lands in
//! the OS notification centre and on the lock screen, which is the last place
//! an end-to-end encrypted message should end up.

use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Shortest gap between desktop notifications.
///
/// With `/notify all` in a busy room every message would otherwise spawn a
/// process. Dropping the extras is fine: the notification says only that
/// something arrived, and the transcript has the rest.
const MIN_GAP: Duration = Duration::from_secs(4);

/// Longest notification text passed on. Long enough for "someone mentioned
/// you", short enough that a hostile username can't paper the screen.
const MAX_TEXT: usize = 120;

/// Windows Terminal's identity, so the toast is attributed to the terminal
/// rather than to whatever happened to launch it.
const WINDOWS_TERMINAL_APP_ID: &str = "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App";

/// Windows PowerShell's identity. Present on every Windows install, so it is
/// the fallback when the terminal in use has no identity of its own. A toast
/// needs *some* registered application to come from.
const POWERSHELL_APP_ID: &str =
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

/// Rings the terminal bell, asks the terminal for a notification, and raises
/// an OS notification where the terminal can't.
pub fn alert(text: &str) {
    let text = sanitize(text);
    ring_terminal(&text);
    if desktop_notifications_available() && throttle_allows(Instant::now()) {
        raise_desktop_notification(&text);
    }
}

/// Strips anything that would corrupt an escape sequence or run away with the
/// display, and caps the length.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT)
        .collect()
}

/// The bell plus an OSC 9 notification request.
fn ring_terminal(text: &str) {
    let sequence = terminal_sequence(text, std::env::var_os("TMUX").is_some());
    let mut out = std::io::stdout();
    let _ = out.write_all(sequence.as_bytes());
    let _ = out.flush();
}

/// Builds the bell-and-escape sequence.
///
/// Under tmux the escape has to be wrapped to reach the outer terminal, with
/// inner escapes doubled, and tmux needs `set -g allow-passthrough on` before
/// it will forward it at all.
fn terminal_sequence(text: &str, in_tmux: bool) -> String {
    let osc = format!("\x1b]9;rustchat: {text}\x07");
    let osc = if in_tmux {
        format!("\x1bPtmux;{}\x1b\\", osc.replace('\x1b', "\x1b\x1b"))
    } else {
        osc
    };
    format!("\x07{osc}")
}

/// At most one desktop notification per [`MIN_GAP`].
fn throttle_allows(now: Instant) -> bool {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    // A poisoned lock here means a previous caller panicked mid-check, which
    // is no reason to stop notifying.
    let mut last = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match *last {
        Some(previous) if now.duration_since(previous) < MIN_GAP => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

/// Whether this machine has a way to raise an OS notification.
fn desktop_notifications_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(running_under_wsl)
}

/// Whether we are running inside WSL.
fn running_under_wsl() -> bool {
    if std::env::var_os("WSL_INTEROP").is_some() || std::env::var_os("WSL_DISTRO_NAME").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/version")
        .map(|version| kernel_is_wsl(&version))
        .unwrap_or(false)
}

/// Whether a `/proc/version` string describes a WSL kernel.
fn kernel_is_wsl(proc_version: &str) -> bool {
    proc_version.to_ascii_lowercase().contains("microsoft")
}

/// Which application the toast should appear to come from.
fn toast_app_id() -> &'static str {
    if std::env::var_os("WT_SESSION").is_some() {
        WINDOWS_TERMINAL_APP_ID
    } else {
        POWERSHELL_APP_ID
    }
}

/// The PowerShell that builds and shows the toast.
///
/// It takes its text from the environment rather than from arguments, so no
/// amount of quoting in a username or a room name can turn into PowerShell
/// syntax. The whole script is then passed base64-encoded, which sidesteps
/// command-line quoting a second time.
const TOAST_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] > $null
$title = [System.Security.SecurityElement]::Escape($env:RUSTCHAT_TOAST_TITLE)
$body  = [System.Security.SecurityElement]::Escape($env:RUSTCHAT_TOAST_BODY)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$title</text><text>$body</text></binding></visual></toast>")
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:RUSTCHAT_TOAST_APPID).Show($toast)
"#;

/// Encodes a script for `powershell.exe -EncodedCommand`, which expects
/// base64 of UTF-16LE.
fn encode_powershell_command(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(utf16)
}

/// Fires the toast without waiting for it.
///
/// `powershell.exe` takes around half a second to start, which is far too
/// long to hold up a redraw, so it runs on its own thread. The thread waits
/// on the child purely so it is reaped rather than left as a zombie.
fn raise_desktop_notification(text: &str) {
    static ENCODED: OnceLock<String> = OnceLock::new();
    let encoded = ENCODED.get_or_init(|| encode_powershell_command(TOAST_SCRIPT));

    let mut command = std::process::Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
        .env("RUSTCHAT_TOAST_TITLE", "rustchat")
        .env("RUSTCHAT_TOAST_BODY", text)
        .env("RUSTCHAT_TOAST_APPID", toast_app_id())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    std::thread::spawn(move || {
        // Nothing to do about a failure: the bell has already rung, and a
        // missing powershell.exe is not worth interrupting a chat over.
        if let Ok(mut child) = command.spawn() {
            let _ = child.wait();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_cannot_break_out_of_the_escape() {
        // A bell or an ESC inside the text would end the sequence early and
        // leave the rest to be interpreted as terminal commands.
        let nasty = "sam\x07\x1b]0;pwned\x07";
        let clean = sanitize(nasty);
        assert!(!clean.contains('\x07'));
        assert!(!clean.contains('\x1b'));
        assert_eq!(clean, "sam]0;pwned");
    }

    #[test]
    fn text_is_capped() {
        assert_eq!(sanitize(&"x".repeat(1000)).chars().count(), MAX_TEXT);
    }

    #[test]
    fn the_sequence_rings_and_asks_for_a_notification() {
        let sequence = terminal_sequence("sam mentioned you", false);
        assert!(sequence.starts_with('\x07'), "the bell should come first");
        assert!(sequence.contains("\x1b]9;rustchat: sam mentioned you\x07"));
    }

    #[test]
    fn tmux_passthrough_doubles_inner_escapes() {
        let sequence = terminal_sequence("hi", true);
        assert!(
            sequence.contains("\x1bPtmux;"),
            "should be wrapped: {sequence:?}"
        );
        assert!(
            sequence.ends_with("\x1b\\"),
            "should be terminated: {sequence:?}"
        );
        assert!(
            sequence.contains("\x1b\x1b]9;"),
            "the inner escape must be doubled or tmux eats it: {sequence:?}"
        );
    }

    #[test]
    fn throttle_lets_the_first_through_then_waits() {
        let start = Instant::now();
        assert!(throttle_allows(start), "the first notification should go");
        assert!(!throttle_allows(start + Duration::from_millis(500)));
        assert!(!throttle_allows(start + MIN_GAP - Duration::from_millis(1)));
        assert!(throttle_allows(start + MIN_GAP + Duration::from_millis(1)));
    }

    #[test]
    fn wsl_kernels_are_recognised() {
        assert!(kernel_is_wsl(
            "Linux version 6.18.33.2-microsoft-standard-WSL2 (gcc ...)"
        ));
        assert!(kernel_is_wsl("... Microsoft ..."), "case should not matter");
        assert!(!kernel_is_wsl(
            "Linux version 6.8.0-139-generic (buildd@lcy02) ..."
        ));
    }

    #[test]
    fn the_script_encodes_as_utf16le_base64() {
        use base64::Engine;
        let encoded = encode_powershell_command("echo hi");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("valid base64");
        // "echo hi" as UTF-16LE: every ASCII byte followed by a zero.
        assert_eq!(decoded.len(), "echo hi".len() * 2);
        assert_eq!(&decoded[..4], &[b'e', 0, b'c', 0]);
    }

    #[test]
    fn the_toast_script_reads_its_text_from_the_environment() {
        // Taking the text as an argument instead would put a username on a
        // PowerShell command line, which is a code-execution hazard.
        assert!(TOAST_SCRIPT.contains("$env:RUSTCHAT_TOAST_BODY"));
        assert!(TOAST_SCRIPT.contains("$env:RUSTCHAT_TOAST_TITLE"));
        assert!(
            !TOAST_SCRIPT.contains("param("),
            "the script should take no parameters"
        );
    }

    #[test]
    fn the_toast_escapes_its_text_for_xml() {
        // The text goes into a XML document; an unescaped quote or angle
        // bracket from a username would otherwise break the toast.
        assert!(TOAST_SCRIPT.contains("SecurityElement]::Escape"));
    }

    #[test]
    fn a_terminal_identity_is_preferred_when_there_is_one() {
        // Not asserting on the live environment: just that the two
        // identities are distinct and non-empty.
        assert_ne!(WINDOWS_TERMINAL_APP_ID, POWERSHELL_APP_ID);
        assert!(toast_app_id() == WINDOWS_TERMINAL_APP_ID || toast_app_id() == POWERSHELL_APP_ID);
    }
}
