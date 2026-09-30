//! `rustchat send` and `rustchat tail`: the room without the TUI, for scripts,
//! cron jobs and bots.
//!
//! Both go through the same connection code as the TUI, so they seal, open and
//! reconnect exactly as it does. Neither announces a join or a leave — a bot
//! posting a build result shouldn't also fill the room with presence noise.

use std::io::{IsTerminal, Read, Write};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustchat_core::identity::fingerprint;
use rustchat_core::vault::open_vault;
use rustchat_core::{Identity, Payload, Signer, proto};

use crate::net::{self, Incoming, NetCmd, NetEvent};
use crate::{Cli, app};

/// How long `send` waits for the relay to echo the message back.
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// Where the room's keys come from when there is no TUI to ask.
const PASSPHRASE_ENV: &str = "RUSTCHAT_PASSPHRASE";

/// A connection and the name to speak under.
struct Target {
    conn: net::Connection,
    username: String,
}

/// Resolves keys from `--invite` / `--room-key`, or else from the vault.
fn target(cli: &Cli) -> Result<Target> {
    let relay_hint = cli
        .relay
        .clone()
        .unwrap_or_else(|| app::DEFAULT_RELAY.to_string());
    if let Some((conn, _, _)) = crate::resolve_direct(cli, &relay_hint)? {
        if cli.identity.is_none() {
            eprintln!(
                "rustchat: signing with a throwaway key, so the room will flag this sender as \
                 unrecognised. Set RUSTCHAT_IDENTITY (from `rustchat identity`) to keep one."
            );
        }
        return Ok(Target {
            conn,
            username: proto::sanitize_username(cli.username.as_deref().unwrap_or("anon")),
        });
    }
    if cli.no_vault {
        bail!("--no-vault needs --invite (or --room-key and --access-key) to know the room");
    }

    let path = crate::vault_path(cli)?;
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "no vault at {} — run `rustchat` once to set one up, or pass --invite",
            path.display()
        )
    })?;
    let mut passphrase = passphrase()?;
    let data = open_vault(&passphrase, &bytes);
    zeroize::Zeroize::zeroize(&mut passphrase);
    let mut data = data?;
    if data.access_key_b64.is_empty() {
        bail!("this vault predates relay access keys; run `rustchat reset` and set up again");
    }
    let room = crate::decode_room_key(&data.room_key_b64)?;
    let access = crate::decode_access_key(&data.access_key_b64)?;
    let relay_url = match &cli.relay {
        Some(relay) => app::normalize_relay(relay).map_err(|e| anyhow::anyhow!(e))?,
        None if !data.relay_url.is_empty() => data.relay_url.clone(),
        None => app::normalize_relay(app::DEFAULT_RELAY).map_err(|e| anyhow::anyhow!(e))?,
    };
    let saved_name = (!data.username.is_empty()).then_some(data.username.clone());
    // A vault from before identities has none yet; the next TUI unlock makes
    // and saves one. This run signs with a one-off key rather than writing
    // the vault behind a TUI that may be open.
    let identity = if data.identity_b64.is_empty() && cli.identity.is_none() {
        eprintln!(
            "rustchat: this vault has no identity yet — open it in rustchat once to make one."
        );
        Identity::generate()
    } else {
        crate::vault_identity(cli, &mut data)?
    };
    Ok(Target {
        conn: net::Connection {
            relay_url,
            access,
            room: room.derive(),
            identity,
        },
        username: proto::sanitize_username(
            cli.username
                .as_deref()
                .or(saved_name.as_deref())
                .unwrap_or("anon"),
        ),
    })
}

/// The vault passphrase: from the environment for scripts, otherwise asked
/// for on the terminal without echoing it.
fn passphrase() -> Result<String> {
    if let Ok(value) = std::env::var(PASSPHRASE_ENV) {
        return Ok(value);
    }
    if !std::io::stderr().is_terminal() {
        bail!(
            "no terminal to ask for your vault passphrase — set {PASSPHRASE_ENV}, \
             or use --invite / RUSTCHAT_INVITE instead of the vault"
        );
    }
    eprint!("Vault passphrase: ");
    let _ = std::io::stderr().flush();
    let read = read_hidden();
    eprintln!();
    read
}

/// Reads a line from the terminal with echo off. Goes through crossterm, which
/// reads the controlling terminal even when stdin is a pipe — so
/// `echo hi | rustchat send` can still ask for the passphrase.
fn read_hidden() -> Result<String> {
    use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, read};
    crossterm::terminal::enable_raw_mode().context("reading the passphrase")?;
    let mut out = String::new();
    let result = loop {
        match read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(anyhow::anyhow!("cancelled"));
                }
                KeyCode::Backspace => {
                    out.pop();
                }
                KeyCode::Char(c) => out.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(err) => break Err(err.into()),
        }
    };
    let _ = crossterm::terminal::disable_raw_mode();
    result.map(|()| out)
}

/// The message to send: the arguments joined, or all of stdin.
fn message(words: &[String]) -> Result<String> {
    let raw = if words.is_empty() || words == ["-"] {
        if std::io::stdin().is_terminal() {
            bail!("nothing to send — pass a message, or pipe one in");
        }
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading the message from stdin")?;
        text
    } else {
        words.join(" ")
    };
    let text = raw.trim_end();
    // `sanitize_body` would truncate; a script should hear about that rather
    // than have the end of its output silently dropped.
    if text.len() > rustchat_core::MAX_BODY_BYTES {
        bail!(
            "message is too long ({} bytes; the limit is {}) — send the end of it, \
             e.g. `| tail -c 3000`",
            text.len(),
            rustchat_core::MAX_BODY_BYTES
        );
    }
    let body = proto::sanitize_body(text);
    if body.trim().is_empty() {
        bail!("nothing to send — the message is empty");
    }
    Ok(body)
}

/// `rustchat send`: posts one message and waits until the relay has it.
pub async fn send(cli: &Cli, words: &[String]) -> Result<()> {
    let body = message(words)?;
    let target = target(cli)?;
    let ours = Payload::Msg {
        user: target.username,
        body,
        ts: proto::now_ms(),
    };
    if !proto::fits(&ours) {
        bail!(
            "message is too long once encrypted ({} bytes; the relay takes {}) — quotes, \
             backslashes and line breaks count double",
            proto::envelope_size(&ours),
            rustchat_core::MAX_ENVELOPE_BYTES
        );
    }

    let (tx, mut rx) = net::spawn(target.conn);
    let outcome = tokio::time::timeout(SEND_TIMEOUT, async {
        let mut sent = false;
        while let Some(event) = rx.recv().await {
            match event {
                // Sent once, on the first connection only. If the link drops
                // before the echo, resending could post it twice; better to
                // report it as unconfirmed and let the caller decide.
                NetEvent::Connected { .. } if !sent => {
                    tx.send(NetCmd::Send(ours.clone()))
                        .await
                        .context("the connection closed")?;
                    sent = true;
                }
                // The relay echoes to the sender too; seeing it means it's in.
                NetEvent::Payload(incoming) if incoming.payload == ours => return Ok(()),
                NetEvent::Fatal(why) => bail!("{why}"),
                NetEvent::Disconnected(why) if sent => {
                    bail!("the connection dropped before the relay confirmed it ({why})")
                }
                _ => {}
            }
        }
        bail!("the connection closed before the relay confirmed it")
    })
    .await;
    let _ = tx.send(NetCmd::Shutdown).await;
    match outcome {
        Ok(result) => result,
        Err(_) => bail!(
            "no confirmation from the relay within {}s — it may or may not have gone out",
            SEND_TIMEOUT.as_secs()
        ),
    }
}

/// `rustchat tail`: prints the backlog, then the room as it happens.
pub async fn tail(cli: &Cli, json: bool, backlog: bool) -> Result<()> {
    let target = target(cli)?;
    let (_tx, mut rx) = net::spawn(target.conn);
    let mut out = std::io::stdout().lock();
    while let Some(event) = rx.recv().await {
        let written = match event {
            NetEvent::History(payloads) if backlog => payloads
                .iter()
                .try_for_each(|p| print_payload(&mut out, p, json, true)),
            NetEvent::Payload(payload) => print_payload(&mut out, &payload, json, false),
            NetEvent::Fatal(why) => bail!("{why}"),
            NetEvent::Disconnected(why) => {
                eprintln!("rustchat: disconnected ({why}); reconnecting");
                Ok(())
            }
            _ => Ok(()),
        };
        // The reader went away (`| head`, a closed pipe): that's a normal end.
        if written.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

fn print_payload(
    out: &mut impl Write,
    incoming: &Incoming,
    json: bool,
    replay: bool,
) -> std::io::Result<()> {
    let payload = &incoming.payload;
    if json {
        let mut value = serde_json::to_value(payload).map_err(std::io::Error::other)?;
        value["replay"] = replay.into();
        // The fingerprint rather than a verdict: `tail` keeps no list of
        // trusted keys, so a bot decides for itself which ones it believes.
        match incoming.signer {
            Signer::Valid(pk) => {
                value["signature"] = "valid".into();
                value["key"] = fingerprint(&pk).into();
            }
            Signer::Unsigned => value["signature"] = "unsigned".into(),
            Signer::Invalid => value["signature"] = "invalid".into(),
        }
        writeln!(out, "{value}")?;
        return out.flush();
    }
    let mark = match incoming.signer {
        Signer::Valid(_) => "",
        Signer::Unsigned => " [unsigned]",
        Signer::Invalid => " [bad signature]",
    };
    match payload {
        Payload::Msg { user, body, ts } => {
            // Continuation lines indented, so a multi-line message still
            // reads as one message to `grep` and to eyes.
            let body = body.replace('\n', "\n      ");
            writeln!(out, "{} {user}{mark}: {body}", clock(*ts))?;
        }
        // Presence from a replay says nothing about now, as in the TUI.
        Payload::Join { user, ts } if !replay => {
            writeln!(out, "{} → {user} joined", clock(*ts))?;
        }
        Payload::Leave { user, ts } if !replay => {
            writeln!(out, "{} ← {user} left", clock(*ts))?;
        }
        _ => return Ok(()),
    }
    out.flush()
}

fn clock(ts: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(ts).single() {
        Some(dt) => dt.format("%H:%M").to_string(),
        None => "--:--".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_join_into_one_message() {
        assert_eq!(
            message(&["deploy".into(), "done".into()]).unwrap(),
            "deploy done"
        );
    }

    #[test]
    fn an_empty_message_is_refused() {
        assert!(message(&["   ".into()]).is_err());
    }

    #[test]
    fn an_over_long_message_is_refused_not_truncated() {
        let long = "x".repeat(rustchat_core::MAX_BODY_BYTES + 10);
        assert!(message(&[long]).is_err());
    }

    #[test]
    fn plain_output_indents_continuation_lines() {
        let mut out = Vec::new();
        let p = Payload::Msg {
            user: "ci".into(),
            body: "build failed\nsee log".into(),
            ts: 0,
        };
        print_payload(&mut out, &p.into(), false, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.ends_with("ci [unsigned]: build failed\n      see log\n"),
            "{text:?}"
        );
    }

    #[test]
    fn json_output_is_one_object_per_line_and_marks_replays() {
        let mut out = Vec::new();
        let p = Payload::Msg {
            user: "ci".into(),
            body: "a\nb".into(),
            ts: 5,
        };
        let id = Identity::generate();
        let incoming = Incoming {
            payload: p,
            signer: Signer::Valid(id.public()),
        };
        print_payload(&mut out, &incoming, true, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["kind"], "msg");
        assert_eq!(value["body"], "a\nb");
        assert_eq!(value["replay"], true);
        assert_eq!(value["signature"], "valid");
        assert_eq!(value["key"], fingerprint(&id.public()));
    }

    #[test]
    fn replayed_presence_is_skipped_in_plain_output() {
        let mut out = Vec::new();
        let p = Payload::Join {
            user: "sam".into(),
            ts: 0,
        };
        print_payload(&mut out, &p.into(), false, true).unwrap();
        assert!(out.is_empty());
    }
}
