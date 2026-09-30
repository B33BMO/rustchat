//! Command-line parsing, checked against the real binary.
//!
//! Environment variables can't safely be set inside a unit test (they're
//! process-wide), so these spawn the binary with its own environment.

use std::process::Command;

/// `rustchat [flags] where`: harmless, but still parses every flag and
/// variable.
fn rustchat(flags: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustchat"));
    cmd.args(flags)
        .args(["where", "--vault", "/nonexistent/vault"])
        .env_remove("RUSTCHAT_NO_UPDATE_CHECK");
    cmd
}

#[test]
fn the_update_opt_out_accepts_the_spellings_people_use() {
    // `1` matters most: the README documents it, and every released updater
    // relaunches the new binary with it set. Refusing it once meant an
    // update that installed fine and then couldn't start.
    for value in ["1", "true", "yes", "on", "0", "false", "no", "off"] {
        let out = rustchat(&[])
            .env("RUSTCHAT_NO_UPDATE_CHECK", value)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "RUSTCHAT_NO_UPDATE_CHECK={value} was refused: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn the_update_opt_out_flag_still_works_bare() {
    let out = rustchat(&["--no-update-check"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
