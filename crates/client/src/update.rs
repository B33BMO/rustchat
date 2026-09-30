//! Checking for a newer release on launch, and installing it if asked.
//!
//! Deliberately thin: finding the latest tag is one request, and installing is
//! the release's own `install.sh`, so checksum verification and the atomic
//! replace are the same code a fresh install runs rather than a second copy of
//! it. Every failure here is quiet or advisory — being offline, or GitHub
//! being slow, must never stand between someone and their chat.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

const REPO: &str = "B33BMO/rustchat";

/// Set to skip the check; also set on the relaunch after an update, so a
/// mismatch between tag and binary version can never loop.
pub const OPT_OUT_ENV: &str = "RUSTCHAT_NO_UPDATE_CHECK";

/// How long the whole check may take before launching without it.
const CHECK_TIMEOUT_SECS: &str = "3";

/// Offers to update if a newer release exists. Returns only if no update was
/// installed; after a successful one the process is replaced by the new binary.
pub fn offer(opted_out: bool) {
    // Nothing to ask, or nobody to ask: a script piping into rustchat, a debug
    // build under `cargo run`, or someone who said no for good.
    if opted_out
        || cfg!(debug_assertions)
        || !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
    {
        return;
    }
    let Some(tag) = latest_tag() else { return };
    let current = env!("CARGO_PKG_VERSION");
    if !is_newer(&tag, current) {
        return;
    }

    print!("rustchat {tag} is available (you have v{current}). Update now? [Y/n] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return;
    }
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes") {
        println!("Skipping. (Set {OPT_OUT_ENV}=1 to stop asking.)\n");
        return;
    }

    match install(&tag) {
        Ok(exe) => relaunch(&exe),
        Err(err) => {
            eprintln!("\nThe update didn't go through: {err:#}");
            eprintln!("Carrying on with v{current}. Press Enter to continue.");
            let _ = std::io::stdin().lock().read_line(&mut String::new());
        }
    }
}

/// The newest release tag, e.g. `v0.2.4`, or `None` if it can't be found
/// quickly. Reads the redirect GitHub serves for the latest release rather than
/// calling the API, which rate-limits anonymous callers.
fn latest_tag() -> Option<String> {
    let output = Command::new("curl")
        .args(["-fsS", "--max-time", CHECK_TIMEOUT_SECS, "-o", "/dev/null"])
        .args(["-w", "%{redirect_url}"])
        .arg(format!("https://github.com/{REPO}/releases/latest"))
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    tag_from_redirect(&String::from_utf8(output.stdout).ok()?)
}

fn tag_from_redirect(url: &str) -> Option<String> {
    let tag = url.trim().rsplit_once("/tag/")?.1;
    parse_version(tag).map(|_| tag.to_string())
}

/// `v1.2.3` or `1.2.3` as a comparable triple. A pre-release suffix is
/// ignored, so `v1.2.3-rc1` counts as `1.2.3`.
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

fn is_newer(tag: &str, current: &str) -> bool {
    match (parse_version(tag), parse_version(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

/// Installs `tag` over the running binary, returning the path to relaunch.
fn install(tag: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("finding this binary")?;
    let dir = exe.parent().context("finding this binary's directory")?;
    if !writable(dir) {
        bail!(
            "can't write to {} — update by hand with:\n  curl -fsSL \
             https://raw.githubusercontent.com/{REPO}/main/install.sh | sh",
            dir.display()
        );
    }

    let scratch = std::env::temp_dir().join(format!("rustchat-update-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).context("making a scratch directory")?;
    let result = run_installer(tag, dir, &scratch.join("install.sh"));
    let _ = std::fs::remove_dir_all(&scratch);
    result?;
    Ok(exe)
}

fn run_installer(tag: &str, dir: &Path, script: &Path) -> Result<()> {
    // The installer from the release being installed, not from `main`, so the
    // two always agree about asset names.
    let fetched = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "--retry-delay", "2", "-o"])
        .arg(script)
        .arg(format!(
            "https://raw.githubusercontent.com/{REPO}/{tag}/install.sh"
        ))
        .status()
        .context("running curl")?;
    if !fetched.success() {
        bail!("could not download the installer for {tag}");
    }

    println!();
    let installed = Command::new("sh")
        .arg(script)
        .args(["--version", tag, "--dir"])
        .arg(dir)
        // An update should install the release it offered, or nothing — not
        // quietly fall back to compiling `main` from source.
        .env("RUSTCHAT_NO_BUILD", "1")
        .status()
        .context("running the installer")?;
    if !installed.success() {
        bail!("the installer failed (see above)");
    }
    Ok(())
}

fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".rustchat-update-{}", std::process::id()));
    let ok = std::fs::File::create(&probe).is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Replaces this process with the freshly installed binary, same arguments.
fn relaunch(exe: &Path) -> ! {
    use std::os::unix::process::CommandExt;
    println!("\nRestarting into the new version…\n");
    let err = Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(OPT_OUT_ENV, "1")
        .exec();
    eprintln!("Updated, but could not restart ({err}). Run rustchat again.");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_with_or_without_a_v() {
        assert_eq!(parse_version("v0.2.3"), Some((0, 2, 3)));
        assert_eq!(parse_version("1.10.0"), Some((1, 10, 0)));
        assert_eq!(parse_version("v1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_version("v1.2"), None);
        assert_eq!(parse_version("v1.2.3.4"), None);
        assert_eq!(parse_version("latest"), None);
    }

    #[test]
    fn newer_compares_numerically_not_as_text() {
        assert!(is_newer("v0.10.0", "0.9.9"), "10 > 9, though '1' < '9'");
        assert!(is_newer("v0.2.4", "0.2.3"));
        assert!(!is_newer("v0.2.3", "0.2.3"));
        assert!(!is_newer("v0.2.2", "0.2.3"), "never offer a downgrade");
        assert!(!is_newer("garbage", "0.2.3"));
    }

    #[test]
    fn the_tag_comes_from_the_release_redirect() {
        assert_eq!(
            tag_from_redirect("https://github.com/B33BMO/rustchat/releases/tag/v0.2.4\n"),
            Some("v0.2.4".into())
        );
        // No redirect (curl prints nothing) or somewhere unexpected.
        assert_eq!(tag_from_redirect(""), None);
        assert_eq!(tag_from_redirect("https://github.com/login"), None);
    }
}
