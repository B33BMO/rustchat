//! Optional on-disk backlog, so a room's history outlives a relay restart and
//! a room sitting empty — which is what lets a second device, joining hours
//! later, see what was said.
//!
//! What lands on disk is exactly what the relay already holds in memory: the
//! room id (as a file name) and sealed envelopes it cannot open. Persisting
//! them hands a thief of this disk nothing that a thief of this process's
//! memory would not already have had; it just keeps it around for longer, which
//! is why retention is bounded both in age and in number of rooms.
//!
//! Each room is one JSON-lines file of envelopes, appended per message and
//! rewritten from memory once it grows well past what memory retains. A torn
//! final line from a crash mid-append is skipped on load rather than fatal.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use rustchat_core::{SealedEnvelope, parse_hex32};

use crate::RoomId;

const EXTENSION: &str = "jsonl";

pub struct Store {
    dir: PathBuf,
    /// How long a room's file survives after its last message.
    retention: Duration,
    /// Most room files kept at once; the longest-quiet are dropped first.
    max_rooms: usize,
}

impl Store {
    /// Opens (creating if need be) the directory, and proves it is writable
    /// now rather than on the first message someone sends.
    pub fn open(dir: &Path, retention: Duration, max_rooms: usize) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let probe = dir.join(".write-test");
        create_private(&probe)
            .and_then(|_| fs::remove_file(&probe))
            .with_context(|| format!("{} is not writable", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            retention,
            max_rooms,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: &RoomId) -> PathBuf {
        self.dir.join(format!("{}.{EXTENSION}", hex(id)))
    }

    /// Every envelope saved for this room, oldest first. A missing file is an
    /// empty room; an unreadable line is skipped.
    pub fn load(&self, id: &RoomId) -> Vec<SealedEnvelope> {
        let Ok(file) = File::open(self.path(id)) else {
            return Vec::new();
        };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect()
    }

    pub fn append(&self, id: &RoomId, env: &SealedEnvelope) -> io::Result<()> {
        let mut line = serde_json::to_vec(env)?;
        line.push(b'\n');
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        private_mode(&mut options);
        // One write call per line, so concurrent appends can't interleave.
        options.open(self.path(id))?.write_all(&line)
    }

    /// Replaces the room's file with exactly `envs`, via a temp file and a
    /// rename so a crash leaves either the old file or the new one.
    pub fn rewrite(&self, id: &RoomId, envs: &[SealedEnvelope]) -> io::Result<()> {
        let path = self.path(id);
        let tmp = path.with_extension("tmp");
        let result = (|| {
            let mut file = create_private(&tmp)?;
            for env in envs {
                serde_json::to_writer(&mut file, env)?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
            fs::rename(&tmp, &path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    /// Deletes rooms quiet for longer than the retention period, then the
    /// quietest beyond the room cap. Rooms in `live` are loaded in memory and
    /// being written to, so they are left alone. Returns how many went.
    pub fn prune(&self, live: &HashSet<RoomId>) -> usize {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        let now = SystemTime::now();
        let mut kept: Vec<(SystemTime, PathBuf)> = Vec::new();
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(id) = room_id_of(&path) else {
                continue;
            };
            if live.contains(&id) {
                continue;
            }
            let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
                continue;
            };
            let age = now.duration_since(modified).unwrap_or_default();
            if age > self.retention {
                removed += usize::from(fs::remove_file(&path).is_ok());
            } else {
                kept.push((modified, path));
            }
        }
        // Rooms in memory count toward the cap but are never the ones dropped.
        let excess = (kept.len() + live.len()).saturating_sub(self.max_rooms);
        if excess > 0 {
            kept.sort_by_key(|(modified, _)| *modified);
            for (_, path) in kept.iter().take(excess) {
                removed += usize::from(fs::remove_file(path).is_ok());
            }
        }
        removed
    }
}

/// Recovers a room id from a file name, so nothing but room files is touched.
fn room_id_of(path: &Path) -> Option<RoomId> {
    if path.extension()? != EXTENSION {
        return None;
    }
    parse_hex32(path.file_stem()?.to_str()?).ok()
}

fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    private_mode(&mut options);
    options.open(path)
}

/// Ciphertext or not, nobody else on the box needs to read it.
fn private_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(c: &str) -> SealedEnvelope {
        SealedEnvelope {
            n: "n".into(),
            c: c.into(),
        }
    }

    /// A fresh directory per test, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rustchat-store-{name}-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn store(dir: &TempDir, max_rooms: usize) -> Store {
        Store::open(&dir.0, Duration::from_secs(3600), max_rooms).unwrap()
    }

    fn bodies(envs: &[SealedEnvelope]) -> Vec<&str> {
        envs.iter().map(|e| e.c.as_str()).collect()
    }

    #[test]
    fn appends_come_back_in_order() {
        let dir = TempDir::new("order");
        let s = store(&dir, 8);
        for c in ["a", "b", "c"] {
            s.append(&[1; 32], &env(c)).unwrap();
        }
        assert_eq!(bodies(&s.load(&[1; 32])), ["a", "b", "c"]);
        assert!(s.load(&[2; 32]).is_empty(), "rooms don't share files");
    }

    #[test]
    fn rewrite_replaces_the_whole_file() {
        let dir = TempDir::new("rewrite");
        let s = store(&dir, 8);
        for c in ["a", "b", "c"] {
            s.append(&[1; 32], &env(c)).unwrap();
        }
        s.rewrite(&[1; 32], &[env("c")]).unwrap();
        assert_eq!(bodies(&s.load(&[1; 32])), ["c"]);
    }

    #[test]
    fn a_torn_last_line_is_skipped_not_fatal() {
        let dir = TempDir::new("torn");
        let s = store(&dir, 8);
        s.append(&[1; 32], &env("whole")).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(s.path(&[1; 32]))
            .unwrap();
        file.write_all(br#"{"n":"n","c":"hal"#).unwrap();
        assert_eq!(bodies(&s.load(&[1; 32])), ["whole"]);
    }

    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        let s = store(&dir, 8);
        s.append(&[1; 32], &env("x")).unwrap();
        let mode = fs::metadata(s.path(&[1; 32])).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn expired_rooms_are_pruned_and_fresh_ones_kept() {
        let dir = TempDir::new("expire");
        let s = Store::open(&dir.0, Duration::from_millis(50), 8).unwrap();
        s.append(&[1; 32], &env("old")).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        s.append(&[2; 32], &env("new")).unwrap();
        assert_eq!(s.prune(&HashSet::new()), 1);
        assert!(s.load(&[1; 32]).is_empty());
        assert_eq!(bodies(&s.load(&[2; 32])), ["new"]);
    }

    #[test]
    fn the_quietest_rooms_go_first_past_the_cap() {
        let dir = TempDir::new("cap");
        let s = store(&dir, 2);
        for id in 1..=3u8 {
            s.append(&[id; 32], &env("x")).unwrap();
            // Distinct mtimes, even on coarse-grained filesystems.
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(s.prune(&HashSet::new()), 1);
        assert!(s.load(&[1; 32]).is_empty(), "the quietest room went");
        assert!(!s.load(&[3; 32]).is_empty());
    }

    #[test]
    fn live_rooms_are_never_pruned() {
        let dir = TempDir::new("live");
        let s = Store::open(&dir.0, Duration::ZERO, 0).unwrap();
        s.append(&[1; 32], &env("x")).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let live = HashSet::from([[1u8; 32]]);
        assert_eq!(s.prune(&live), 0);
        assert!(!s.load(&[1; 32]).is_empty());
    }

    #[test]
    fn stray_files_are_left_alone() {
        let dir = TempDir::new("stray");
        let s = Store::open(&dir.0, Duration::ZERO, 0).unwrap();
        fs::write(dir.0.join("notes.txt"), "keep me").unwrap();
        fs::write(dir.0.join("nothex.jsonl"), "keep me").unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(s.prune(&HashSet::new()), 0);
        assert!(dir.0.join("notes.txt").exists());
    }
}
