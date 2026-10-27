//! Unprivileged real-time watcher built on `inotify`.

#![cfg(target_os = "linux")]
//!
//! inotify is per-directory and not recursive, so we add a watch on each
//! configured root and on every existing subdirectory, and dynamically add
//! watches when new subdirectories appear. We surface files on `CLOSE_WRITE`
//! (a writer finished) and `MOVED_TO` (a file was moved/downloaded in) — the
//! two moments a freshly-landed file is complete and worth scanning.

use super::{EventKind, WatchEvent, Watcher};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct InotifyWatcher {
    roots: Vec<PathBuf>,
    rx: Option<mpsc::Receiver<WatchEvent>>,
}

impl InotifyWatcher {
    /// Start watching `roots`. Spawns a dedicated blocking thread that reads
    /// inotify events and forwards them over a channel.
    pub fn start(roots: Vec<PathBuf>) -> std::io::Result<Self> {
        let inotify = Inotify::init()?;
        let (tx, rx) = mpsc::channel(1024);

        let watch_roots = roots.clone();
        std::thread::Builder::new()
            .name("aegis-inotify".into())
            .spawn(move || run(inotify, watch_roots, tx))?;

        Ok(Self {
            roots,
            rx: Some(rx),
        })
    }
}

impl Watcher for InotifyWatcher {
    fn backend(&self) -> &'static str {
        "inotify"
    }
    fn watched(&self) -> Vec<PathBuf> {
        self.roots.clone()
    }
    fn take_events(&mut self) -> Option<mpsc::Receiver<WatchEvent>> {
        self.rx.take()
    }
}

fn mask() -> WatchMask {
    WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::CREATE
}

fn run(mut inotify: Inotify, roots: Vec<PathBuf>, tx: mpsc::Sender<WatchEvent>) {
    // Map watch descriptor → directory path, so we can rebuild full paths.
    let mut wd_paths: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

    for root in &roots {
        add_watch_recursive(&mut inotify, root, &mut wd_paths);
    }

    let mut buffer = [0u8; 8192];
    let mut since = std::time::SystemTime::now();
    loop {
        let read_started = std::time::SystemTime::now();
        let events = match inotify.read_events_blocking(&mut buffer) {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "inotify read failed; stopping watcher");
                return;
            }
        };
        // Collect first so we can mutate `inotify` (add watches) without holding
        // the borrow produced by `read_events_blocking`.
        let pending: Vec<(WatchDescriptor, EventMask, Option<PathBuf>)> = events
            .map(|e| (e.wd.clone(), e.mask, e.name.map(PathBuf::from)))
            .collect();

        for (wd, evmask, name) in pending {
            if evmask.contains(EventMask::Q_OVERFLOW) {
                // The kernel dropped events: catch up on everything changed since the last good read.
                tracing::warn!("inotify queue overflow; rescanning watched roots");
                for root in &roots {
                    if !emit_files(root, since, &tx) {
                        return;
                    }
                }
                continue;
            }
            let dir = match wd_paths.get(&wd) {
                Some(d) => d.clone(),
                None => continue,
            };
            let name = match name {
                Some(n) => n,
                None => continue,
            };
            let full = dir.join(&name);

            if evmask.contains(EventMask::ISDIR) {
                if evmask.contains(EventMask::CREATE) || evmask.contains(EventMask::MOVED_TO) {
                    add_watch_recursive(&mut inotify, &full, &mut wd_paths);
                    // Files already inside a moved/unpacked folder never raise their own events.
                    if !emit_files(&full, std::time::UNIX_EPOCH, &tx) {
                        return;
                    }
                }
                continue;
            }

            // CREATE alone means an empty new file; its CLOSE_WRITE follows.
            if evmask == EventMask::CREATE {
                continue;
            }
            let kind = if evmask.contains(EventMask::MOVED_TO) {
                EventKind::MovedIn
            } else {
                EventKind::Written
            };
            // inotify cannot attribute the originating process.
            if tx
                .blocking_send(WatchEvent {
                    path: full,
                    kind,
                    pid: None,
                })
                .is_err()
            {
                return; // receiver dropped → daemon shutting down
            }
        }
        since = read_started;
    }
}

/// Send a `Written` event for every file under `dir` modified at or after `since`.
/// Returns false when the receiver is gone.
fn emit_files(dir: &Path, since: std::time::SystemTime, tx: &mpsc::Sender<WatchEvent>) -> bool {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() && meta.modified().map(|m| m >= since).unwrap_or(true) {
                let ev = WatchEvent { path: entry.path(), kind: EventKind::Written, pid: None };
                if tx.blocking_send(ev).is_err() {
                    return false;
                }
            }
        }
    }
    true
}

/// Add a watch on `dir` and every existing subdirectory beneath it.
fn add_watch_recursive(
    inotify: &mut Inotify,
    dir: &Path,
    wd_paths: &mut HashMap<WatchDescriptor, PathBuf>,
) {
    if !dir.is_dir() {
        return;
    }
    match inotify.watches().add(dir, mask()) {
        Ok(wd) => {
            wd_paths.insert(wd, dir.to_path_buf());
        }
        Err(e) => {
            tracing::warn!(path = %dir.display(), error = %e, "failed to watch directory");
            return;
        }
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() && !ft.is_symlink() {
                    add_watch_recursive(inotify, &entry.path(), wd_paths);
                }
            }
        }
    }
}
