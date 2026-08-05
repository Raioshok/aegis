//! Unprivileged real-time watcher built on `inotify`.
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
    loop {
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
                }
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
    }
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
            let p = entry.path();
            if p.is_dir() {
                add_watch_recursive(inotify, &p, wd_paths);
            }
        }
    }
}
