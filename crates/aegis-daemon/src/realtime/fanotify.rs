//! Privileged, mount-wide real-time watcher built on `fanotify`.
//!
//! fanotify sees activity across an entire mount and (in permission mode) can
//! *block* access until a verdict is reached — the basis for true prevention.
//! It requires `CAP_SYS_ADMIN`, so this backend is opt-in via the `fanotify`
//! cargo feature and is selected only for the privileged system daemon. When
//! unavailable it degrades to a clear error and the daemon falls back to
//! inotify.

use super::{WatchEvent, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc;

/// Construct a fanotify watcher over `roots`, or return why it is unavailable.
#[cfg(feature = "fanotify")]
pub fn start(roots: Vec<PathBuf>) -> Result<FanotifyWatcher, String> {
    FanotifyWatcher::start(roots).map_err(|e| e.to_string())
}

/// Stub used when the crate is built without the `fanotify` feature.
#[cfg(not(feature = "fanotify"))]
pub fn start(_roots: Vec<PathBuf>) -> Result<FanotifyWatcher, String> {
    Err("aegis-daemon was compiled without the `fanotify` feature".to_string())
}

// ---------------------------------------------------------------------------
// Real implementation (feature = "fanotify")
// ---------------------------------------------------------------------------
#[cfg(feature = "fanotify")]
pub struct FanotifyWatcher {
    roots: Vec<PathBuf>,
    rx: Option<mpsc::Receiver<WatchEvent>>,
}

#[cfg(feature = "fanotify")]
impl FanotifyWatcher {
    pub fn start(roots: Vec<PathBuf>) -> nix::Result<Self> {
        use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};

        let fan = Fanotify::init(
            InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY,
        )?;

        // Mark each root's mount for file close-write/modify. We open the root
        // directory as an fd and mark the mount that contains it (FAN_MARK_MOUNT
        // with a dirfd and no path), which avoids needing AT_FDCWD (nix's `mark`
        // requires an `AsFd`, and this crate forbids `unsafe`).
        let mask = MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_MODIFY;
        for root in &roots {
            let dir = std::fs::File::open(root).map_err(|_| nix::Error::EACCES)?;
            fan.mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
                mask,
                &dir,
                None::<&std::path::Path>,
            )?;
        }

        let (tx, rx) = mpsc::channel(1024);
        std::thread::Builder::new()
            .name("aegis-fanotify".into())
            .spawn(move || run(fan, tx))
            .map_err(|_| nix::Error::ENOMEM)?;

        Ok(Self {
            roots,
            rx: Some(rx),
        })
    }
}

#[cfg(feature = "fanotify")]
fn run(fan: nix::sys::fanotify::Fanotify, tx: mpsc::Sender<WatchEvent>) {
    use std::os::fd::AsRawFd;
    loop {
        let events = match fan.read_events() {
            Ok(ev) => ev,
            Err(e) => {
                tracing::error!(error = %e, "fanotify read failed; stopping watcher");
                return;
            }
        };
        for event in events {
            // Resolve the accessed file's path via /proc/self/fd/<fd>.
            let Some(fd) = event.fd() else { continue };
            let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let path = match std::fs::read_link(&link) {
                Ok(p) => p,
                Err(_) => continue,
            };
            // fanotify attributes the originating process.
            let pid = {
                let p = event.pid();
                if p > 0 {
                    Some(p as u32)
                } else {
                    None
                }
            };
            if tx
                .blocking_send(WatchEvent {
                    path,
                    kind: super::EventKind::Written,
                    pid,
                })
                .is_err()
            {
                return;
            }
        }
    }
}

#[cfg(feature = "fanotify")]
impl Watcher for FanotifyWatcher {
    fn backend(&self) -> &'static str {
        "fanotify"
    }
    fn watched(&self) -> Vec<PathBuf> {
        self.roots.clone()
    }
    fn take_events(&mut self) -> Option<mpsc::Receiver<WatchEvent>> {
        self.rx.take()
    }
}

// ---------------------------------------------------------------------------
// Stub type (feature disabled) — never constructed, keeps the API uniform.
// ---------------------------------------------------------------------------
#[cfg(not(feature = "fanotify"))]
pub struct FanotifyWatcher {
    _private: (),
}

#[cfg(not(feature = "fanotify"))]
impl Watcher for FanotifyWatcher {
    fn backend(&self) -> &'static str {
        "fanotify(disabled)"
    }
    fn watched(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn take_events(&mut self) -> Option<mpsc::Receiver<WatchEvent>> {
        None
    }
}
