//! Privileged, mount-wide real-time watcher built on `fanotify`.

#![cfg(target_os = "linux")]
//!
//! fanotify sees activity across an entire mount and (in permission mode) can
//! *block* access until a verdict is reached — the basis for true prevention.
//! It requires `CAP_SYS_ADMIN`, so this backend is opt-in via the `fanotify`
//! cargo feature and is selected only for the privileged system daemon. When
//! unavailable it degrades to a clear error and the daemon falls back to
//! inotify.

use super::{WatchEvent, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Decides whether an executable may run (`true` = allow). Called on the
/// fanotify thread while the launching process waits.
pub type ExecGate = Arc<dyn Fn(&Path) -> bool + Send + Sync>;

/// Construct a fanotify watcher over `roots`, or return why it is unavailable.
/// With `gate`, program launches on those mounts wait for its verdict.
#[cfg(feature = "fanotify")]
pub fn start(roots: Vec<PathBuf>, gate: Option<ExecGate>) -> Result<FanotifyWatcher, String> {
    FanotifyWatcher::start(roots, gate).map_err(|e| e.to_string())
}

/// Stub used when the crate is built without the `fanotify` feature.
#[cfg(not(feature = "fanotify"))]
pub fn start(_roots: Vec<PathBuf>, _gate: Option<ExecGate>) -> Result<FanotifyWatcher, String> {
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
    pub fn start(roots: Vec<PathBuf>, gate: Option<ExecGate>) -> nix::Result<Self> {
        use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};

        // Permission events need a content-class group.
        let class = if gate.is_some() { InitFlags::FAN_CLASS_CONTENT } else { InitFlags::FAN_CLASS_NOTIF };
        let fan = Fanotify::init(class | InitFlags::FAN_CLOEXEC, EventFFlags::O_RDONLY)?;

        // Mark each root's mount for file close-write. We open the root
        // directory as an fd and mark the mount that contains it (FAN_MARK_MOUNT
        // with a dirfd and no path), which avoids needing AT_FDCWD (nix's `mark`
        // requires an `AsFd`, and this crate forbids `unsafe`).
        // CLOSE_WRITE only: FAN_MODIFY fires per write() and rescans files mid-write.
        let mut mask = MaskFlags::FAN_CLOSE_WRITE;
        if gate.is_some() {
            mask |= MaskFlags::FAN_OPEN_EXEC_PERM;
        }
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
            .spawn(move || run(fan, tx, gate))
            .map_err(|_| nix::Error::ENOMEM)?;

        Ok(Self {
            roots,
            rx: Some(rx),
        })
    }
}

#[cfg(feature = "fanotify")]
fn run(fan: nix::sys::fanotify::Fanotify, tx: mpsc::Sender<WatchEvent>, gate: Option<ExecGate>) {
    use nix::sys::fanotify::{FanotifyResponse, MaskFlags, Response};
    use std::os::fd::AsRawFd;
    let own_pid = std::process::id() as i32;
    loop {
        let events = match fan.read_events() {
            Ok(ev) => ev,
            Err(nix::errno::Errno::EINTR) => continue,
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
                Err(_) => {
                    if event.mask().contains(MaskFlags::FAN_OPEN_EXEC_PERM) {
                        let _ = fan.write_response(FanotifyResponse::new(fd, Response::FAN_ALLOW));
                    }
                    continue;
                }
            };
            if event.mask().contains(MaskFlags::FAN_OPEN_EXEC_PERM) {
                // Every permission event must be answered or the launcher hangs:
                // allow our own process and fail open if the scanner panics.
                let allow = event.pid() == own_pid
                    || gate.as_ref().map_or(true, |g| {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g(&path))).unwrap_or(true)
                    });
                let verdict = if allow { Response::FAN_ALLOW } else { Response::FAN_DENY };
                if let Err(e) = fan.write_response(FanotifyResponse::new(fd, verdict)) {
                    tracing::error!(error = %e, "fanotify permission response failed");
                }
                if allow {
                    continue;
                }
                tracing::warn!(path = %path.display(), pid = event.pid(), "blocked execution of detected threat");
            }
            // fanotify attributes the originating process.
            let pid = {
                let p = event.pid();
                if p > 0 {
                    Some(p as u32)
                } else {
                    None
                }
            };
            let ev = WatchEvent {
                path,
                kind: super::EventKind::Written,
                pid,
            };
            if gate.is_some() {
                // Never wait on the monitor here: pending launches are queued behind this thread.
                match tx.try_send(ev) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(ev)) => {
                        tracing::warn!(path = %ev.path.display(), "real-time queue full; event dropped")
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }
            } else if tx.blocking_send(ev).is_err() {
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
