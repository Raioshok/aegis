//! Real-time on-access protection.
//!
//! A [`Watcher`] turns filesystem activity into a stream of [`WatchEvent`]s;
//! the [`Monitor`] consumes those events, scans the affected file, and reacts.
//! Two backends implement `Watcher`:
//!
//! * [`inotify::InotifyWatcher`] — unprivileged, per-directory (default for the
//!   per-user daemon). Fully functional today.
//! * [`fanotify::FanotifyWatcher`] — mount-wide, requires `CAP_SYS_ADMIN`
//!   (system daemon). Falls back gracefully when privileges are missing.
//!
//! The seam between "what produces events" and "what we do about them" keeps the
//! scan/quarantine pipeline testable without any kernel privileges.

pub mod fanotify;
pub mod inotify;
mod monitor;

pub use monitor::Monitor;

use std::path::PathBuf;

/// Why a file was surfaced to the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A file was created or finished being written.
    Written,
    /// A file was moved into a watched location.
    MovedIn,
    /// A file was opened (fanotify).
    Opened,
}

/// A single real-time filesystem event of interest.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    pub path: PathBuf,
    pub kind: EventKind,
}

/// A source of [`WatchEvent`]s. Implementations push events into an mpsc
/// channel on a blocking thread and expose the receiver here.
pub trait Watcher: Send {
    /// A short backend name for status reporting.
    fn backend(&self) -> &'static str;

    /// The paths being watched.
    fn watched(&self) -> Vec<PathBuf>;

    /// Take the event receiver (callable once).
    fn take_events(&mut self) -> Option<tokio::sync::mpsc::Receiver<WatchEvent>>;
}
