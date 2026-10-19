//! Real-time file system watcher on Windows using ReadDirectoryChangesW.

use super::{EventKind, WatchEvent, Watcher};
use aegis_core::AccessEventType;
use aegis_platform::{FileEventSource, WindowsFileEventSource};
use std::path::PathBuf;
use tokio::sync::mpsc;

pub struct WindowsWatcher {
    roots: Vec<PathBuf>,
    rx: Option<mpsc::Receiver<WatchEvent>>,
}

impl WindowsWatcher {
    pub fn start(roots: Vec<PathBuf>) -> std::io::Result<Self> {
        let source = WindowsFileEventSource::new();
        let mut stream = source
            .start(&roots)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let (tx, rx) = mpsc::channel(1024);

        std::thread::Builder::new()
            .name("aegis-win-rt".into())
            .spawn(move || {
                while let Some(ev) = stream.next_event() {
                    let kind = match ev.event_type {
                        AccessEventType::CloseWrite => EventKind::Written,
                        AccessEventType::Modify => EventKind::Written,
                        AccessEventType::Rename => EventKind::MovedIn,
                        _ => EventKind::Written,
                    };
                    if tx
                        .blocking_send(WatchEvent {
                            path: ev.path,
                            kind,
                            pid: if ev.pid > 0 { Some(ev.pid) } else { None },
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;

        Ok(Self {
            roots,
            rx: Some(rx),
        })
    }
}

impl Watcher for WindowsWatcher {
    fn backend(&self) -> &'static str {
        "ReadDirectoryChangesW"
    }

    fn watched(&self) -> Vec<PathBuf> {
        self.roots.clone()
    }

    fn take_events(&mut self) -> Option<mpsc::Receiver<WatchEvent>> {
        self.rx.take()
    }
}
