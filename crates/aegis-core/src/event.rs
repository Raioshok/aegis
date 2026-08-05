//! A lightweight, synchronous event bus (Observer pattern).
//!
//! Engines and services publish [`Event`]s; subscribers (loggers, the UI IPC
//! layer, telemetry) react without the publisher knowing who is listening. The
//! bus is deliberately synchronous and lock-guarded — the async daemon in
//! Milestone 2 wraps it with a Tokio broadcast channel.

use crate::model::{FileVerdict, ScanStats};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Events emitted across the platform.
#[derive(Debug, Clone)]
pub enum Event {
    ScanStarted {
        target: PathBuf,
        total: u64,
    },
    FileScanned {
        path: PathBuf,
        index: u64,
        total: u64,
    },
    ThreatFound(Box<FileVerdict>),
    ScanFinished(ScanStats),
    Info(String),
    Warning(String),
}

/// A subscriber callback.
pub type Subscriber = Arc<dyn Fn(&Event) + Send + Sync>;

/// Synchronous multi-subscriber event bus.
#[derive(Clone, Default)]
pub struct EventBus {
    subscribers: Arc<Mutex<Vec<Subscriber>>>,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.subscribers.lock().map(|s| s.len()).unwrap_or(0);
        f.debug_struct("EventBus").field("subscribers", &n).finish()
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a subscriber. Returns the subscriber count.
    pub fn subscribe(&self, f: Subscriber) -> usize {
        let mut subs = self.subscribers.lock().expect("event bus poisoned");
        subs.push(f);
        subs.len()
    }

    /// Publish an event to every subscriber, in registration order.
    pub fn publish(&self, event: &Event) {
        let subs = self.subscribers.lock().expect("event bus poisoned");
        for s in subs.iter() {
            s(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn subscribers_receive_events() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        bus.subscribe(Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        bus.publish(&Event::Info("hi".into()));
        bus.publish(&Event::Info("again".into()));
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
