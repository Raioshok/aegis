//! Shared types for the optimizer.

use serde::{Deserialize, Serialize};

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Impact {
    /// Nothing to do — already optimal (informational).
    Ok = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl Impact {
    pub fn label(self) -> &'static str {
        match self {
            Impact::Ok => "OK",
            Impact::Low => "Low",
            Impact::Medium => "Medium",
            Impact::High => "High",
        }
    }
}

/// A single optimization opportunity (or a confirmation that something is fine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Grouping, e.g. `"Package cache"`, `"Network"`.
    pub category: String,
    pub title: String,
    pub detail: String,
    pub impact: Impact,
    /// Disk space this finding can reclaim, in bytes (0 if not applicable).
    pub reclaimable: u64,
    /// The command a user (or `aegis optimize clean/tune`) would run to fix it.
    pub action: Option<String>,
    /// Whether applying the action needs root.
    pub needs_root: bool,
}

impl Finding {
    pub fn ok(category: &str, title: &str, detail: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            title: title.into(),
            detail: detail.into(),
            impact: Impact::Ok,
            reclaimable: 0,
            action: None,
            needs_root: false,
        }
    }

    pub fn action(
        category: &str,
        title: &str,
        detail: impl Into<String>,
        impact: Impact,
        reclaimable: u64,
        action: impl Into<String>,
        needs_root: bool,
    ) -> Self {
        Self {
            category: category.into(),
            title: title.into(),
            detail: detail.into(),
            impact,
            reclaimable,
            action: Some(action.into()),
            needs_root,
        }
    }
}

/// The result of an optimization scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptimizeReport {
    pub findings: Vec<Finding>,
}

impl OptimizeReport {
    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    /// Total disk space reclaimable across all findings.
    pub fn total_reclaimable(&self) -> u64 {
        self.findings.iter().map(|f| f.reclaimable).sum()
    }

    /// Findings that represent actual work (not already-OK confirmations).
    pub fn actionable(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.impact > Impact::Ok)
    }
}

/// Human-readable byte size.
pub fn human_bytes(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_and_actionable() {
        let mut r = OptimizeReport::default();
        r.push(Finding::ok("X", "fine", "nothing"));
        r.push(Finding::action(
            "Cache",
            "big",
            "clean me",
            Impact::High,
            1024,
            "rm -rf x",
            false,
        ));
        assert_eq!(r.total_reclaimable(), 1024);
        assert_eq!(r.actionable().count(), 1);
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(11 * 1024 * 1024 * 1024), "11.0 GB");
    }
}
