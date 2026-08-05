//! CLI subcommands for the system & network optimizer (Kaspersky-style tune-up).

use crate::render::{self, BOLD, CYAN, DIM, GREEN, RED, RESET};
use aegis_optimize::model::{human_bytes, Impact, OptimizeReport};

fn impact_color(i: Impact) -> &'static str {
    match i {
        Impact::Ok => GREEN,
        Impact::Low => CYAN,
        Impact::Medium => render::YELLOW,
        Impact::High => RED,
    }
}

fn print_report(title: &str, report: &OptimizeReport) {
    println!("{BOLD}{title}{RESET}");
    // Group by category, actionable items first.
    let mut cats: Vec<&str> = report
        .findings
        .iter()
        .map(|f| f.category.as_str())
        .collect();
    cats.sort_unstable();
    cats.dedup();
    for cat in cats {
        println!("\n{CYAN}▸ {cat}{RESET}");
        for f in report.findings.iter().filter(|f| f.category == cat) {
            let tag = format!("[{}]", f.impact.label());
            let reclaim = if f.reclaimable > 0 {
                format!(" {DIM}(reclaims ~{}){RESET}", human_bytes(f.reclaimable))
            } else {
                String::new()
            };
            println!(
                "  {} {}{}",
                render::paint(impact_color(f.impact), &tag),
                f.title,
                reclaim
            );
            println!("      {DIM}{}{RESET}", f.detail);
            if let Some(a) = &f.action {
                let root = if f.needs_root { " (needs root)" } else { "" };
                println!("      {DIM}→ {a}{root}{RESET}");
            }
        }
    }
    let total = report.total_reclaimable();
    let n = report.actionable().count();
    println!(
        "\n{BOLD}{} opportunit{} · up to {} reclaimable{RESET}",
        n,
        if n == 1 { "y" } else { "ies" },
        render::paint(GREEN, &human_bytes(total))
    );
}

/// `aegis optimize` / `optimize scan` — full read-only tune-up scan.
pub fn scan(json: bool) -> i32 {
    let report = aegis_optimize::full_scan();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return 0;
    }
    print_report("System & network optimization", &report);
    0
}

/// `aegis optimize network` — network-only tune-up scan.
pub fn network(json: bool) -> i32 {
    let report = aegis_optimize::network::scan();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return 0;
    }
    print_report("Network optimization", &report);
    0
}

/// `aegis optimize clean [--apply]` — reclaim disk space.
pub fn clean(apply: bool, pacman: bool, journal: bool, orphans: bool, user_cache: bool) -> i32 {
    use aegis_optimize::actions;
    // If no specific target is chosen, do the safe disk reclaimers.
    let all = !(pacman || journal || orphans || user_cache);
    let mut results = Vec::new();

    if pacman || all {
        results.push(actions::clean_pacman_cache(apply));
    }
    if journal || all {
        results.push(actions::vacuum_journal("200M", apply));
    }
    if orphans {
        results.push(actions::remove_orphans(apply));
    }
    if user_cache {
        results.push(clean_user_cache(apply));
    }

    for r in &results {
        let mark = if r.applied && r.ok {
            render::paint(GREEN, "✓")
        } else if !r.applied {
            render::paint(CYAN, "○")
        } else {
            render::paint(RED, "✗")
        };
        println!("{mark} {}", r.description);
        if !r.output.is_empty() {
            for line in r.output.lines().take(6) {
                println!("    {DIM}{line}{RESET}");
            }
        }
    }
    if !apply {
        println!(
            "\n{}",
            render::paint(
                CYAN,
                "Dry run — nothing changed. Re-run with `--apply` (privileged \
                 steps need sudo) to reclaim the space."
            )
        );
    }
    0
}

/// `aegis optimize tune [--apply]` — apply the network sysctl profile.
pub fn tune(apply: bool) -> i32 {
    let r = aegis_optimize::actions::apply_network_tuning(apply);
    let mark = if r.applied && r.ok {
        render::paint(GREEN, "✓")
    } else if !r.applied {
        render::paint(CYAN, "○")
    } else {
        render::paint(RED, "✗")
    };
    println!("{mark} {}", r.description);
    for line in r.output.lines() {
        println!("    {DIM}{line}{RESET}");
    }
    if !apply {
        println!(
            "\n{}",
            render::paint(
                CYAN,
                "Dry run — re-run with `sudo aegis optimize tune --apply`."
            )
        );
    }
    if r.applied && !r.ok {
        return 2;
    }
    0
}

/// Clearing ~/.cache is user-owned but can disturb running apps — handle here
/// rather than in the library so the warning is explicit.
fn clean_user_cache(apply: bool) -> aegis_optimize::actions::ActionResult {
    use aegis_optimize::actions::ActionResult;
    let cache = std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache"));
    let Some(cache) = cache else {
        return ActionResult {
            description: "Clear ~/.cache".into(),
            applied: false,
            output: "HOME not set".into(),
            ok: false,
        };
    };
    let size = aegis_optimize::system::dir_size(&cache);
    if !apply {
        return ActionResult {
            description: "Clear ~/.cache".into(),
            applied: false,
            output: format!(
                "[dry-run] would delete contents of {} ({}). Close apps first.",
                cache.display(),
                human_bytes(size)
            ),
            ok: true,
        };
    }
    // Remove entries inside ~/.cache (not the dir itself).
    let mut removed_ok = true;
    if let Ok(entries) = std::fs::read_dir(&cache) {
        for e in entries.flatten() {
            let p = e.path();
            let res = if p.is_dir() {
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            };
            if res.is_err() {
                removed_ok = false;
            }
        }
    }
    ActionResult {
        description: "Clear ~/.cache".into(),
        applied: true,
        output: format!("cleared ~{} of cache", human_bytes(size)),
        ok: removed_ok,
    }
}
