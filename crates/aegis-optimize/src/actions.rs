//! Applying optimizations. Every action defaults to a **dry run** and reports
//! exactly what it would do; nothing changes the system unless `apply` is true.
//! Destructive/privileged steps shell out to the canonical Arch tools.

use crate::network::RECOMMENDED_SYSCTL;
use std::process::Command;

/// The outcome of one action.
#[derive(Debug)]
pub struct ActionResult {
    pub description: String,
    pub applied: bool,
    pub output: String,
    pub ok: bool,
}

fn run(prog: &str, args: &[&str]) -> (bool, String) {
    match Command::new(prog).args(args).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Trim the pacman cache to one version per package (`paccache -rk1`).
pub fn clean_pacman_cache(apply: bool) -> ActionResult {
    let desc = "Trim pacman cache to the latest version of each package".to_string();
    if !apply {
        let (_, dry) = run("paccache", &["-dvk1"]);
        return ActionResult {
            description: desc,
            applied: false,
            output: format!("[dry-run] would run `sudo paccache -rk1`\n{dry}"),
            ok: true,
        };
    }
    let (ok, out) = run("paccache", &["-rk1"]);
    ActionResult {
        description: desc,
        applied: true,
        output: out,
        ok,
    }
}

/// Cap the systemd journal at `size` (e.g. "200M").
pub fn vacuum_journal(size: &str, apply: bool) -> ActionResult {
    let desc = format!("Vacuum the systemd journal to {size}");
    if !apply {
        return ActionResult {
            description: desc,
            applied: false,
            output: format!("[dry-run] would run `sudo journalctl --vacuum-size={size}`"),
            ok: true,
        };
    }
    let arg = format!("--vacuum-size={size}");
    let (ok, out) = run("journalctl", &[&arg]);
    ActionResult {
        description: desc,
        applied: true,
        output: out,
        ok,
    }
}

/// Remove orphaned packages (`pacman -Rns $(pacman -Qtdq)`).
pub fn remove_orphans(apply: bool) -> ActionResult {
    let desc = "Remove orphaned packages".to_string();
    let (_, list) = run("pacman", &["-Qtdq"]);
    let orphans: Vec<&str> = list
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if orphans.is_empty() {
        return ActionResult {
            description: desc,
            applied: false,
            output: "no orphans to remove".into(),
            ok: true,
        };
    }
    if !apply {
        return ActionResult {
            description: desc,
            applied: false,
            output: format!(
                "[dry-run] would run `sudo pacman -Rns {}`",
                orphans.join(" ")
            ),
            ok: true,
        };
    }
    let mut args = vec!["-Rns", "--noconfirm"];
    args.extend(orphans.iter());
    let (ok, out) = run("pacman", &args);
    ActionResult {
        description: desc,
        applied: true,
        output: out,
        ok,
    }
}

/// Apply the recommended network sysctl profile by writing a drop-in and
/// reloading it. In dry-run, just show the file that would be written.
pub fn apply_network_tuning(apply: bool) -> ActionResult {
    let desc = "Apply the recommended network sysctl profile".to_string();
    let mut content = String::from("# Written by `aegis optimize tune --apply`\n");
    for (k, v) in RECOMMENDED_SYSCTL {
        content.push_str(&format!("{k} = {v}\n"));
    }
    let path = "/etc/sysctl.d/99-aegis-network.conf";

    if !apply {
        return ActionResult {
            description: desc,
            applied: false,
            output: format!("[dry-run] would write {path}:\n{content}\nthen `sysctl --system`"),
            ok: true,
        };
    }

    // Writing to /etc requires root; report clearly if we lack it.
    if let Err(e) = std::fs::write(path, &content) {
        return ActionResult {
            description: desc,
            applied: false,
            output: format!("failed to write {path} (need root): {e}"),
            ok: false,
        };
    }
    let (ok, out) = run("sysctl", &["--system"]);
    ActionResult {
        description: desc,
        applied: true,
        output: out,
        ok,
    }
}
