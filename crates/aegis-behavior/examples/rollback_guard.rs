//! Ransomware rollback guard — write-interception with pre-write snapshots.
//!
//! Requires Linux with `CAP_SYS_ADMIN` and the `rollback` Cargo feature.

#[cfg(target_os = "linux")]
mod linux_impl {
    use aegis_behavior::ransomware::{EventType, RansomwareConfig, RansomwareGuard};
    use aegis_engine::shannon_entropy;
    use nix::sys::fanotify::{
        EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
    };
    use nix::unistd::{lseek, read, Whence};
    use std::collections::HashMap;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 3 {
            eprintln!("usage: rollback_guard <mount> <snapshot-dir>");
            std::process::exit(2);
        }
        let mount = PathBuf::from(&args[1]);
        let snap_dir = PathBuf::from(&args[2]);
        std::fs::create_dir_all(&snap_dir).expect("create snapshot dir");

        let fan = Fanotify::init(
            InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY,
        )
        .expect("fanotify init (needs CAP_SYS_ADMIN)");

        let dir = std::fs::File::open(&mount).expect("open mount");
        fan.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
            MaskFlags::FAN_OPEN_PERM | MaskFlags::FAN_MODIFY,
            &dir,
            None::<&Path>,
        )
        .expect("fanotify mark");

        eprintln!(
            "[guard] protecting mount {} (snapshots → {})",
            mount.display(),
            snap_dir.display()
        );

        let mut guard = RansomwareGuard::new(RansomwareConfig {
            window_ms: 60_000,
            max_writes: 6,
            entropy_threshold: 7.0,
            min_high_entropy: 4,
            rename_storm: 6,
        });
        let mut snapshots: HashMap<PathBuf, PathBuf> = HashMap::new();
        let start = Instant::now();

        loop {
            let events = match fan.read_events() {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("[guard] read_events error: {e}; stopping");
                    break;
                }
            };
            for event in events {
                let mask = event.mask();
                let pid = event.pid();
                let Some(fd) = event.fd() else { continue };

                let path = resolve_path(fd.as_raw_fd());

                if mask.contains(MaskFlags::FAN_OPEN_PERM) {
                    if let Some(p) = &path {
                        if is_under(p, &mount) && !snapshots.contains_key(p) {
                            if let Some(bytes) = read_fd(fd) {
                                if !bytes.is_empty() {
                                    let snap = snap_dir.join(sanitize(p));
                                    if std::fs::write(&snap, &bytes).is_ok() {
                                        snapshots.insert(p.clone(), snap);
                                    }
                                }
                            }
                        }
                    }
                    let _ = fan.write_response(FanotifyResponse::new(fd, Response::FAN_ALLOW));
                    continue;
                }

                if mask.contains(MaskFlags::FAN_MODIFY) {
                    let Some(p) = path else { continue };
                    if !is_under(&p, &mount) {
                        continue;
                    }
                    let entropy = read_fd(fd).map(|b| shannon_entropy(&b)).unwrap_or(0.0);
                    let now_ms = start.elapsed().as_millis() as u64;
                    if let Some(alert) =
                        guard.observe(&p, EventType::Write, entropy, Some(pid as u32), now_ms)
                    {
                        eprintln!(
                            "\n[guard] ⚠ RANSOMWARE detected ({:?}) pid={:?} — {} high-entropy writes",
                            alert.reason, alert.pid, alert.high_entropy_writes
                        );
                        respond_and_rollback(&fan, &mount, &snapshots, alert.pid);
                        eprintln!(
                            "[guard] done — restored {} file(s). Exiting.",
                            snapshots.len()
                        );
                        return;
                    }
                }
            }
        }
    }

    fn respond_and_rollback(
        fan: &Fanotify,
        mount: &Path,
        snapshots: &HashMap<PathBuf, PathBuf>,
        pid: Option<u32>,
    ) {
        let _ = std::fs::File::open(mount).map(|d| {
            fan.mark(
                MarkFlags::FAN_MARK_REMOVE | MarkFlags::FAN_MARK_MOUNT,
                MaskFlags::FAN_OPEN_PERM | MaskFlags::FAN_MODIFY,
                &d,
                None::<&Path>,
            )
        });

        if let Some(pid) = pid {
            if pid > 1 {
                match aegis_behavior::response::kill_pid(pid) {
                    Ok(()) => eprintln!("[guard] killed ransomware process pid={pid}"),
                    Err(e) => eprintln!("[guard] kill pid={pid} failed: {e}"),
                }
            }
        }

        let mut restored = 0;
        for (orig, snap) in snapshots {
            if let Ok(bytes) = std::fs::read(snap) {
                if std::fs::write(orig, &bytes).is_ok() {
                    restored += 1;
                }
            }
            for ext in ["locked", "crypt", "enc"] {
                let mut renamed = orig.clone();
                let name = format!(
                    "{}.{ext}",
                    orig.file_name().unwrap_or_default().to_string_lossy()
                );
                renamed.set_file_name(name);
                let _ = std::fs::remove_file(&renamed);
            }
        }
        eprintln!("[guard] restored {restored} file(s) from snapshots");
    }

    fn read_fd(fd: BorrowedFd<'_>) -> Option<Vec<u8>> {
        lseek(fd, 0, Whence::SeekSet).ok()?;
        let mut out = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            match read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return None,
            }
        }
        Some(out)
    }

    fn resolve_path(raw: i32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/self/fd/{raw}")).ok()
    }

    fn is_under(p: &Path, mount: &Path) -> bool {
        p.starts_with(mount)
    }

    fn sanitize(p: &Path) -> String {
        p.to_string_lossy().replace(['/', '.'], "_")
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        linux_impl::run();
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("rollback_guard example requires Linux fanotify and CAP_SYS_ADMIN");
    }
}
