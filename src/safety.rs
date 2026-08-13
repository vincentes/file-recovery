//! Safety checks: mandatory warnings, explicit YES confirmation, root
//! enforcement, same-physical-disk verification (ABORT, not just warn), and
//! best-effort environment detection (FileVault, SSD/TRIM, mounted volumes).
//!
//! Everything here is read-only: the conditional checks use `diskutil info`
//! and `df`, which never modify anything.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::disk::{device_number_of_fs, device_number_of_source, SourceKind};
use crate::error::CarveError;

pub fn is_root() -> bool {
    let euid = unsafe { libc::geteuid() };
    euid == 0
}

pub fn root_explanation(device: &str) -> String {
    format!(
        "error: reading raw device {device} requires root privileges.\n\
         Raw block devices (/dev/rdisk*) are protected by macOS; without sudo the open will fail.\n\
         Re-run with sudo, e.g.:\n  sudo file-recovery --device {device} --output /Volumes/External/recovered\n\
         (Scanning a regular disk-image file with --allow-file does not require root.)"
    )
}

/// The mandatory warnings. Displayed before ANY disk access, in every mode
/// (including --force and --quiet).
pub fn print_warnings(device: &str, output: &str) {
    println!("======================================================================");
    println!("                     file-recovery — SAFETY WARNINGS");
    println!("======================================================================");
    println!("WARNING: This tool reads raw disk data. Use at your own risk.");
    println!("WARNING: For best results, the source disk should not be actively in use (consider booting from an external drive or using Target Disk Mode).");
    println!("WARNING: If FileVault is enabled, deleted file content may be encrypted and unrecoverable without keys.");
    println!("WARNING: SSDs with TRIM enabled may have already permanently zeroed deleted blocks — recovery may not be possible.");
    println!("WARNING: Do not write recovered files to the same disk you are scanning — this can overwrite recoverable data.");
    println!("This tool is READ-ONLY and will not modify the source disk in any way.");
    println!();
    println!("This tool will NOT:");
    println!("  - delete any files or data");
    println!("  - modify the source disk");
    println!("  - attempt to repair file system corruption");
    println!("  - bypass FileVault encryption");
    println!("  - access system-protected volumes without explicit user consent");
    println!("  - recover files to the same disk being scanned");
    println!("  - run without root/sudo for raw devices (it will explain why if missing)");
    println!();
    println!("Source: {device}");
    println!("Output: {output}");
    println!("Recover only your OWN data — see --help / README for legal terms.");
    println!("======================================================================");
}

/// Best-effort environment warnings for real devices (FileVault, SSD/TRIM,
/// mounted volumes, live boot disk). Failures here never abort the run.
pub fn environment_warnings(device: &str, kind: SourceKind) {
    if kind != SourceKind::Device {
        return;
    }
    if let Ok(out) = Command::new("diskutil").args(["info", device]).output() {
        if out.status.success() {
            let info = String::from_utf8_lossy(&out.stdout);
            let field = |name: &str| -> Option<String> {
                info.lines().find_map(|l| {
                    let l = l.trim_start();
                    l.strip_prefix(name)
                        .map(|rest| rest.trim_start_matches(':').trim().to_string())
                })
            };
            if field("FileVault").as_deref() == Some("Yes") {
                println!("WARNING: FileVault is ENABLED on this volume — deleted content is encrypted at rest and carved bytes will very likely be unrecoverable ciphertext.");
            }
            if field("Solid State").as_deref() == Some("Yes") {
                println!("WARNING: This is a solid-state device. TRIM may have already permanently zeroed deleted blocks — recovery may not be possible.");
            }
            if field("Mounted").as_deref() == Some("Yes") {
                println!("WARNING: The source volume is currently MOUNTED. Live writes can overwrite recoverable data at any moment. For best results, unmount it or scan from an external boot / Target Disk Mode.");
            }
        }
    }
    // Boot-disk check: is the source the disk the running system lives on?
    if let (Some(src_base), Some(boot_base)) = (base_disk_of(device), boot_disk()) {
        if src_base == boot_base {
            println!("WARNING: The source appears to be the LIVE BOOT DISK ({boot_base}). Scanning the running system disk is the worst case for recovery — every running process may overwrite deleted data. Strongly consider booting from an external drive instead.");
        }
    }
}

/// Explicit confirmation: the user must type exactly "YES" (not y/Y).
/// --force skips the prompt (warnings were already displayed regardless).
pub fn confirm_or_abort(force: bool) -> Result<(), CarveError> {
    if force {
        return Ok(());
    }
    eprint!("\nType YES (uppercase) to proceed: ");
    io::stderr().flush().ok();
    let mut line = String::new();
    let n = io::stdin()
        .read_line(&mut line)
        .map_err(|e| CarveError::Io {
            path: "<stdin>".into(),
            source: e,
        })?;
    if n == 0 {
        eprintln!("\n(no input on stdin — use --force for non-interactive/scripted use)");
        return Err(CarveError::Aborted);
    }
    if line.trim() == "YES" {
        Ok(())
    } else {
        Err(CarveError::Aborted)
    }
}

/// Same-physical-disk enforcement. For real devices this ABORTS the run when
/// the output is on the source disk. For image files (used with --allow-file)
/// the source is just a file, so a same-filesystem output cannot overwrite
/// recoverable device data — warn but allow.
pub fn check_same_disk(source: &str, kind: SourceKind, output: &Path) -> Result<(), CarveError> {
    let out_anchor = existing_ancestor(output);
    match kind {
        SourceKind::ImageFile => {
            let same = std::fs::metadata(source)
                .ok()
                .zip(std::fs::metadata(&out_anchor).ok())
                .map(|(s, o)| {
                    use std::os::unix::fs::MetadataExt;
                    s.dev() == o.dev()
                })
                .unwrap_or(false);
            if same {
                println!("NOTE: the disk-image file and the output directory are on the same filesystem. This is safe for image files (the source is an ordinary file), but for real device scans this would be refused.");
            }
            Ok(())
        }
        SourceKind::Device => {
            let src_base = base_disk_of(source);
            let out_base = df_filesystem(&out_anchor).and_then(|fs| base_disk_of(&fs));
            let name_match = src_base.is_some() && src_base == out_base;
            let dev_match = match (device_number_of_source(source), device_number_of_fs(&out_anchor))
            {
                (Some(rdev), Some(out_dev)) => rdev != 0 && rdev == out_dev,
                _ => false,
            };
            if name_match || dev_match {
                return Err(CarveError::SameDisk {
                    device: source.to_string(),
                    output: output.display().to_string(),
                });
            }
            if src_base.is_none() || out_base.is_none() {
                println!("WARNING: could not fully verify that the output disk differs from the source disk. Double-check this yourself before proceeding — writing to the source disk destroys recoverable data.");
            }
            Ok(())
        }
    }
}

fn existing_ancestor(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    while !cur.exists() {
        if !cur.pop() {
            break;
        }
    }
    cur
}

/// "/dev/rdisk2s1" -> "disk2", "/dev/disk3s1s1" -> "disk3".
fn base_disk_of(dev_path: &str) -> Option<String> {
    let name = dev_path.rsplit('/').next()?;
    let name = name.strip_prefix('r').unwrap_or(name);
    let rest = name.strip_prefix("disk")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("disk{digits}"))
    }
}

fn df_filesystem(path: &Path) -> Option<String> {
    let out = Command::new("df")
        .arg("-P")
        .arg(path)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .last()
        .and_then(|l| l.split_whitespace().next())
        .map(|s| s.to_string())
}

fn boot_disk() -> Option<String> {
    df_filesystem(Path::new("/")).and_then(|fs| base_disk_of(&fs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base_disk_names() {
        assert_eq!(base_disk_of("/dev/rdisk2s1").as_deref(), Some("disk2"));
        assert_eq!(base_disk_of("/dev/disk3s1s1").as_deref(), Some("disk3"));
        assert_eq!(base_disk_of("/dev/disk10").as_deref(), Some("disk10"));
        assert_eq!(base_disk_of("/dev/rdisk2"), base_disk_of("/dev/disk2s7"));
        assert_eq!(base_disk_of("/tmp/image.dmg"), None);
    }
}
