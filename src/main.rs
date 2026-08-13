//! file-recovery — READ-ONLY file carving for macOS raw disks.
//!
//! Flow: parse args → mandatory warnings → environment warnings → same-disk
//! ABORT check → explicit YES confirmation → open source O_RDONLY (verified)
//! → scan → plan → carve to a SEPARATE disk → JSON log → summary.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use clap::Parser;

use file_recovery::carver;
use file_recovery::disk::{self, RawDisk, SourceKind};
use file_recovery::error::CarveError;
use file_recovery::output::{write_log, LogEntry, OutputManager, RunLog, TypeCount};
use file_recovery::progress::Reporter;
use file_recovery::safety;
use file_recovery::scanner;
use file_recovery::signatures;

const ABOUT: &str = "READ-ONLY file carving tool for macOS raw disks (APFS and other block devices). \
Scans raw disk blocks for file signatures and reconstructs deleted files onto a SEPARATE disk. \
The source device is opened O_RDONLY (verified at runtime) and is never written to, modified, \
truncated, or repaired in any way.";

const LONG_ABOUT: &str = "\
READ-ONLY file carving tool for macOS raw disks.

WHAT THIS TOOL WILL NOT DO:
  - delete any files or data
  - modify the source disk (opened O_RDONLY and verified at runtime)
  - attempt to repair file system corruption
  - bypass FileVault encryption
  - access system-protected volumes without explicit user consent
  - recover files to the same disk being scanned (verified and refused)
  - run without root/sudo for raw devices

LEGAL & ETHICAL TERMS:
  This tool is for recovering your OWN deleted files. Unauthorized access to
  another person's data may be illegal. You are responsible for complying
  with all applicable laws. This tool comes with NO WARRANTY — recovery is
  not guaranteed. Use may violate evidence-preservation standards if the
  data is involved in legal proceedings.

EXAMPLES:
  sudo file-recovery --device /dev/rdisk2 --output /Volumes/External/recovered
  sudo file-recovery --device /dev/rdisk2s1 --output /Volumes/External/rec --types jpg,png,pdf --organize
  file-recovery --device image.dmg --output ./rec --allow-file   # disk image, no root needed
  sudo file-recovery --device /dev/rdisk2 --output /Volumes/External/rec --dry-run --force";

#[derive(Parser)]
#[command(name = "file-recovery", version, about = ABOUT, long_about = LONG_ABOUT)]
struct Cli {
    /// Source device or image: /dev/rdisk2s1 (partition), /dev/rdisk2 (whole disk),
    /// or a disk-image file (requires --allow-file).
    #[arg(long, required_unless_present = "list_types")]
    device: Option<String>,

    /// Output directory for recovered files — MUST be on a different physical
    /// disk than the source (verified; the run aborts otherwise).
    #[arg(long, required_unless_present = "list_types")]
    output: Option<String>,

    /// Comma-separated file types to recover (see --list-types). Default: all.
    #[arg(long)]
    types: Option<String>,

    /// Device read granularity in bytes (accepts K/M/G suffixes, e.g. 4K).
    #[arg(long, default_value = "4096", value_parser = parse_size)]
    block_size: u64,

    /// Max bytes carved per file for formats without size info; also the hard
    /// ceiling for footer search (accepts K/M/G suffixes, e.g. 100MB).
    #[arg(long, default_value = "100MB", value_parser = parse_size)]
    max_size: u64,

    /// Organize recovered files into per-type subdirectories.
    #[arg(long)]
    organize: bool,

    /// Scan and report only — do not save any recovered files (writes nothing,
    /// unless --log-file is explicitly given).
    #[arg(long)]
    dry_run: bool,

    /// Verbose output: list every planned carve (offset, size, type).
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Minimal output: no progress bar (warnings and summary still shown).
    #[arg(short, long)]
    quiet: bool,

    /// Write the JSON recovery log to this path (default: <output>/recovery_log.json).
    /// Must not be on the source disk — verified.
    #[arg(long)]
    log_file: Option<String>,

    /// Skip the interactive YES confirmation (for scripting). Safety warnings
    /// are still displayed.
    #[arg(long)]
    force: bool,

    /// Allow the source to be a regular disk-image file instead of a device.
    #[arg(long)]
    allow_file: bool,

    /// List supported file types and exit.
    #[arg(long)]
    list_types: bool,
}

fn parse_size(s: &str) -> Result<u64, String> {
    let lower = s.trim().to_ascii_lowercase();
    let (digits, mult) = if let Some(p) = lower.strip_suffix("kb") {
        (p, 1024u64)
    } else if let Some(p) = lower.strip_suffix("mb") {
        (p, 1024 * 1024)
    } else if let Some(p) = lower.strip_suffix("gb") {
        (p, 1024 * 1024 * 1024)
    } else if let Some(p) = lower.strip_suffix('k') {
        (p, 1024)
    } else if let Some(p) = lower.strip_suffix('m') {
        (p, 1024 * 1024)
    } else if let Some(p) = lower.strip_suffix('g') {
        (p, 1024 * 1024 * 1024)
    } else if let Some(p) = lower.strip_suffix('b') {
        (p, 1)
    } else {
        (lower.as_str(), 1)
    };
    digits
        .trim()
        .parse::<u64>()
        .map(|v| v * mult)
        .map_err(|_| format!("invalid size '{s}' (use bytes or a K/M/G/KB/MB/GB suffix)"))
}

fn fmt_bytes(n: u64) -> String {
    const G: u64 = 1024 * 1024 * 1024;
    const M: u64 = 1024 * 1024;
    const K: u64 = 1024;
    if n >= G {
        format!("{:.2} GB", n as f64 / G as f64)
    } else if n >= M {
        format!("{:.2} MB", n as f64 / M as f64)
    } else if n >= K {
        format!("{:.2} KB", n as f64 / K as f64)
    } else {
        format!("{n} B")
    }
}

fn list_types() {
    println!("Supported --types values:\n");
    println!("  jpg png pdf gif mp4 mov zip docx xlsx pptx mp3 wav sqlite bmp tiff rar 7z gz bz2 plist\n");
    println!("Signature database:");
    for s in signatures::database() {
        let display = if s.name == "ftyp" { "mp4/mov" } else { s.name };
        println!(
            "  {:7} header {:<24} footer {:<10} max {:>9} {}",
            display,
            hex(s.header),
            s.footer.map(hex).unwrap_or_else(|| "-".into()),
            fmt_bytes(s.max_size),
            if s.has_internal_size {
                "(internal size)"
            } else {
                "(size cap only)"
            }
        );
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\n{e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.list_types {
        list_types();
        return Ok(());
    }

    let db = signatures::database();

    // --- type filter ---
    let valid = signatures::valid_type_names();
    let filter: Option<HashSet<String>> = match &cli.types {
        None => None,
        Some(list) => {
            let mut set = HashSet::new();
            let mut bad = Vec::new();
            for t in list.split(',').map(|t| t.trim().to_ascii_lowercase()) {
                if valid.iter().any(|v| *v == t) {
                    set.insert(t);
                } else {
                    bad.push(t);
                }
            }
            if !bad.is_empty() {
                return Err(CarveError::UnknownTypes(bad.join(", ")).into());
            }
            if set.is_empty() {
                return Err(anyhow!("--types given but empty"));
            }
            Some(set)
        }
    };

    // --- root enforcement for raw devices (before anything else) ---
    let device = cli
        .device
        .clone()
        .ok_or_else(|| anyhow!("--device is required"))?;
    let output = cli
        .output
        .clone()
        .ok_or_else(|| anyhow!("--output is required"))?;
    let meta = std::fs::metadata(&device)
        .with_context(|| format!("cannot stat source {device}"))?;
    let kind = disk::detect_kind(&meta, &device, cli.allow_file)?;
    if kind == SourceKind::Device && !safety::is_root() {
        return Err(anyhow!(safety::root_explanation(&device)));
    }

    // --- mandatory warnings, always shown ---
    safety::print_warnings(&device, &output);
    safety::environment_warnings(&device, kind);

    // --- output location + same-physical-disk ABORT check ---
    let out_root = PathBuf::from(&output);
    if !cli.dry_run {
        std::fs::create_dir_all(&out_root)
            .with_context(|| format!("cannot create output directory {}", out_root.display()))?;
    }
    safety::check_same_disk(&device, kind, &out_root)?;
    let log_path = cli.log_file.as_ref().map(PathBuf::from);
    if let Some(lp) = &log_path {
        safety::check_same_disk(&device, kind, lp.parent().unwrap_or(&out_root))?;
    }

    // --- explicit confirmation ---
    safety::confirm_or_abort(cli.force)?;

    // --- open source strictly read-only ---
    let disk = RawDisk::open(&device, cli.allow_file)?;
    if !cli.quiet {
        println!(
            "\nOpened {} read-only (O_RDONLY, verified) — {} ({})",
            disk.path,
            fmt_bytes(disk.size),
            disk.size
        );
        println!(
            "Types: {}",
            match &filter {
                None => "all".to_string(),
                Some(f) => {
                    let mut v: Vec<_> = f.iter().cloned().collect();
                    v.sort();
                    v.join(",")
                }
            }
        );
    }

    // --- scan ---
    let active = active_signatures(db, &filter);
    let chunk_size = (64 * 1024 * 1024u64).max(cli.block_size) / cli.block_size * cli.block_size;
    let bar = Reporter::new(disk.size, cli.quiet, "Scan ");
    let t0 = Instant::now();
    let scan = scanner::scan(&disk, disk.size, cli.block_size, chunk_size, db, &active, |done, found| {
        bar.set(done);
        bar.message(format!("{found} candidates"));
    });
    bar.finish("scan complete");

    // --- plan carves (validation + size parsing, parallel, read-only) ---
    let plans = carver::plan_carves(&disk, disk.size, &scan, db, cli.max_size, &filter);
    if cli.verbose {
        for p in &plans {
            println!(
                "  plan: {:>12} {:>12} {:>6} {}",
                p.offset,
                fmt_bytes(p.size),
                p.type_name,
                if p.truncated { "(truncated)" } else { "" }
            );
        }
    }

    // --- carve ---
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut entries: Vec<LogEntry> = Vec::new();
    let mut counts: BTreeMap<String, TypeCount> = BTreeMap::new();
    let mut errors: Vec<String> = scan.errors.clone();
    let mut total_bytes = 0u64;
    let mut truncated_count = 0u64;

    if cli.dry_run {
        for p in &plans {
            let c = counts.entry(p.type_name.clone()).or_insert(TypeCount { files: 0, bytes: 0 });
            c.files += 1;
            c.bytes += p.size;
            total_bytes += p.size;
            if p.truncated {
                truncated_count += 1;
            }
        }
        // Always shown, even in --quiet mode: this is the core dry-run result.
        println!(
            "\nDry run: {} files would be carved ({}). Nothing was written.",
            plans.len(),
            fmt_bytes(total_bytes)
        );
    } else {
        let mut om = OutputManager::prepare(out_root.clone(), cli.organize)
            .context("cannot prepare output directory")?;
        let carve_total: u64 = plans.iter().map(|p| p.size).sum();
        let cbar = Reporter::new(carve_total, cli.quiet, "Carve");
        'carve: for p in &plans {
            match om.save(&disk, p) {
                Ok(path) => {
                    if cli.verbose {
                        cbar.note(&format!(
                            "  carved {} <- offset {} ({})",
                            path.display(),
                            p.offset,
                            p.type_name
                        ));
                    }
                    cbar.inc(p.size);
                    let c = counts.entry(p.type_name.clone()).or_insert(TypeCount { files: 0, bytes: 0 });
                    c.files += 1;
                    c.bytes += p.size;
                    total_bytes += p.size;
                    if p.truncated {
                        truncated_count += 1;
                    }
                    entries.push(LogEntry {
                        file: path.display().to_string(),
                        offset: p.offset,
                        size: p.size,
                        type_name: p.type_name.clone(),
                        truncated: p.truncated,
                        timestamp_unix: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    });
                }
                Err(CarveError::DiskFull(m)) => {
                    errors.push(format!("output disk full at {m} — recovery stopped early"));
                    eprintln!("\nERROR: output disk full — stopping recovery gracefully.");
                    break 'carve;
                }
                Err(e) => {
                    errors.push(format!("offset {} ({}): {e}", p.offset, p.type_name));
                    continue 'carve; // log and continue, never panic
                }
            }
        }
        cbar.finish("carve complete");
    }

    let duration = t0.elapsed().as_secs_f64();

    // --- recovery log (never written in dry-run unless explicitly requested) ---
    let log_written_to = if !cli.dry_run || cli.log_file.is_some() {
        let path = log_path.unwrap_or_else(|| out_root.join("recovery_log.json"));
        if cli.dry_run {
            entries = plans
                .iter()
                .map(|p| LogEntry {
                    file: format!("(not written — dry run) would-be .{}", p.extension),
                    offset: p.offset,
                    size: p.size,
                    type_name: p.type_name.clone(),
                    truncated: p.truncated,
                    timestamp_unix: started,
                })
                .collect();
        }
        let log = RunLog {
            tool: "file-recovery".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            source_device: disk.path.clone(),
            source_size_bytes: disk.size,
            opened_read_only: true,
            dry_run: cli.dry_run,
            started_unix: started,
            duration_secs: duration,
            total_files: entries.len(),
            total_bytes,
            counts_by_type: counts.clone(),
            errors: errors.clone(),
            entries,
        };
        match write_log(&path, &log) {
            Ok(()) => Some(path),
            Err(e) => {
                errors.push(format!("could not write recovery log: {e}"));
                eprintln!("WARNING: could not write recovery log to {}: {e}", path.display());
                None
            }
        }
    } else {
        None
    };

    // --- summary ---
    println!("\n=================== SUMMARY ===================");
    println!("Scan duration:     {duration:.1}s");
    println!("Bytes scanned:     {} ({})", fmt_bytes(scan.bytes_scanned), scan.bytes_scanned);
    println!(
        "Files {}:  {}",
        if cli.dry_run { "found" } else { "recovered" },
        counts.values().map(|c| c.files).sum::<u64>()
    );
    println!(
        "Bytes {}:  {}",
        if cli.dry_run { "found" } else { "recovered" },
        fmt_bytes(total_bytes)
    );
    if !counts.is_empty() {
        println!("By type:");
        for (name, c) in &counts {
            println!("  {name:8} {:>5} files, {}", c.files, fmt_bytes(c.bytes));
        }
    }
    if truncated_count > 0 {
        println!("Truncated files:   {truncated_count} (hit the --max-size cap or disk end; raise --max-size to retry larger)");
    }
    if errors.is_empty() {
        println!("Errors:            none");
    } else {
        println!("Errors:            {} (see recovery log)", errors.len());
        for e in errors.iter().take(5) {
            println!("  - {e}");
        }
    }
    if let Some(p) = log_written_to {
        println!("Recovery log:      {}", p.display());
    }
    println!();
    println!("Source disk was opened read-only (O_RDONLY, verified at runtime)");
    println!("and was NOT modified in any way.");
    println!("==============================================");
    Ok(())
}

/// Signature indices to scan for: everything, or the filter plus its aliases
/// (zip also covers docx/xlsx/pptx; ftyp covers mp4/mov).
fn active_signatures(db: &[signatures::Signature], filter: &Option<HashSet<String>>) -> Vec<usize> {
    db.iter()
        .enumerate()
        .filter_map(|(i, s)| match filter {
            None => Some(i),
            Some(f) => {
                let wanted = match s.name {
                    "zip" => ["zip", "docx", "xlsx", "pptx"].iter().any(|t| f.contains(*t)),
                    "ftyp" => f.contains("mp4") || f.contains("mov"),
                    n => f.contains(n),
                };
                if wanted {
                    Some(i)
                } else {
                    None
                }
            }
        })
        .collect()
}
