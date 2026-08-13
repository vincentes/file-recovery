//! End-to-end: build a synthetic "disk" image with embedded files at known
//! offsets, run the real CLI against it (--allow-file so no root is needed),
//! and verify the carved output — including that the source image is byte-
//! for-byte unchanged afterwards (the read-only contract).

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "file-recovery-test-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn jpeg_bytes() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    v.extend_from_slice(b"JFIF\0");
    v.extend_from_slice(&[0xAA; 2000]);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn png_bytes() -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&[0xBB; 500]);
    v.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]); // IEND+CRC
    v
}

fn pdf_bytes() -> Vec<u8> {
    let mut v = b"%PDF-1.7\n".to_vec();
    v.extend_from_slice(&[0x43; 900]);
    v.extend_from_slice(b"%%EOF");
    v
}

fn sqlite_image() -> Vec<u8> {
    // page_size 512 * 4 pages = 2048 bytes total
    let mut v = vec![0u8; 2048];
    v[..16].copy_from_slice(b"SQLite format 3\0");
    v[16..18].copy_from_slice(&512u16.to_be_bytes());
    v[18] = 1;
    v[19] = 1;
    v[28..32].copy_from_slice(&4u32.to_be_bytes());
    v
}

fn mp4_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&24u32.to_be_bytes());
    v.extend_from_slice(b"ftypisom");
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&40u32.to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(&[0x55; 32]);
    v
}

fn docx_bytes() -> Vec<u8> {
    // minimal zip: local header + EOCD, with office markers in the tail window
    let mut v = Vec::new();
    v.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    v.extend_from_slice(&20u16.to_le_bytes()); // version
    v.extend_from_slice(&0u16.to_le_bytes()); // flags
    v.extend_from_slice(&0u16.to_le_bytes()); // method = stored
    v.extend_from_slice(&[0; 16]); // time/date/crc/sizes
    v.extend_from_slice(&5u16.to_le_bytes()); // name len
    v.extend_from_slice(&0u16.to_le_bytes()); // extra len
    v.extend_from_slice(b"a.txt");
    v.extend_from_slice(&[0x44; 700]); // payload padding
    v.extend_from_slice(b"[Content_Types].xml ... word/document.xml");
    v.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD
    v.extend_from_slice(&[0; 18]); // rest of EOCD (comment len 0)
    v
}

fn build_image() -> (Vec<u8>, Vec<(u64, &'static str, Vec<u8>)>) {
    let files: Vec<(u64, &'static str, Vec<u8>)> = vec![
        (0x1000, "jpg", jpeg_bytes()),
        (0x100000, "png", png_bytes()),
        (0x180000, "pdf", pdf_bytes()),
        (0x200000, "sqlite", sqlite_image()),
        (0x280000, "mp4", mp4_bytes()),
        (0x300000, "docx", docx_bytes()),
    ];
    let mut img = vec![0u8; 4 * 1024 * 1024];
    for (off, _, bytes) in &files {
        img[*off as usize..*off as usize + bytes.len()].copy_from_slice(bytes);
    }
    (img, files)
}

fn run_cli(args: &[&str], stdin_text: Option<&str>) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_file-recovery"));
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_text.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(text) = stdin_text {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn carves_all_types_end_to_end_and_leaves_source_untouched() {
    let dir = tmpdir("e2e");
    let img_path = dir.join("image.dmg");
    let out_dir = dir.join("recovered");
    let (img, files) = build_image();
    fs::write(&img_path, &img).unwrap();

    let out = run_cli(
        &[
            "--device",
            img_path.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--allow-file",
            "--force",
            "--quiet",
            "--organize",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for (_, ext, bytes) in &files {
        let sub = out_dir.join(ext);
        assert!(sub.is_dir(), "missing type dir {}", sub.display());
        let carved: Vec<_> = fs::read_dir(&sub)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("recovered_"))
            .collect();
        assert_eq!(carved.len(), 1, "expected exactly one {ext} file");
        let data = fs::read(carved[0].path()).unwrap();
        assert_eq!(
            data.len(),
            bytes.len(),
            "carved {ext} has wrong size ({} vs {})",
            data.len(),
            bytes.len()
        );
        assert_eq!(&data, bytes, "carved {ext} bytes differ from embedded");
    }

    // recovery log
    let log_path = out_dir.join("recovery_log.json");
    let log: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&log_path).unwrap()).unwrap();
    assert_eq!(log["opened_read_only"], true);
    assert_eq!(log["total_files"], 6);
    assert_eq!(log["counts_by_type"]["docx"]["files"], 1);

    // READ-ONLY CONTRACT: source image must be byte-for-byte unchanged.
    let after = fs::read(&img_path).unwrap();
    assert_eq!(after, img, "source image was modified!");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn type_filter_limits_what_is_carved() {
    let dir = tmpdir("filter");
    let img_path = dir.join("image.dmg");
    let out_dir = dir.join("recovered");
    let (img, _) = build_image();
    fs::write(&img_path, &img).unwrap();

    let out = run_cli(
        &[
            "--device",
            img_path.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--allow-file",
            "--force",
            "--quiet",
            "--types",
            "jpg",
        ],
        None,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let recovered: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("recovered_"))
        .collect();
    assert_eq!(recovered.len(), 1);
    assert!(recovered[0].file_name().to_string_lossy().ends_with(".jpg"));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn dry_run_writes_nothing() {
    let dir = tmpdir("dry");
    let img_path = dir.join("image.dmg");
    let out_dir = dir.join("recovered");
    let (img, _) = build_image();
    fs::write(&img_path, &img).unwrap();

    let out = run_cli(
        &[
            "--device",
            img_path.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--allow-file",
            "--force",
            "--quiet",
            "--dry-run",
        ],
        None,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Dry run"), "stdout: {stdout}");
    // Dry run must not create the output directory or any recovered files.
    assert!(!out_dir.exists() || fs::read_dir(&out_dir).unwrap().count() == 0);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn confirmation_requires_exact_yes() {
    let dir = tmpdir("confirm");
    let img_path = dir.join("image.dmg");
    let out_dir = dir.join("recovered");
    let (img, _) = build_image();
    fs::write(&img_path, &img).unwrap();

    // "yes" lowercase must be rejected.
    let out = run_cli(
        &[
            "--device",
            img_path.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--allow-file",
            "--quiet",
        ],
        Some("yes\n"),
    );
    assert!(!out.status.success(), "lowercase 'yes' must be rejected");

    // Exact "YES" must be accepted.
    let out = run_cli(
        &[
            "--device",
            img_path.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--allow-file",
            "--quiet",
        ],
        Some("YES\n"),
    );
    assert!(
        out.status.success(),
        "exact YES must be accepted: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn refuses_regular_file_without_allow_file() {
    let dir = tmpdir("refuse");
    let img_path = dir.join("image.dmg");
    let out_dir = dir.join("recovered");
    let (img, _) = build_image();
    fs::write(&img_path, &img).unwrap();

    let out = run_cli(
        &[
            "--device",
            img_path.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--force",
            "--quiet",
        ],
        None,
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a block/character device"), "stderr: {stderr}");
    fs::remove_dir_all(&dir).ok();
}
