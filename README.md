# file-recovery

A **READ-ONLY** file carving tool for macOS, written in Rust. It scans raw disk
blocks (`/dev/rdisk*`) for file signatures (magic numbers) and reconstructs
deleted files onto a **separate** disk. Built for recovering your **own**
deleted files from APFS volumes — but it works on any raw block device.

## Safety design (read this first)

The tool is read-only **by design**, not by policy:

- The source device is opened with `O_RDONLY` only, and the open flags are
  **verified at runtime** via `fcntl(F_GETFL)`. If the descriptor is not
  read-only, the tool refuses to continue.
- The only operations ever issued against the source are positioned reads
  (`pread`-style). There is no `write`, `pwrite`, `fsync`, `truncate`,
  `unlink`, `rename`, or write-ioctl call anywhere in the codebase.
- Carving means **copying bytes out** — never cutting or moving.
- Before any scan, the tool verifies that the output directory is on a
  **different physical disk** than the source (by device name and device
  number). If they match, it **aborts** — writing to the source disk could
  overwrite the very data you are trying to recover.
- Every run ends by confirming that the source was not modified.

Before doing anything, the tool displays these warnings and requires you to
type exactly `YES` (uppercase) to proceed (`--force` skips the prompt for
scripting, but the warnings are always shown):

```
WARNING: This tool reads raw disk data. Use at your own risk.
WARNING: For best results, the source disk should not be actively in use (consider booting from an external drive or using Target Disk Mode).
WARNING: If FileVault is enabled, deleted file content may be encrypted and unrecoverable without keys.
WARNING: SSDs with TRIM enabled may have already permanently zeroed deleted blocks — recovery may not be possible.
WARNING: Do not write recovered files to the same disk you are scanning — this can overwrite recoverable data.
This tool is READ-ONLY and will not modify the source disk in any way.
```

**What this tool will NOT do:**

- delete any files or data
- modify the source disk
- attempt to repair file system corruption
- bypass FileVault encryption
- access system-protected volumes without explicit user consent
- recover files to the same disk being scanned
- run without root/sudo for raw devices (and it explains why when missing)

**Legal & ethical disclaimers:**

- This tool is for recovering **your own** deleted files.
- Unauthorized access to another person's data may be **illegal**.
- You are responsible for complying with all applicable laws.
- This tool comes with **NO WARRANTY** — recovery is not guaranteed.
- Use may violate evidence-preservation standards if the data is involved in
  legal proceedings. If the disk is evidence, stop and use a forensic
  workflow instead.

## Why root/sudo is required

Raw block devices (`/dev/rdisk*`, `/dev/disk*`) are protected by macOS —
opening them without root fails with `EPERM`. The tool checks this up front
and tells you exactly what to run. Scanning a regular disk-image file with
`--allow-file` does **not** require root.

## Build

```sh
cargo build --release
# binary at target/release/file-recovery
```

Targets macOS on both arm64 and x86_64. Requires a recent stable Rust.

## Usage

```sh
# Typical: external USB disk (disk2), recover everything to another drive
sudo file-recovery --device /dev/rdisk2 --output /Volumes/External/recovered

# Only photos and documents, organized into per-type subdirectories
sudo file-recovery --device /dev/rdisk2s1 --output /Volumes/External/rec \
    --types jpg,png,pdf --organize

# Preview what would be carved, writing nothing (no confirmation needed with --force)
sudo file-recovery --device /dev/rdisk2 --output /Volumes/External/rec --dry-run --force

# Scan a disk image instead of a live device (no root needed)
file-recovery --device image.dmg --output ./rec --allow-file

# Scripted use (still displays all warnings)
sudo file-recovery --device /dev/rdisk2 --output /Volumes/External/rec --force -q
```

### Options

| Flag | Default | Meaning |
|---|---|---|
| `--device <path>` | (required) | Source: `/dev/rdisk2s1` (partition), `/dev/rdisk2` (whole disk), or an image file with `--allow-file` |
| `--output <dir>` | (required) | Output directory — **must** be on a different physical disk (verified) |
| `--types <list>` | all | Comma-separated types, e.g. `jpg,png,pdf` (see `--list-types`) |
| `--block-size <bytes>` | `4096` | Device read granularity (accepts `4K`/`4KB` style suffixes) |
| `--max-size <bytes>` | `100MB` | Per-file cap for formats without size info; also the footer-search ceiling |
| `--organize` | off | Sort recovered files into per-type subdirectories |
| `--dry-run` | off | Scan and report only — save nothing |
| `--verbose` / `-v` | off | List every planned carve (offset, size, type) |
| `--quiet` / `-q` | off | No progress bar (warnings and summary still shown) |
| `--log-file <path>` | `<output>/recovery_log.json` | JSON recovery log destination (verified not to be on the source disk) |
| `--force` | off | Skip the interactive `YES` confirmation (warnings still shown) |
| `--allow-file` | off | Permit a regular disk-image file as the source |
| `--list-types` | — | Print supported file types and the signature database |

### Supported types

`jpg png pdf gif mp4 mov zip docx xlsx pptx mp3 wav sqlite bmp tiff rar 7z gz bz2 plist`

Signatures carried by the database (see `src/signatures.rs`):

- **JPEG** `FF D8 FF` (covers the E0/E1/E8 variants) with `FF D9` footer; the
  APP marker (JFIF/Exif) is validated to reject false positives
- **PNG** `89 50 4E 47 0D 0A 1A 0A` with `IEND` footer
- **PDF** `%PDF-` with `%%EOF` footer
- **GIF** `GIF87a`/`GIF89a` — size from a real block walk to the `0x3B` trailer
- **MP4/MOV** `ftyp` boxes — brand-validated (`qt` → mov), size from walking
  the top-level atom chain
- **ZIP** `50 4B 03 04` with end-of-central-directory footer; **DOCX/XLSX/PPTX**
  classified by content (`[Content_Types].xml`, `word/`, `xl/`, `ppt/`)
- **MP3** ID3v2 tags (syncsafe-validated)
- **WAV** `RIFF` + `WAVE` validated, RIFF size field (AVI etc. rejected)
- **SQLite** `SQLite format 3\0`, size = page_size × page_count from the header
- **BMP** `BM` with strict validation (reserved bytes, DIB size), size field
- **TIFF** `49 49 2A 00` / `4D 4D 00 2A` with sane-IFD validation
- **RAR** 4.x and 5.x markers, **7z** (size from next-header offset+size),
  **GZIP** `1F 8B` (validated), **BZ2** `BZh` (validated), **bplist00**

Formats with footers or internal size info are carved to their real end.
Formats with neither (mp3, tiff, rar, gz, bz2, plist) are carved up to
`--max-size` and marked `truncated` in the log.

## How it works

1. **Scan** (`src/scanner.rs`) — streams the source in 64 MB chunks
   (read-only `pread`), matching all active signatures via a first-byte index;
   chunk-boundary-spanning matches are caught with a carry overlap. I/O errors
   never abort: failed chunks are retried block-by-block, unrecoverable blocks
   are skipped and reported in the summary and log.
2. **Plan** (`src/carver.rs`) — every candidate header is validated with small
   positioned reads (parallelized with rayon, still read-only), its size is
   determined from a footer / internal size info / the `--max-size` cap, and
   overlapping same-type hits are deduplicated (a signature inside an
   already-carved file's range is not carved twice).
3. **Carve** (`src/carver.rs`, `src/output.rs`) — each planned range is copied
   out in 1 MB chunks to uniquely named files (`recovered_0001.jpg`, …),
   optionally organized per type. Zero-length results are discarded; if the
   output disk fills up, recovery stops gracefully and reports.
4. **Log** — `recovery_log.json` records offset, size, type, truncation flag,
   and timestamp for every carved file, plus run metadata (including
   `opened_read_only: true`) and any errors.

## Limitations (read before trusting the output)

- **Fragmentation**: carving assumes contiguous storage. APFS may scatter a
  file across non-adjacent blocks; such files come out corrupt or partial.
  There is no way around this with pure block carving.
- **FileVault**: with FileVault on, raw blocks are encrypted — carved bytes
  are ciphertext. The tool detects FileVault via `diskutil info` and warns.
- **SSD/TRIM**: deleted blocks on SSDs are often zeroed quickly and are
  unrecoverable, period. The tool warns on solid-state devices.
- **Live disks**: scanning a mounted/in-use disk means the data can change
  mid-scan and new writes may overwrite deleted data. Best results come from
  an unmounted disk, an external boot, or Target Disk Mode. The tool warns
  for mounted volumes and for the live boot disk.
- **False positives**: short signatures (gz, bz2, RIFF, ID3) occur naturally
  in unrelated data. Validators reject most of these, but some junk carves
  are inevitable — use `--types` to narrow down and `--dry-run` to preview.
- **JPEG thumbnails**: an embedded thumbnail's `FF D9` can truncate a carved
  JPEG early; hits smaller than a sane minimum are skipped, but some
  truncation may remain.
- **MP3 without ID3** tags (bare frame sync) is not detected — the `FF Ex`
  pattern produces far too many false positives to be useful.

## Performance notes

The scan is sequential and I/O-bound: signatures are matched in a single pass
with a first-byte index, so disk read speed dominates. Validation/planning is
parallelized across hits with rayon (positioned reads only). On an NVMe Mac,
expect the scan phase to run at roughly raw read speed of the source device.

## Project layout

```
src/
  main.rs        CLI entry point, argument parsing, confirmation flow
  disk.rs        READ-ONLY raw disk reading, block device access
  signatures.rs  File signature database
  scanner.rs     Core scanning logic
  carver.rs      File carving and extraction (copy, never move)
  output.rs      Output file management (separate disk verification)
  progress.rs    Progress reporting
  safety.rs      Safety checks, warnings, disk verification
  error.rs       Custom error types (thiserror)
tests/
  end_to_end.rs  Carves a synthetic image via the real CLI and verifies
                 the source is byte-for-byte unchanged afterwards
```

## Testing

```sh
cargo test
```

Unit tests cover the signature database, chunk-boundary scanning, all size
parsers (GIF/MP4/SQLite/7z/WAV/BMP), ZIP classification, and deduplication.
Integration tests build a synthetic 4 MB "disk" with embedded files at known
offsets, run the real binary against it, verify the carved bytes match the
embedded ones exactly, and verify the **source image is unchanged
byte-for-byte** afterwards — the read-only contract, tested.

## License

MIT. No warranty of any kind — see above.
