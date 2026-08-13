//! File carving: turn raw signature hits into concrete recovery plans
//! (offset + size + type), then *copy* those byte ranges out to the output
//! manager. Carving never modifies the source — it is copy, not cut.
//!
//! Size determination order per hit:
//!   1. format-specific internal-size parser (GIF block walk, MP4 atom walk,
//!      SQLite header, 7z header, RIFF/BMP size fields),
//!   2. first matching footer after the header (JPEG/PNG/PDF/ZIP),
//!   3. the max-size cap (formats with neither size info nor footer).
//!
//! Hits that fail format validation are dropped as false positives; hits of
//! the same type overlapping an already-planned carve are deduplicated.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use rayon::prelude::*;

use crate::disk::ReadAt;
use crate::scanner::ScanResult;
use crate::signatures::{Signature, SizeParser, Validator};

#[derive(Debug, Clone)]
pub struct CarvePlan {
    pub offset: u64,
    pub size: u64,
    /// Resolved type name: jpg, png, ..., mp4/mov, zip/docx/xlsx/pptx.
    pub type_name: String,
    pub extension: String,
    /// True when the file was cut off by the size cap (or disk end) rather
    /// than terminated by a footer/parsed size — likely incomplete.
    pub truncated: bool,
}

const COPY_BUF: usize = 1024 * 1024;

pub fn plan_carves(
    reader: &dyn ReadAt,
    disk_size: u64,
    scan: &ScanResult,
    sigs: &[Signature],
    max_size: u64,
    filter: &Option<HashSet<String>>,
) -> Vec<CarvePlan> {
    let mut footers_by_sig: HashMap<usize, Vec<u64>> = HashMap::new();
    for &(f, si) in &scan.footers {
        footers_by_sig.entry(si).or_default().push(f);
    }
    for v in footers_by_sig.values_mut() {
        v.sort_unstable();
    }

    // Validation and size parsing do small independent positioned reads, so
    // they parallelize well across hits (all read-only).
    let mut plans: Vec<CarvePlan> = scan
        .headers
        .par_iter()
        .filter_map(|&(off, si)| plan_one(reader, disk_size, off, si, sigs, &footers_by_sig, max_size, filter))
        .collect();

    plans.sort_by_key(|p| p.offset);

    // Deduplicate per resolved type: a header landing inside the byte range
    // of an already-planned file of the same type is almost always signature
    // bytes occurring inside that file's data, not a new file. Cross-type
    // overlaps are kept (they recover files embedded in other files).
    let mut last_end: HashMap<String, u64> = HashMap::new();
    plans.retain(|p| {
        let end_of_previous = last_end.get(&p.type_name).copied().unwrap_or(0);
        if p.offset < end_of_previous {
            false
        } else {
            last_end.insert(p.type_name.clone(), p.offset + p.size);
            true
        }
    });
    plans
}

fn plan_one(
    reader: &dyn ReadAt,
    disk_size: u64,
    off: u64,
    si: usize,
    sigs: &[Signature],
    footers_by_sig: &HashMap<usize, Vec<u64>>,
    max_size: u64,
    filter: &Option<HashSet<String>>,
) -> Option<CarvePlan> {
    let sig = &sigs[si];

    // The ftyp pattern matches the box *type* field; the box (and file)
    // actually starts 4 bytes earlier, at the box size field.
    let off = if sig.validator == Validator::Ftyp {
        off.checked_sub(4)?
    } else {
        off
    };

    // Cheap pre-filter for types that don't need late name resolution.
    if let Some(f) = filter {
        if sig.name != "zip" && sig.name != "ftyp" && !f.contains(sig.name) {
            return None;
        }
    }

    let remaining = disk_size.checked_sub(off)?;
    let cap = sig.max_size.min(max_size).min(remaining);
    if cap < sig.min_size {
        return None;
    }

    let mut name = sig.name.to_string();
    let mut ext = sig.extension.to_string();

    match sig.validator {
        Validator::None => {}
        Validator::Jpeg if !validate_jpeg(reader, off) => return None,
        Validator::Zip if !validate_zip(reader, off) => return None,
        Validator::Mp3 if !validate_mp3(reader, off) => return None,
        Validator::Gz if !validate_gz(reader, off) => return None,
        Validator::Bz2 if !validate_bz2(reader, off) => return None,
        Validator::Tiff if !validate_tiff(reader, off, sig.header) => return None,
        Validator::Ftyp => match classify_ftyp(reader, off) {
            Some((n, e)) => {
                name = n.to_string();
                ext = e.to_string();
            }
            None => return None,
        },
        _ => {}
    }
    if sig.name == "ftyp" {
        if let Some(f) = filter {
            if !f.contains(&name) {
                return None;
            }
        }
    }

    // --- determine size ---
    let mut truncated = false;
    let parsed = match sig.parser {
        SizeParser::None => None,
        SizeParser::Gif => parse_gif(reader, off, cap),
        SizeParser::Mp4 => parse_mp4(reader, off, cap),
        SizeParser::Sqlite => parse_sqlite(reader, off),
        SizeParser::SevenZip => parse_7z(reader, off),
        SizeParser::Wav => parse_wav(reader, off),
        SizeParser::Bmp => parse_bmp(reader, off),
    };
    let size = match parsed {
        Some(s) if s >= cap => {
            truncated = true;
            cap
        }
        Some(s) => s,
        None => {
            // For these, parser failure means the hit was a false positive.
            if matches!(
                sig.parser,
                SizeParser::Gif | SizeParser::Wav | SizeParser::Bmp | SizeParser::Mp4
            ) {
                return None;
            }
            match sig.footer {
                Some(fp) => match find_footer_end(reader, footers_by_sig.get(&si), off, fp, sig, cap) {
                    Some(end) => end - off,
                    None => {
                        truncated = true;
                        cap
                    }
                },
                None => {
                    truncated = true;
                    cap
                }
            }
        }
    };
    if size < sig.min_size {
        return None;
    }

    // ZIP-based office formats: classify by content, then apply the filter.
    if sig.name == "zip" {
        let cls = classify_zip(reader, off, size);
        name = cls.to_string();
        ext = cls.to_string();
        if let Some(f) = filter {
            if !f.contains(&name) {
                return None;
            }
        }
    }

    Some(CarvePlan {
        offset: off,
        size,
        type_name: name,
        extension: ext,
        truncated,
    })
}

/// First footer after `off` that yields at least min_size, within cap.
/// ZIP's end-of-central-directory record adds its comment length.
fn find_footer_end(
    reader: &dyn ReadAt,
    footers: Option<&Vec<u64>>,
    off: u64,
    footer_pat: &[u8],
    sig: &Signature,
    cap: u64,
) -> Option<u64> {
    let footers = footers?;
    let mut idx = footers.partition_point(|&f| f <= off);
    while idx < footers.len() {
        let f = footers[idx];
        let mut end = f + footer_pat.len() as u64;
        if sig.name == "zip" {
            let mut c = [0u8; 2];
            let comment_len = reader
                .read_exact_at(f + 20, &mut c)
                .map(|_| u16::from_le_bytes(c) as u64)
                .unwrap_or(0);
            end = f + 22 + comment_len;
        }
        let size = end.saturating_sub(off);
        if size > cap {
            break;
        }
        if size >= sig.min_size {
            return Some(end);
        }
        idx += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Validators (false-positive rejection via small positioned reads)
// ---------------------------------------------------------------------------

fn validate_jpeg(reader: &dyn ReadAt, off: u64) -> bool {
    let mut b = [0u8; 12];
    if reader.read_exact_at(off, &mut b).is_err() {
        return false;
    }
    match b[3] {
        0xE0 => &b[6..11] == b"JFIF\0",
        0xE1 => &b[6..12] == b"Exif\0\0",
        0xE2 | 0xDB | 0xC4 | 0xC0 | 0xC1 | 0xC2 | 0xEE => true,
        m => (0xE3..=0xEF).contains(&m),
    }
}

fn validate_zip(reader: &dyn ReadAt, off: u64) -> bool {
    let mut b = [0u8; 30];
    if reader.read_exact_at(off, &mut b).is_err() {
        return false;
    }
    let method = u16::from_le_bytes([b[8], b[9]]);
    let name_len = u16::from_le_bytes([b[26], b[27]]);
    let extra_len = u16::from_le_bytes([b[28], b[29]]);
    method <= 99 && (1..=1024).contains(&name_len) && extra_len <= 8192
}

fn validate_mp3(reader: &dyn ReadAt, off: u64) -> bool {
    let mut b = [0u8; 10];
    if reader.read_exact_at(off, &mut b).is_err() {
        return false;
    }
    // ID3v2.2/2.3/2.4, syncsafe size (high bits clear in the 4 size bytes).
    (2..=4).contains(&b[3]) && b[6] & 0x80 == 0 && b[7] & 0x80 == 0 && b[8] & 0x80 == 0 && b[9] & 0x80 == 0
}

fn validate_gz(reader: &dyn ReadAt, off: u64) -> bool {
    let mut b = [0u8; 10];
    if reader.read_exact_at(off, &mut b).is_err() {
        return false;
    }
    b[2] == 8 // deflate
        && matches!(b[8], 0 | 2 | 4)
        && matches!(b[9], 0 | 1 | 2 | 3 | 6 | 7 | 11 | 13 | 255)
}

fn validate_bz2(reader: &dyn ReadAt, off: u64) -> bool {
    let mut b = [0u8; 10];
    if reader.read_exact_at(off, &mut b).is_err() {
        return false;
    }
    (b'1'..=b'9').contains(&b[3]) && b[4..10] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
}

fn validate_tiff(reader: &dyn ReadAt, off: u64, header: &[u8]) -> bool {
    let mut b = [0u8; 8];
    if reader.read_exact_at(off, &mut b).is_err() {
        return false;
    }
    let ifd_offset = if header[0] == b'I' {
        u32::from_le_bytes([b[4], b[5], b[6], b[7]])
    } else {
        u32::from_be_bytes([b[4], b[5], b[6], b[7]])
    };
    (8..=(1 << 28)).contains(&ifd_offset)
}

/// ftyp major brand decides mp4 vs mov; unknown brands are false positives.
fn classify_ftyp(reader: &dyn ReadAt, off: u64) -> Option<(&'static str, &'static str)> {
    let mut b = [0u8; 12];
    reader.read_exact_at(off, &mut b).ok()?;
    let box_size = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    if !(8..=(1 << 20)).contains(&box_size) {
        return None;
    }
    match &b[8..12] {
        b"qt  " => Some(("mov", "mov")),
        b"isom" | b"iso2" | b"iso3" | b"iso4" | b"iso5" | b"iso6" | b"iso8" | b"mp41"
        | b"mp42" | b"avc1" | b"M4V " | b"M4A " | b"MSNV" | b"mmp4" | b"dash" | b"3gp4"
        | b"3gp5" | b"3g2a" | b"3g2b" => Some(("mp4", "mp4")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Internal-size parsers
// ---------------------------------------------------------------------------

/// GIF: walk header → logical screen descriptor → optional global color
/// table → blocks until the 0x3B trailer. Bounded by cap and step count.
fn parse_gif(reader: &dyn ReadAt, start: u64, cap: u64) -> Option<u64> {
    let limit = start.checked_add(cap)?;
    let mut hdr = [0u8; 13]; // 6-byte header + 7-byte LSD
    reader.read_exact_at(start, &mut hdr).ok()?;
    let packed = hdr[10];
    let mut pos = start + 13;
    if packed & 0x80 != 0 {
        pos += 3u64 * (1u64 << ((packed & 0x07) + 1)); // global color table
    }
    let mut b = [0u8; 1];
    let mut steps = 0u32;
    loop {
        if pos >= limit || steps > 1_000_000 {
            return None;
        }
        steps += 1;
        reader.read_exact_at(pos, &mut b).ok()?;
        match b[0] {
            0x3B => return Some(pos - start + 1), // trailer
            0x21 => {
                // extension: introducer + label, then sub-blocks
                pos += 2;
                pos = skip_sub_blocks(reader, pos, limit)?;
            }
            0x2C => {
                // image descriptor: 9 bytes + 1 LZW min code size byte
                let mut d = [0u8; 10];
                reader.read_exact_at(pos + 1, &mut d).ok()?;
                let packed2 = d[8];
                pos += 11;
                if packed2 & 0x80 != 0 {
                    pos += 3u64 * (1u64 << ((packed2 & 0x07) + 1)); // local color table
                }
                pos = skip_sub_blocks(reader, pos, limit)?;
            }
            _ => return None,
        }
    }
}

fn skip_sub_blocks(reader: &dyn ReadAt, mut pos: u64, limit: u64) -> Option<u64> {
    let mut s = [0u8; 1];
    loop {
        if pos >= limit {
            return None;
        }
        reader.read_exact_at(pos, &mut s).ok()?;
        pos += 1;
        if s[0] == 0 {
            return Some(pos);
        }
        pos += s[0] as u64;
    }
}

/// MP4/MOV: walk the top-level box (atom) chain from ftyp. The file ends at
/// the first invalid box; requires having seen mdat or moov to be credible.
fn parse_mp4(reader: &dyn ReadAt, start: u64, cap: u64) -> Option<u64> {
    let end_limit = start.checked_add(cap)?;
    let mut pos = start;
    let mut saw_mdat = false;
    let mut saw_moov = false;
    for _ in 0..4096 {
        let mut h = [0u8; 16];
        if reader.read_exact_at(pos, &mut h[..8]).is_err() {
            break;
        }
        let mut box_size = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as u64;
        // A box type is 4 printable ASCII chars. Anything else (zeros, high
        // bytes) means we've walked off the end of the file into free space.
        if !h[4..8].iter().all(|&b| (0x20..=0x7E).contains(&b)) {
            break;
        }
        let header_len = if box_size == 1 {
            if reader.read_exact_at(pos + 8, &mut h[8..16]).is_err() {
                break;
            }
            box_size = u64::from_be_bytes([
                h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
            ]);
            16
        } else {
            8
        };
        if box_size == 0 {
            // "to end of file" box — treat as everything up to the cap.
            return Some(cap);
        }
        if box_size < header_len {
            break; // invalid chain
        }
        match &h[4..8] {
            b"mdat" => saw_mdat = true,
            b"moov" => saw_moov = true,
            _ => {}
        }
        pos += box_size;
        if pos >= end_limit {
            return Some(cap);
        }
    }
    let total = pos - start;
    if total >= 8 && (saw_mdat || saw_moov) {
        Some(total)
    } else {
        None
    }
}

/// SQLite: page_size (offset 16) * page_count (offset 28), both big-endian.
fn parse_sqlite(reader: &dyn ReadAt, off: u64) -> Option<u64> {
    let mut h = [0u8; 100];
    reader.read_exact_at(off, &mut h).ok()?;
    let mut page_size = u16::from_be_bytes([h[16], h[17]]) as u64;
    if page_size == 1 {
        page_size = 65536;
    }
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return None;
    }
    // File format write/read versions must be 1 (legacy) or 2 (WAL).
    if !(1..=2).contains(&h[18]) || !(1..=2).contains(&h[19]) {
        return None;
    }
    let pages = u32::from_be_bytes([h[28], h[29], h[30], h[31]]) as u64;
    if pages == 0 {
        return None; // pre-3.7 databases: size unknown, caller falls back
    }
    Some(page_size * pages)
}

/// 7z: 32-byte start header holds offset and size of the "next header".
fn parse_7z(reader: &dyn ReadAt, off: u64) -> Option<u64> {
    let mut h = [0u8; 32];
    reader.read_exact_at(off, &mut h).ok()?;
    let next_off = u64::from_le_bytes([h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19]]);
    let next_size = u64::from_le_bytes([h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27]]);
    if next_off > (1 << 40) || next_size > (1 << 34) {
        return None;
    }
    Some(32 + next_off + next_size)
}

/// WAV: require "WAVE" at +8 (RIFF is shared with AVI etc.), then the RIFF
/// chunk size at +4 (+ 8 header bytes) is the file size.
fn parse_wav(reader: &dyn ReadAt, off: u64) -> Option<u64> {
    let mut h = [0u8; 12];
    reader.read_exact_at(off, &mut h).ok()?;
    if &h[8..12] != b"WAVE" {
        return None;
    }
    let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as u64 + 8;
    if size < 36 {
        return None;
    }
    Some(size)
}

/// BMP: file size at +2, but only after strict plausibility checks (the
/// 2-byte "BM" signature is very prone to false positives).
fn parse_bmp(reader: &dyn ReadAt, off: u64) -> Option<u64> {
    let mut h = [0u8; 26];
    reader.read_exact_at(off, &mut h).ok()?;
    let reserved_ok = h[6..10] == [0, 0, 0, 0];
    let size = u32::from_le_bytes([h[2], h[3], h[4], h[5]]) as u64;
    let dib_size = u32::from_le_bytes([h[14], h[15], h[16], h[17]]);
    let dib_known = matches!(dib_size, 12 | 40 | 52 | 56 | 108 | 124);
    if reserved_ok && dib_known && size >= 54 {
        Some(size)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// ZIP content classification (docx / xlsx / pptx vs plain zip)
// ---------------------------------------------------------------------------

fn classify_zip(reader: &dyn ReadAt, off: u64, size: u64) -> &'static str {
    let mut window: Vec<u8> = Vec::new();
    let head_len = size.min(4096) as usize;
    let mut head = vec![0u8; head_len];
    if reader.read_exact_at(off, &mut head).is_ok() {
        window.extend_from_slice(&head);
    }
    if size > head_len as u64 {
        // The central directory at the end lists all member names in plain text.
        let tail_len = size.min(65536);
        let mut tail = vec![0u8; tail_len as usize];
        if reader.read_exact_at(off + size - tail_len, &mut tail).is_ok() {
            window.extend_from_slice(&tail);
        }
    }
    if !contains(&window, b"[Content_Types].xml") {
        return "zip";
    }
    if contains(&window, b"word/") {
        "docx"
    } else if contains(&window, b"xl/") {
        "xlsx"
    } else if contains(&window, b"ppt/") {
        "pptx"
    } else {
        "zip"
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Copying bytes out (the only data movement: source -> output file)
// ---------------------------------------------------------------------------

/// Stream a planned range from the source into `path`, 1MB at a time.
/// Source side is strictly `read_exact_at`; destination is a fresh file on
/// the (already verified) separate output disk.
pub fn carve_to_file(reader: &dyn ReadAt, plan: &CarvePlan, path: &Path) -> io::Result<u64> {
    let out = File::create(path)?;
    let mut writer = io::BufWriter::new(out);
    let mut buf = vec![0u8; COPY_BUF];
    let mut offset = plan.offset;
    let mut remaining = plan.size;
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        reader.read_exact_at(offset, &mut buf[..n])?;
        writer.write_all(&buf[..n])?;
        offset += n as u64;
        remaining -= n as u64;
    }
    writer.flush()?;
    Ok(plan.size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gif_bytes() -> Vec<u8> {
        let mut g = b"GIF89a".to_vec();
        g.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // LSD, no GCT
        g.push(0x3B); // trailer
        g
    }

    #[test]
    fn parses_minimal_gif() {
        let g = gif_bytes();
        assert_eq!(parse_gif(&g, 0, 1024), Some(g.len() as u64));
    }

    #[test]
    fn parses_gif_with_image_block() {
        let mut g = b"GIF89a".to_vec();
        g.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        g.push(0x2C); // image descriptor
        g.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0]); // 9-byte descriptor
        g.push(0x02); // LZW min code size
        g.push(0x02); // sub-block of 2
        g.extend_from_slice(&[0x4C, 0x01]);
        g.push(0x00); // block terminator
        g.push(0x3B);
        assert_eq!(parse_gif(&g, 0, 1024), Some(g.len() as u64));
    }

    #[test]
    fn parses_mp4_atom_chain() {
        let mut m = Vec::new();
        m.extend_from_slice(&24u32.to_be_bytes()); // ftyp box, 24 bytes
        m.extend_from_slice(b"ftypisom");
        m.extend_from_slice(&[0; 12]);
        m.extend_from_slice(&16u32.to_be_bytes()); // mdat box, 16 bytes
        m.extend_from_slice(b"mdat");
        m.extend_from_slice(&[0; 8]);
        assert_eq!(parse_mp4(&m, 0, 1024), Some(40));
        // mov via qt brand
        let mut mv = m.clone();
        mv[8..12].copy_from_slice(b"qt  ");
        assert_eq!(classify_ftyp(&mv, 0), Some(("mov", "mov")));
        assert_eq!(classify_ftyp(&m, 0), Some(("mp4", "mp4")));
    }

    #[test]
    fn rejects_bogus_mp4() {
        let m = vec![0xFF; 64];
        assert_eq!(classify_ftyp(&m, 0), None);
    }

    #[test]
    fn parses_sqlite_header() {
        let mut h = vec![0u8; 100];
        h[..16].copy_from_slice(b"SQLite format 3\0");
        h[16..18].copy_from_slice(&4096u16.to_be_bytes()); // page size
        h[18] = 1;
        h[19] = 1;
        h[28..32].copy_from_slice(&3u32.to_be_bytes()); // 3 pages
        assert_eq!(parse_sqlite(&h, 0), Some(3 * 4096));
    }

    #[test]
    fn parses_7z_header() {
        let mut h = vec![0u8; 32];
        h[..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
        h[12..20].copy_from_slice(&100u64.to_le_bytes());
        h[20..28].copy_from_slice(&50u64.to_le_bytes());
        assert_eq!(parse_7z(&h, 0), Some(32 + 100 + 50));
    }

    #[test]
    fn parses_wav_and_rejects_avi() {
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&100u32.to_le_bytes());
        w.extend_from_slice(b"WAVE");
        assert_eq!(parse_wav(&w, 0), Some(108));
        let mut a = w.clone();
        a[8..12].copy_from_slice(b"AVI ");
        assert_eq!(parse_wav(&a, 0), None);
    }

    #[test]
    fn parses_bmp_with_validation() {
        let mut b = vec![0u8; 54];
        b[0..2].copy_from_slice(b"BM");
        b[2..6].copy_from_slice(&1000u32.to_le_bytes());
        b[14..18].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(parse_bmp(&b, 0), Some(1000));
        b[6] = 1; // reserved bytes nonzero → reject
        assert_eq!(parse_bmp(&b, 0), None);
    }

    #[test]
    fn classifies_office_zips() {
        let mut z = vec![0u8; 8192];
        let marker = b"[Content_Types].xml .... word/document.xml";
        z[4000..4000 + marker.len()].copy_from_slice(marker);
        assert_eq!(classify_zip(&z, 0, 8192), "docx");
        let mut plain = vec![0u8; 8192];
        plain[100..110].copy_from_slice(b"randomdata");
        assert_eq!(classify_zip(&plain, 0, 8192), "zip");
    }

    #[test]
    fn dedupes_overlapping_same_type_hits() {
        use crate::scanner::ScanResult;
        use crate::signatures::database;
        let sigs = database();
        let jpg_idx = sigs.iter().position(|s| s.name == "jpg").unwrap();
        // Build a fake disk: real JFIF JPEG at 0, stray FFD8FF-like noise inside it.
        let mut disk = vec![0u8; 4096];
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        jpg.extend_from_slice(b"JFIF\0");
        jpg.extend_from_slice(&[0u8; 640]); // pad past the 512-byte min_size
        jpg.extend_from_slice(&[0xFF, 0xD9]);
        disk[..jpg.len()].copy_from_slice(&jpg);
        let scan = ScanResult {
            headers: vec![(0, jpg_idx), (50, jpg_idx)], // second hit inside first file
            footers: vec![((jpg.len() - 2) as u64, jpg_idx)],
            errors: vec![],
            bytes_scanned: 4096,
        };
        let plans = plan_carves(&disk, 4096, &scan, &sigs, 100 * 1024 * 1024, &None);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].offset, 0);
        assert_eq!(plans[0].size, jpg.len() as u64);
        assert!(!plans[0].truncated);
    }
}
