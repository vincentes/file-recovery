//! Core scanning logic: stream the source in large chunks and record every
//! header/footer signature offset. Read-only throughout — the only source
//! operation is `read_exact_at` (pread).
//!
//! Signatures are indexed by first byte so the inner loop is cheap; matches
//! spanning a chunk boundary are caught by carrying `max_pattern_len - 1`
//! bytes of tail into the next window, and the "not fully inside the carry"
//! rule keeps them from being recorded twice.
//!
//! I/O errors never abort the scan: a failed chunk is re-read block by block,
//! unrecoverable blocks are zero-filled (which matches nothing), recorded in
//! `errors`, and reported at the end.

use crate::disk::ReadAt;
use crate::signatures::Signature;

pub struct ScanResult {
    /// (absolute offset, signature index) for every header match, in scan order.
    pub headers: Vec<(u64, usize)>,
    /// (absolute offset, signature index) for every footer match, in scan order.
    pub footers: Vec<(u64, usize)>,
    /// Human-readable descriptions of I/O errors encountered (skipped regions).
    pub errors: Vec<String>,
    pub bytes_scanned: u64,
}

struct Pattern {
    bytes: &'static [u8],
    sig: usize,
    is_footer: bool,
}

pub fn scan(
    reader: &dyn ReadAt,
    total_size: u64,
    block_size: u64,
    chunk_size: u64,
    sigs: &[Signature],
    active: &[usize],
    mut progress: impl FnMut(u64, usize),
) -> ScanResult {
    // Build the pattern table (headers + footers for active signatures only).
    let mut patterns: Vec<Pattern> = Vec::new();
    for &si in active {
        let s = &sigs[si];
        patterns.push(Pattern {
            bytes: s.header,
            sig: si,
            is_footer: false,
        });
        if let Some(f) = s.footer {
            patterns.push(Pattern {
                bytes: f,
                sig: si,
                is_footer: true,
            });
        }
    }
    let max_pat_len = patterns.iter().map(|p| p.bytes.len()).max().unwrap_or(1);
    let overlap = max_pat_len - 1;

    let mut first_byte_index: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (i, p) in patterns.iter().enumerate() {
        first_byte_index[p.bytes[0] as usize].push(i);
    }

    let block_size = block_size.max(512);
    let chunk_size = chunk_size.max(block_size);
    let mut buf = vec![0u8; (chunk_size as usize) + overlap];
    let mut result = ScanResult {
        headers: Vec::new(),
        footers: Vec::new(),
        errors: Vec::new(),
        bytes_scanned: 0,
    };

    let mut carry = 0usize; // tail bytes kept from the previous window
    let mut pos = 0u64; // absolute offset of the next fresh read
    while pos < total_size {
        let want = chunk_size.min(total_size - pos) as usize;
        let n = read_span(
            reader,
            pos,
            &mut buf[carry..carry + want],
            block_size,
            &mut result.errors,
        );
        if n == 0 {
            break; // defensive: never spin on a dead device
        }
        let window_len = carry + n;
        let window = &buf[..window_len];
        let abs_base = pos - carry as u64; // absolute offset of window[0]

        for i in 0..window_len {
            let candidates = &first_byte_index[window[i] as usize];
            for &pi in candidates {
                let p = &patterns[pi];
                let end = i + p.bytes.len();
                if end <= window_len && &window[i..end] == p.bytes {
                    let abs = abs_base + i as u64;
                    // Skip matches fully inside the carry region — they were
                    // recorded in the previous iteration.
                    if abs + p.bytes.len() as u64 > pos {
                        if p.is_footer {
                            result.footers.push((abs, p.sig));
                        } else {
                            result.headers.push((abs, p.sig));
                        }
                    }
                }
            }
        }

        result.bytes_scanned += n as u64;
        progress(result.bytes_scanned, result.headers.len());
        pos += n as u64;

        if pos < total_size && window_len >= overlap {
            carry = overlap;
            buf.copy_within(window_len - overlap..window_len, 0);
        } else {
            carry = 0;
        }
    }

    result
}

/// Read `buf.len()` bytes at `pos`. On failure, retry block by block so one
/// bad sector doesn't lose a whole 64MB chunk; failed blocks are zero-filled
/// (they match no signature) and reported.
fn read_span(
    reader: &dyn ReadAt,
    pos: u64,
    buf: &mut [u8],
    block_size: u64,
    errors: &mut Vec<String>,
) -> usize {
    if buf.is_empty() {
        return 0;
    }
    match reader.read_exact_at(pos, buf) {
        Ok(()) => buf.len(),
        Err(e) => {
            let bs = block_size as usize;
            if buf.len() <= bs {
                errors.push(format!("read error at offset {pos}: {e} — region skipped"));
                buf.iter_mut().for_each(|b| *b = 0);
                return buf.len();
            }
            let mut off = pos;
            let mut done = 0usize;
            for sub in buf.chunks_mut(bs) {
                if let Err(e2) = reader.read_exact_at(off, sub) {
                    errors.push(format!("read error at offset {off}: {e2} — block skipped"));
                    sub.iter_mut().for_each(|b| *b = 0);
                }
                off += sub.len() as u64;
                done += sub.len();
            }
            done
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::database;

    fn active_all(sigs: &[Signature]) -> Vec<usize> {
        (0..sigs.len()).collect()
    }

    #[test]
    fn finds_signatures_across_chunk_boundaries() {
        let sigs = database();
        let png_idx = sigs.iter().position(|s| s.name == "png").unwrap();
        let png_len = sigs[png_idx].header.len();

        let mut disk = vec![0u8; 4096];
        // Place a PNG header straddling the 1024-byte chunk boundary.
        let at = 1024 - (png_len - 2);
        disk[at..at + png_len].copy_from_slice(sigs[png_idx].header);
        // And a JPEG fully inside the second chunk.
        let jpg_idx = sigs.iter().position(|s| s.name == "jpg").unwrap();
        disk[2000..2003].copy_from_slice(sigs[jpg_idx].header);

        let result = scan(
            &disk,
            disk.len() as u64,
            512,
            1024,
            &sigs,
            &active_all(&sigs),
            |_, _| {},
        );
        assert!(
            result
                .headers
                .contains(&((at as u64) - 0, png_idx))
                || result.headers.iter().any(|&(o, s)| o == at as u64 && s == png_idx),
            "boundary-spanning PNG header not found: {:?}",
            result.headers
        );
        assert!(result
            .headers
            .iter()
            .any(|&(o, s)| o == 2000 && s == jpg_idx));
        // No duplicate recordings from the carry overlap.
        let png_hits = result
            .headers
            .iter()
            .filter(|&&(_, s)| s == png_idx)
            .count();
        assert_eq!(png_hits, 1);
    }

    #[test]
    fn collects_footers() {
        let sigs = database();
        let jpg_idx = sigs.iter().position(|s| s.name == "jpg").unwrap();
        let mut disk = vec![0u8; 512];
        disk[10..13].copy_from_slice(sigs[jpg_idx].header);
        disk[100..102].copy_from_slice(&[0xFF, 0xD9]);
        let result = scan(
            &disk,
            disk.len() as u64,
            512,
            512,
            &sigs,
            &active_all(&sigs),
            |_, _| {},
        );
        assert!(result.footers.iter().any(|&(o, s)| o == 100 && s == jpg_idx));
    }
}
