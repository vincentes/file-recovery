//! Built-in file signature (magic number) database.
//!
//! Each entry describes a recoverable format: header bytes, optional footer
//! bytes, a per-type size ceiling, whether the format carries internal size
//! information (parsed by `carver`), and an optional validator used to reject
//! false positives from short signatures (e.g. "BM", 1F 8B, "ID3").

/// Which internal-size parser (in `carver`) applies to this format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeParser {
    None,
    Gif,
    Mp4,
    Sqlite,
    SevenZip,
    Wav,
    Bmp,
}

/// Extra validation of the bytes right after the header, done with small
/// positioned reads before committing to a carve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validator {
    None,
    Jpeg,
    Zip,
    Mp3,
    Ftyp,
    Gz,
    Bz2,
    Tiff,
}

pub struct Signature {
    /// Name used for --types filtering ("jpg", "png", ...). The ftyp entry is
    /// named "ftyp" internally and resolves to mp4/mov during carving.
    pub name: &'static str,
    /// Default file extension (ftyp is resolved to mp4/mov at carve time).
    pub extension: &'static str,
    pub header: &'static [u8],
    /// Footer byte sequence marking end-of-file, if the format has one.
    pub footer: Option<&'static [u8]>,
    /// Per-type hard ceiling; effective cap = min(this, --max-size).
    pub max_size: u64,
    /// Carves smaller than this are discarded as noise.
    pub min_size: u64,
    pub parser: SizeParser,
    pub validator: Validator,
    /// True when the format encodes its own length (parsed size, atom walk,
    /// or footer) rather than relying on the max-size cap.
    pub has_internal_size: bool,
}

pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * KB;
pub const GB: u64 = 1024 * MB;

static DB: &[Signature] = &[
    // JPEG: spec variants FF D8 FF E0 / E1 / E8 all share the FFD8FF prefix;
    // the Jpeg validator then confirms the APP marker (JFIF/Exif/...).
    Signature {
        name: "jpg",
        extension: "jpg",
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size: 128 * MB,
        min_size: 512,
        parser: SizeParser::None,
        validator: Validator::Jpeg,
        has_internal_size: true, // via FFD9 footer
    },
    Signature {
        name: "png",
        extension: "png",
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]), // IEND + CRC
        max_size: 512 * MB,
        min_size: 64,
        parser: SizeParser::None,
        validator: Validator::None,
        has_internal_size: true, // via IEND footer
    },
    Signature {
        name: "pdf",
        extension: "pdf",
        header: b"%PDF-",
        footer: Some(b"%%EOF"),
        max_size: 2 * GB,
        min_size: 128,
        parser: SizeParser::None,
        validator: Validator::None,
        has_internal_size: true, // via %%EOF footer
    },
    // GIF covered as the full 6-byte forms of the spec's 47 49 46 38 prefix.
    Signature {
        name: "gif",
        extension: "gif",
        header: b"GIF87a",
        footer: None,
        max_size: 64 * MB,
        min_size: 14,
        parser: SizeParser::Gif,
        validator: Validator::None,
        has_internal_size: true, // block walk to 0x3B trailer
    },
    Signature {
        name: "gif",
        extension: "gif",
        header: b"GIF89a",
        footer: None,
        max_size: 64 * MB,
        min_size: 14,
        parser: SizeParser::Gif,
        validator: Validator::None,
        has_internal_size: true,
    },
    // MP4/MOV: any box whose 4-byte size is followed by "ftyp"; the brand at
    // +8 decides mp4 vs mov and rejects false positives. Size comes from
    // walking the top-level atom chain.
    Signature {
        name: "ftyp",
        extension: "mp4",
        header: b"ftyp",
        footer: None,
        max_size: 32 * GB,
        min_size: 32,
        parser: SizeParser::Mp4,
        validator: Validator::Ftyp,
        has_internal_size: true,
    },
    // ZIP also covers DOCX/XLSX/PPTX — classified by content after carving.
    Signature {
        name: "zip",
        extension: "zip",
        header: &[0x50, 0x4B, 0x03, 0x04],
        footer: Some(&[0x50, 0x4B, 0x05, 0x06]), // end of central directory
        max_size: 8 * GB,
        min_size: 32,
        parser: SizeParser::None,
        validator: Validator::Zip,
        has_internal_size: true, // via EOCD footer (+ comment length)
    },
    // MP3 via ID3v2 tag (frame-sync-only files without ID3 are not detected;
    // the bare 0xFFEx sync pattern produces far too many false positives).
    Signature {
        name: "mp3",
        extension: "mp3",
        header: b"ID3",
        footer: None,
        max_size: 64 * MB,
        min_size: 128,
        parser: SizeParser::None,
        validator: Validator::Mp3,
        has_internal_size: false,
    },
    Signature {
        name: "wav",
        extension: "wav",
        header: b"RIFF",
        footer: None,
        max_size: 8 * GB,
        min_size: 64,
        parser: SizeParser::Wav,
        validator: Validator::None,
        has_internal_size: true, // RIFF size field (+ validated "WAVE")
    },
    Signature {
        name: "sqlite",
        extension: "sqlite",
        header: b"SQLite format 3\0",
        footer: None,
        max_size: 16 * GB,
        min_size: 512,
        parser: SizeParser::Sqlite,
        validator: Validator::None,
        has_internal_size: true, // page_size * page_count from header
    },
    Signature {
        name: "bmp",
        extension: "bmp",
        header: b"BM",
        footer: None,
        max_size: 256 * MB,
        min_size: 64,
        parser: SizeParser::Bmp,
        validator: Validator::None,
        has_internal_size: true, // file-size field (strictly validated)
    },
    Signature {
        name: "tiff",
        extension: "tiff",
        header: &[0x49, 0x49, 0x2A, 0x00], // little-endian
        footer: None,
        max_size: 1 * GB,
        min_size: 32,
        parser: SizeParser::None,
        validator: Validator::Tiff,
        has_internal_size: false,
    },
    Signature {
        name: "tiff",
        extension: "tiff",
        header: &[0x4D, 0x4D, 0x00, 0x2A], // big-endian
        footer: None,
        max_size: 1 * GB,
        min_size: 32,
        parser: SizeParser::None,
        validator: Validator::Tiff,
        has_internal_size: false,
    },
    Signature {
        name: "rar",
        extension: "rar",
        header: b"Rar!\x1A\x07\x00", // RAR 4.x
        footer: None,
        max_size: 8 * GB,
        min_size: 32,
        parser: SizeParser::None,
        validator: Validator::None,
        has_internal_size: false,
    },
    Signature {
        name: "rar",
        extension: "rar",
        header: b"Rar!\x1A\x07\x01\x00", // RAR 5.x
        footer: None,
        max_size: 8 * GB,
        min_size: 32,
        parser: SizeParser::None,
        validator: Validator::None,
        has_internal_size: false,
    },
    Signature {
        name: "7z",
        extension: "7z",
        header: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        footer: None,
        max_size: 16 * GB,
        min_size: 32,
        parser: SizeParser::SevenZip,
        validator: Validator::None,
        has_internal_size: true, // next-header offset + size
    },
    Signature {
        name: "gz",
        extension: "gz",
        header: &[0x1F, 0x8B],
        footer: None,
        max_size: 4 * GB,
        min_size: 24,
        parser: SizeParser::None,
        validator: Validator::Gz,
        has_internal_size: false,
    },
    Signature {
        name: "bz2",
        extension: "bz2",
        header: b"BZh",
        footer: None,
        max_size: 4 * GB,
        min_size: 24,
        parser: SizeParser::None,
        validator: Validator::Bz2,
        has_internal_size: false,
    },
    Signature {
        name: "plist",
        extension: "plist",
        header: b"bplist00",
        footer: None,
        max_size: 64 * MB,
        min_size: 16,
        parser: SizeParser::None,
        validator: Validator::None,
        has_internal_size: false,
    },
];

pub fn database() -> &'static [Signature] {
    DB
}

/// User-facing type names accepted by --types. "docx"/"xlsx"/"pptx" are
/// ZIP-based and resolved by content classification during carving; "mp4" and
/// "mov" share the ftyp entry and are resolved by brand.
pub fn valid_type_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = DB
        .iter()
        .map(|s| if s.name == "ftyp" { "mp4" } else { s.name })
        .collect();
    names.extend(["mov", "docx", "xlsx", "pptx"]);
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_covers_required_formats() {
        let names = valid_type_names();
        for required in [
            "jpg", "png", "pdf", "gif", "mp4", "mov", "zip", "docx", "xlsx", "mp3", "wav",
            "sqlite", "bmp", "tiff", "rar", "7z", "gz", "bz2", "plist",
        ] {
            assert!(names.contains(&required), "missing type: {required}");
        }
    }

    #[test]
    fn every_signature_has_nonempty_header() {
        for s in database() {
            assert!(!s.header.is_empty(), "empty header for {}", s.name);
            assert!(s.max_size >= s.min_size, "bad size bounds for {}", s.name);
        }
    }
}
