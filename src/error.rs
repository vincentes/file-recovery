use thiserror::Error;

/// Library-style errors. Application-level context is layered on with
/// `anyhow` in the binary.
#[derive(Error, Debug)]
pub enum CarveError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error(
        "permission denied opening {path} — raw device access requires root; re-run with sudo \
         (e.g. `sudo file-recovery --device {path} ...`)"
    )]
    PermissionDenied { path: String },

    #[error("{path} is not a block/character device (use --allow-file to scan a regular disk-image file)")]
    NotADevice { path: String },

    #[error("internal error: {path} was not opened read-only (O_RDONLY) — refusing to continue")]
    NotReadOnly { path: String },

    #[error("could not determine the size of device {path} (ioctl DKIOCGETBLOCK* failed)")]
    SizeUnknown { path: String },

    #[error(
        "SAFETY: output location `{output}` appears to be on the SAME physical disk as the source \
         `{device}` — writing there could overwrite recoverable data. Aborting. \
         Choose an output directory on a different physical disk."
    )]
    SameDisk { device: String, output: String },

    #[error("scan aborted by user")]
    Aborted,

    #[error("unknown file type(s): {0} — run with --list-types to see supported types")]
    UnknownTypes(String),

    #[error("output disk is full — stopping recovery gracefully: {0}")]
    DiskFull(String),
}
