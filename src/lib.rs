//! file-recovery — a READ-ONLY file carving tool for macOS.
//!
//! Design invariant: the source disk is only ever opened with `O_RDONLY`
//! (verified at runtime via `fcntl(F_GETFL)`), and only `read`/`pread`-style
//! operations are ever issued against it. Carving means *copying* bytes out;
//! nothing is ever written, moved, truncated, or deleted on the source.

pub mod carver;
pub mod disk;
pub mod error;
pub mod output;
pub mod progress;
pub mod safety;
pub mod scanner;
pub mod signatures;
