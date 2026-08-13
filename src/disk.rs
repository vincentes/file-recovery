//! READ-ONLY raw disk access.
//!
//! The source is opened with `O_RDONLY` only and the flags are verified at
//! runtime with `fcntl(F_GETFL)`. The only operations ever performed against
//! the source are `pread`-style positioned reads (`FileExt::read_at`). No
//! write, fsync, truncate, unlink, rename, or write-ioctl call exists in this
//! module — or anywhere in this crate.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;

use crate::error::CarveError;

/// What the source path actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A real block/character device, e.g. /dev/rdisk2s1 or /dev/disk2.
    Device,
    /// A regular file (disk image), only accepted with --allow-file.
    ImageFile,
}

/// Positioned-read abstraction so scanners/parsers work against devices,
/// files, and in-memory test buffers uniformly. All reads are non-mutating.
pub trait ReadAt: Send + Sync {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

impl ReadAt for File {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0usize;
        while filled < buf.len() {
            match self.read_at(&mut buf[filled..], offset + filled as u64) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short read (end of device)",
                    ))
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = offset as usize;
        if start.checked_add(buf.len()).map_or(true, |end| end > self.len()) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past end of buffer",
            ));
        }
        buf.copy_from_slice(&self[start..start + buf.len()]);
        Ok(())
    }
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.as_slice().read_exact_at(offset, buf)
    }
}

/// Classify the source path. Regular files require the explicit --allow-file
/// override; anything that is neither a device nor a file is rejected.
pub fn detect_kind(meta: &Metadata, path: &str, allow_file: bool) -> Result<SourceKind, CarveError> {
    let ft = meta.file_type();
    if ft.is_block_device() || ft.is_char_device() {
        Ok(SourceKind::Device)
    } else if ft.is_file() && allow_file {
        Ok(SourceKind::ImageFile)
    } else {
        Err(CarveError::NotADevice {
            path: path.to_string(),
        })
    }
}

/// An opened read-only source (device or image file).
pub struct RawDisk {
    pub file: File,
    pub path: String,
    pub kind: SourceKind,
    pub size: u64,
}

impl ReadAt for RawDisk {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        <File as ReadAt>::read_exact_at(&self.file, offset, buf)
    }
}

impl RawDisk {
    /// Open `path` strictly read-only and verify the flags at runtime.
    pub fn open(path: &str, allow_file: bool) -> Result<Self, CarveError> {
        let meta = std::fs::metadata(path).map_err(|e| map_io(path, e))?;
        let kind = detect_kind(&meta, path, allow_file)?;

        // O_RDONLY: read(true), no write(true), no custom flags. Ever.
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| map_io(path, e))?;
        verify_read_only(&file, path)?;

        let size = match kind {
            SourceKind::Device => device_size(&file)
                .or_else(|| seek_end_size(&file))
                .filter(|s| *s > 0)
                .ok_or_else(|| CarveError::SizeUnknown {
                    path: path.to_string(),
                })?,
            SourceKind::ImageFile => meta.len(),
        };

        Ok(RawDisk {
            file,
            path: path.to_string(),
            kind,
            size,
        })
    }
}

fn map_io(path: &str, e: io::Error) -> CarveError {
    match e.kind() {
        io::ErrorKind::PermissionDenied => CarveError::PermissionDenied {
            path: path.to_string(),
        },
        _ => CarveError::Io {
            path: path.to_string(),
            source: e,
        },
    }
}

/// Runtime proof that the descriptor is O_RDONLY. If this ever fails we
/// refuse to continue rather than risk touching the source with write access.
fn verify_read_only(file: &File, path: &str) -> Result<(), CarveError> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(CarveError::Io {
            path: path.to_string(),
            source: io::Error::last_os_error(),
        });
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(CarveError::NotReadOnly {
            path: path.to_string(),
        });
    }
    Ok(())
}

/// Device size via DKIOCGETBLOCKSIZE * DKIOCGETBLOCKCOUNT (macOS).
#[cfg(target_os = "macos")]
fn device_size(file: &File) -> Option<u64> {
    const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x4004_6418;
    const DKIOCGETBLOCKCOUNT: libc::c_ulong = 0x4008_6419;
    let fd = file.as_raw_fd();
    let mut block_size: libc::c_uint = 0;
    let mut block_count: libc::c_ulonglong = 0;
    let r1 = unsafe { libc::ioctl(fd, DKIOCGETBLOCKSIZE, &mut block_size) };
    let r2 = unsafe { libc::ioctl(fd, DKIOCGETBLOCKCOUNT, &mut block_count) };
    if r1 == 0 && r2 == 0 && block_size > 0 && block_count > 0 {
        Some(block_size as u64 * block_count as u64)
    } else {
        None
    }
}

#[cfg(not(target_os = "macos"))]
fn device_size(_file: &File) -> Option<u64> {
    None
}

/// Fallback: lseek to end. Works on some devices, harmless on failure.
fn seek_end_size(file: &File) -> Option<u64> {
    use std::io::{Seek, SeekFrom};
    let mut f = file;
    f.seek(SeekFrom::End(0)).ok().filter(|s| *s > 0)
}

/// st_rdev of the source device / st_dev of a filesystem path, used by the
/// same-physical-disk safety check.
pub fn device_number_of_source(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.rdev())
}
pub fn device_number_of_fs(path: &std::path::Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.dev())
}
