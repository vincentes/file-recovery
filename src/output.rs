//! Output management. All recovered bytes go to a directory that `safety`
//! has already verified is NOT on the source physical disk. Files are
//! created fresh (never appended to source paths), zero-length results are
//! discarded, and every carve is recorded in a JSON recovery log.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::carver::{carve_to_file, CarvePlan};
use crate::disk::ReadAt;
use crate::error::CarveError;

#[derive(Serialize)]
pub struct LogEntry {
    pub file: String,
    pub offset: u64,
    pub size: u64,
    #[serde(rename = "type")]
    pub type_name: String,
    pub truncated: bool,
    pub timestamp_unix: u64,
}

#[derive(Serialize, Clone)]
pub struct TypeCount {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Serialize)]
pub struct RunLog {
    pub tool: String,
    pub version: String,
    pub source_device: String,
    pub source_size_bytes: u64,
    /// Always true — recorded as evidence of the read-only contract.
    pub opened_read_only: bool,
    pub dry_run: bool,
    pub started_unix: u64,
    pub duration_secs: f64,
    pub total_files: usize,
    pub total_bytes: u64,
    pub counts_by_type: BTreeMap<String, TypeCount>,
    pub errors: Vec<String>,
    pub entries: Vec<LogEntry>,
}

pub fn write_log(path: &Path, log: &RunLog) -> io::Result<()> {
    let json = serde_json::to_string_pretty(log)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, json)
}

pub struct OutputManager {
    root: PathBuf,
    organize: bool,
    counter: u64,
}

impl OutputManager {
    pub fn prepare(root: PathBuf, organize: bool) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            organize,
            counter: 1,
        })
    }

    fn next_path(&mut self, plan: &CarvePlan) -> io::Result<PathBuf> {
        let dir = if self.organize {
            let d = self.root.join(&plan.type_name);
            fs::create_dir_all(&d)?;
            d
        } else {
            self.root.clone()
        };
        loop {
            let p = dir.join(format!(
                "recovered_{:04}.{}",
                self.counter, plan.extension
            ));
            self.counter += 1;
            if !p.exists() {
                return Ok(p);
            }
        }
    }

    /// Carve one plan to disk. Zero-length results are deleted and reported
    /// as errors; ENOSPC aborts recovery gracefully via CarveError::DiskFull.
    pub fn save(&mut self, reader: &dyn ReadAt, plan: &CarvePlan) -> Result<PathBuf, CarveError> {
        let path = self
            .next_path(plan)
            .map_err(|e| CarveError::Io {
                path: self.root.display().to_string(),
                source: e,
            })?;
        let written = carve_to_file(reader, plan, &path).map_err(|e| {
            if e.raw_os_error() == Some(libc::ENOSPC) {
                let _ = fs::remove_file(&path); // partial file on the OUTPUT disk only
                CarveError::DiskFull(path.display().to_string())
            } else {
                CarveError::Io {
                    path: path.display().to_string(),
                    source: e,
                }
            }
        })?;
        let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if written == 0 || len == 0 {
            let _ = fs::remove_file(&path);
            return Err(CarveError::Io {
                path: path.display().to_string(),
                source: io::Error::new(io::ErrorKind::Other, "carved file is zero-length"),
            });
        }
        Ok(path)
    }
}
