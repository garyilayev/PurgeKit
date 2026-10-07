//! The engine's only view of the operating system.
//!
//! `purgekit-win` implements this with handle-relative, no-follow Win32/NT
//! calls. [`crate::testing::MemFs`] implements it in memory for tests.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use purgekit_core::{FileId128, KnownFolder, RelPath, SkipReason};
use purgekit_rules::EntryTimes;

/// One file reported by a walk. Directories are never reported, only entered.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    pub rel: RelPath,
    pub file_id: FileId128,
    pub logical_size: u64,
    pub alloc_size: u64,
    pub times: EntryTimes,
    pub readonly: bool,
}

/// Why the walker did not enter or report an entry. Counted in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalkSkip {
    /// Symlink, junction, mount point or any other reparse point.
    ReparsePoint,
    /// `RECALL_ON_OPEN`, `RECALL_ON_DATA_ACCESS` or `OFFLINE`.
    Cloud,
    /// Name could not be represented safely (invalid UTF-16, forbidden chars).
    BadName,
    /// A directory could not be opened or listed.
    Unreadable,
}

/// Receives walk results. Called from worker threads.
pub trait WalkVisitor: Sync {
    /// Checked once per directory batch; return true to stop the walk.
    fn cancelled(&self) -> bool;
    /// Whether to enter `dir` (root-relative). Never called for reparse points.
    fn enter_dir(&self, dir: &RelPath) -> bool;
    /// One directory's worth of files.
    fn files(&self, batch: Vec<WalkEntry>);
    fn skipped(&self, why: WalkSkip);
}

#[derive(Debug, Clone, Copy)]
pub struct RootInfo {
    pub volume_serial: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    #[error("not found")]
    NotFound,
    #[error("the root is a link or cloud placeholder")]
    RootIsLink,
    #[error("access denied")]
    AccessDenied,
    #[error("{0}")]
    Other(String),
}

/// State of a file opened for deletion, read from the open handle.
#[derive(Debug, Clone)]
pub struct OpenedFile {
    pub volume_serial: u64,
    pub file_id: FileId128,
    pub is_dir: bool,
    pub readonly: bool,
    pub reparse: bool,
    pub cloud: bool,
    pub link_count: u32,
    pub alloc_size: u64,
    pub times: EntryTimes,
}

/// Outcome of one deletion with an optional technical code for the details expander.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip {
    pub reason: SkipReason,
    pub detail: Option<String>,
}

impl Skip {
    pub fn new(reason: SkipReason) -> Self {
        Skip {
            reason,
            detail: None,
        }
    }
    pub fn with(reason: SkipReason, detail: impl Into<String>) -> Self {
        Skip {
            reason,
            detail: Some(detail.into()),
        }
    }
}

impl From<SkipReason> for Skip {
    fn from(r: SkipReason) -> Self {
        Skip::new(r)
    }
}

#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Display name, e.g. `C:`.
    pub name: String,
    pub label: String,
    pub root: PathBuf,
    pub total: u64,
    pub free: u64,
}

pub trait FsBackend: Send + Sync {
    /// Resolve a known folder (`SHGetKnownFolderPath`, `GetTempPath2W`).
    fn resolve(&self, folder: KnownFolder) -> Option<PathBuf>;

    /// Walk `root` without following reparse points. Must report every file
    /// below directories the visitor agrees to enter, in per-directory batches.
    fn walk(&self, root: &Path, visitor: &dyn WalkVisitor) -> Result<RootInfo, FsError>;

    /// Open `rel` below `root` one component at a time, each relative to its
    /// parent and without following reparse points; run `check` on the final
    /// handle; if it passes, delete through that same handle.
    fn delete_file(
        &self,
        root: &Path,
        rel: &RelPath,
        check: &dyn Fn(&OpenedFile) -> Result<(), Skip>,
    ) -> Result<(), Skip>;

    /// Remove `rel` below `root` if it is an empty, non-reparse directory.
    /// Never recursive. Returns true if removed.
    fn remove_dir_if_empty(&self, root: &Path, rel: &RelPath) -> bool;

    /// Lower-cased executable names of running processes.
    fn running_processes(&self) -> HashSet<String>;

    /// Free bytes available on the volume holding `path`.
    fn free_space(&self, path: &Path) -> Option<u64>;

    /// Total bytes and item count in the Recycle Bin (all drives).
    fn recycle_bin_query(&self) -> Option<(u64, u64)>;

    /// Empty the Recycle Bin (all drives), without UI.
    fn recycle_bin_empty(&self) -> Result<(), Skip>;

    /// Read-only registry presence check for `detect = { registry_key = ... }`.
    fn registry_key_exists(&self, key: &str) -> bool;

    /// Fixed drives for the Space screen.
    fn volumes(&self) -> Vec<VolumeInfo>;

    /// True if the drive holding `path` reports a seek penalty (HDD).
    fn has_seek_penalty(&self, _path: &Path) -> bool {
        false
    }

    /// Function each scan worker thread calls at start (background I/O
    /// priority). A plain `fn` so the thread pool can hold it.
    fn background_mode_fn(&self) -> Option<fn()> {
        None
    }
}
