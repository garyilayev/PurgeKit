//! Batched engine events. There is no per-file event: an aggregator emits at
//! most one `Progress` per ~100 ms so the UI is never flooded.

use purgekit_core::Category;

#[derive(Debug, Clone, Default)]
pub struct Progress {
    /// Display name of the cleaner being scanned ("Chrome cache").
    pub current: String,
    pub bytes_found: u64,
    pub files_found: u64,
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started,
    CategoryStarted(Category),
    Progress(Progress),
    CategoryCompleted {
        category: Category,
        bytes: u64,
        files: u64,
    },
    Completed {
        bytes: u64,
    },
    Cancelled {
        bytes: u64,
    },
    Failed(String),
}

#[derive(Debug, Clone, Default)]
pub struct CleanProgress {
    pub done_files: u64,
    pub total_files: u64,
    pub done_bytes: u64,
}
