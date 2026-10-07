//! PurgeKit engine: scanner, result tree, cleanup plan and cleaner.
//!
//! The engine talks to the OS only through [`backend::FsBackend`]. Scanning
//! never deletes; deletion only consumes an immutable [`plan::CleanupPlan`].

#![forbid(unsafe_code)]

pub mod backend;
pub mod cancel;
pub mod clean;
pub mod events;
pub mod exclusions;
pub mod helper;
pub mod plan;
pub mod scan;
pub mod testing;
pub mod tree;

pub use backend::FsBackend;
pub use cancel::CancelToken;
pub use clean::{CleanOptions, CleanReport, clean};
pub use exclusions::{Exclusion, Exclusions};
pub use plan::CleanupPlan;
pub use scan::{ScanOptions, ScanResult, scan};
pub use tree::{NodeKind, ResultTree};
