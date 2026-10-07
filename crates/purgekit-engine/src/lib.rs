//! PurgeKit engine: scanner, result tree, cleanup plan and cleaner.
//!
//! The engine talks to the OS only through [`backend::FsBackend`]. Scanning
//! never deletes; deletion only consumes an immutable [`plan::CleanupPlan`].

#![forbid(unsafe_code)]

pub mod backend;
pub mod cancel;
pub mod events;
pub mod exclusions;
pub mod plan;
pub mod testing;
pub mod tree;

pub use backend::FsBackend;
pub use cancel::CancelToken;
pub use exclusions::{Exclusion, Exclusions};
pub use plan::CleanupPlan;
pub use tree::{NodeKind, ResultTree};
