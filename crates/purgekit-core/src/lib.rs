//! PurgeKit domain types shared by every other crate.
//!
//! This crate contains no OS code. It owns the protected-data deny-list
//! ([`protected`]), which is code rather than a rule file so that no rule bug,
//! rule edit or user action can reach those files.

#![forbid(unsafe_code)]

pub mod format;
pub mod path;
pub mod telemetry;
pub mod time;
pub mod types;

pub use path::{PathError, RelPath};
pub use time::{AgeSpec, FileTime};
pub use types::*;
