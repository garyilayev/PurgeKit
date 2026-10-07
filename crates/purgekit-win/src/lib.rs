//! Every Win32/NT call PurgeKit makes. This is the only crate allowed to use
//! `unsafe`; each block carries a `SAFETY:` comment.
//!
//! All file operations are handle-relative and never follow reparse points.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

mod delete;
pub mod elevate;
mod handle;
mod nt;
pub mod shell;
mod sys;
mod walk;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use purgekit_core::{KnownFolder, RelPath};
use purgekit_engine::backend::{
    FsBackend, FsError, OpenedFile, RootInfo, Skip, VolumeInfo, WalkVisitor,
};

pub use sys::long_path;

/// The real Windows backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinFs;

impl FsBackend for WinFs {
    fn resolve(&self, folder: KnownFolder) -> Option<PathBuf> {
        sys::resolve(folder)
    }

    fn walk(&self, root: &Path, visitor: &dyn WalkVisitor) -> Result<RootInfo, FsError> {
        walk::walk(root, visitor)
    }

    fn delete_file(
        &self,
        root: &Path,
        rel: &RelPath,
        check: &dyn Fn(&OpenedFile) -> Result<(), Skip>,
    ) -> Result<(), Skip> {
        delete::delete_file(root, rel, check)
    }

    fn remove_dir_if_empty(&self, root: &Path, rel: &RelPath) -> bool {
        delete::remove_dir_if_empty(root, rel)
    }

    fn running_processes(&self) -> HashSet<String> {
        sys::running_processes()
    }

    fn free_space(&self, path: &Path) -> Option<u64> {
        sys::free_space(path)
    }

    fn recycle_bin_query(&self) -> Option<(u64, u64)> {
        sys::recycle_bin_query()
    }

    fn recycle_bin_empty(&self) -> Result<(), Skip> {
        sys::recycle_bin_empty()
    }

    fn registry_key_exists(&self, key: &str) -> bool {
        sys::registry_key_exists(key)
    }

    fn volumes(&self) -> Vec<VolumeInfo> {
        sys::volumes()
    }

    fn has_seek_penalty(&self, path: &Path) -> bool {
        sys::has_seek_penalty(path)
    }

    fn background_mode_fn(&self) -> Option<fn()> {
        Some(sys::enter_background_mode)
    }
}
