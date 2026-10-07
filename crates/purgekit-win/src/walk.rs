//! Custom walker: handle-relative directory enumeration with
//! `GetFileInformationByHandleEx(FileIdExtdDirectoryInfo)`. One call returns a
//! batch of entries with attributes, reparse tag, sizes, timestamps and a
//! 128-bit file ID, without opening any file. Subdirectories are opened
//! relative to their parent handle, so a renamed or swapped parent cannot
//! redirect the walk. Reparse points and cloud files are skipped, never entered.

use std::mem::offset_of;
use std::path::Path;

use purgekit_core::{FileId128, RelPath};
use purgekit_engine::backend::{FsError, RootInfo, WalkEntry, WalkSkip, WalkVisitor};
use purgekit_rules::EntryTimes;
use rayon::prelude::*;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_NOT_SUPPORTED, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
    FILE_ID_EXTD_DIR_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FileIdBothDirectoryInfo,
    FileIdExtdDirectoryInfo, GetFileInformationByHandleEx,
};

use crate::handle::OwnedHandle;
use crate::nt::{self, CLOUD_ATTRS, OpenKind, RootError};

/// One raw directory entry.
struct Raw {
    name: String,
    attrs: u32,
    file_id: FileId128,
    logical: u64,
    alloc: u64,
    times: EntryTimes,
}

const BUF_BYTES: usize = 64 * 1024;

/// Enumerates a directory handle. Falls back to `FileIdBothDirectoryInfo`
/// (64-bit IDs) on file systems without extended IDs.
fn enumerate(dir: &OwnedHandle, out: &mut Vec<Raw>, bad_names: &mut u64) -> Result<(), u32> {
    let mut buf = vec![0u64; BUF_BYTES / 8];
    let mut class = FileIdExtdDirectoryInfo;
    let mut first = true;
    loop {
        // SAFETY: buf is a writable, 8-byte aligned buffer of BUF_BYTES bytes.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.raw(),
                class,
                buf.as_mut_ptr() as *mut _,
                BUF_BYTES as u32,
            )
        };
        if ok == 0 {
            // SAFETY: trivially safe.
            let e = unsafe { GetLastError() };
            if e == ERROR_NO_MORE_FILES {
                return Ok(());
            }
            if first
                && class == FileIdExtdDirectoryInfo
                && (e == ERROR_INVALID_PARAMETER || e == ERROR_NOT_SUPPORTED)
            {
                class = FileIdBothDirectoryInfo;
                continue;
            }
            return Err(e);
        }
        first = false;
        let base = buf.as_ptr() as *const u8;
        let mut off = 0usize;
        loop {
            if off + 8 > BUF_BYTES {
                break;
            }
            // SAFETY: the kernel filled a chain of entries inside `buf`; every
            // read is bounds-checked against BUF_BYTES and done unaligned.
            let (next, raw) = unsafe {
                let p = base.add(off);
                if class == FileIdExtdDirectoryInfo {
                    let e = std::ptr::read_unaligned(p as *const FILE_ID_EXTD_DIR_INFO);
                    let name_off = offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
                    let len = e.FileNameLength as usize;
                    if off + name_off + len > BUF_BYTES {
                        break;
                    }
                    let name = read_name(p.add(name_off), len);
                    (
                        e.NextEntryOffset as usize,
                        name.map(|name| Raw {
                            name,
                            attrs: e.FileAttributes,
                            file_id: FileId128(e.FileId.Identifier),
                            logical: e.EndOfFile.max(0) as u64,
                            alloc: e.AllocationSize.max(0) as u64,
                            times: EntryTimes {
                                created: nt::ft(e.CreationTime),
                                modified: nt::ft(e.LastWriteTime),
                                changed: nt::ft(e.ChangeTime),
                            },
                        }),
                    )
                } else {
                    let e = std::ptr::read_unaligned(p as *const FILE_ID_BOTH_DIR_INFO);
                    let name_off = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                    let len = e.FileNameLength as usize;
                    if off + name_off + len > BUF_BYTES {
                        break;
                    }
                    let name = read_name(p.add(name_off), len);
                    (
                        e.NextEntryOffset as usize,
                        name.map(|name| Raw {
                            name,
                            attrs: e.FileAttributes,
                            file_id: FileId128::from_u64(e.FileId as u64),
                            logical: e.EndOfFile.max(0) as u64,
                            alloc: e.AllocationSize.max(0) as u64,
                            times: EntryTimes {
                                created: nt::ft(e.CreationTime),
                                modified: nt::ft(e.LastWriteTime),
                                changed: nt::ft(e.ChangeTime),
                            },
                        }),
                    )
                }
            };
            match raw {
                Some(r) if r.name == "." || r.name == ".." => {}
                Some(r) => out.push(r),
                None => *bad_names += 1,
            }
            if next == 0 {
                break;
            }
            off += next;
        }
    }
}

/// Strict UTF-16 decode: names that are not valid Unicode cannot be
/// represented safely and are skipped.
///
/// # Safety
/// `p` must point to `len_bytes` readable bytes.
unsafe fn read_name(p: *const u8, len_bytes: usize) -> Option<String> {
    let mut units = vec![0u16; len_bytes / 2];
    // SAFETY: guaranteed by the caller.
    unsafe { std::ptr::copy_nonoverlapping(p, units.as_mut_ptr() as *mut u8, units.len() * 2) };
    String::from_utf16(&units).ok()
}

fn walk_dir(dir: &OwnedHandle, rel: &RelPath, visitor: &dyn WalkVisitor) {
    if visitor.cancelled() {
        return;
    }
    let mut raw = Vec::new();
    let mut bad = 0u64;
    if enumerate(dir, &mut raw, &mut bad).is_err() {
        visitor.skipped(WalkSkip::Unreadable);
        return;
    }
    for _ in 0..bad {
        visitor.skipped(WalkSkip::BadName);
    }
    let mut files = Vec::new();
    let mut subdirs: Vec<(String, RelPath)> = Vec::new();
    for r in raw {
        if r.attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            visitor.skipped(WalkSkip::ReparsePoint);
            continue;
        }
        if r.attrs & CLOUD_ATTRS != 0 {
            visitor.skipped(WalkSkip::Cloud);
            continue;
        }
        let Ok(child) = rel.join(&r.name) else {
            visitor.skipped(WalkSkip::BadName);
            continue;
        };
        if r.attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            subdirs.push((r.name, child));
        } else {
            files.push(WalkEntry {
                rel: child,
                file_id: r.file_id,
                logical_size: r.logical,
                alloc_size: r.alloc,
                times: r.times,
                readonly: nt::is_readonly(r.attrs),
            });
        }
    }
    if !files.is_empty() {
        visitor.files(files);
    }
    subdirs.retain(|(_, child)| visitor.enter_dir(child));
    subdirs.par_iter().for_each(|(name, child)| {
        let Ok(h) = nt::open_relative(
            dir,
            name,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            OpenKind::Directory,
        ) else {
            visitor.skipped(WalkSkip::Unreadable);
            return;
        };
        // The entry might have been swapped for a link since enumeration;
        // FILE_OPEN_REPARSE_POINT opened the link itself, so check and refuse.
        match nt::attribute_tag(&h) {
            Ok((attrs, _)) if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                visitor.skipped(WalkSkip::ReparsePoint)
            }
            Ok((attrs, _)) if attrs & CLOUD_ATTRS != 0 => visitor.skipped(WalkSkip::Cloud),
            Ok(_) => walk_dir(&h, child, visitor),
            Err(_) => visitor.skipped(WalkSkip::Unreadable),
        }
    });
}

pub fn walk(root: &Path, visitor: &dyn WalkVisitor) -> Result<RootInfo, FsError> {
    let h = nt::open_root_dir(root, 0).map_err(|e| match e {
        RootError::NotFound => FsError::NotFound,
        RootError::AccessDenied => FsError::AccessDenied,
        RootError::IsLink => FsError::RootIsLink,
        RootError::NotDirectory => FsError::Other("root is not a directory".into()),
        RootError::Other(c) => FsError::Other(format!("error {c}")),
    })?;
    let (volume_serial, _) =
        nt::file_id(&h).map_err(|c| FsError::Other(format!("file id error {c}")))?;
    walk_dir(&h, &RelPath::root(), visitor);
    Ok(RootInfo { volume_serial })
}
