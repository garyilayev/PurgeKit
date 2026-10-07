//! Handle-based deletion. The path is walked one component at a time, each
//! opened relative to its parent without following reparse points; the final
//! handle is checked and then deleted through, so a file swapped after the
//! check cannot be the file deleted.

use std::mem::size_of;
use std::path::Path;

use purgekit_core::{RelPath, SkipReason};
use purgekit_engine::backend::{OpenedFile, Skip};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_DIR_NOT_EMPTY, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER,
    ERROR_NOT_SUPPORTED, ERROR_SHARING_VIOLATION, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, FileDispositionInfo,
    FileDispositionInfoEx, SetFileInformationByHandle,
};

use crate::handle::OwnedHandle;
use crate::nt::{self, CLOUD_ATTRS, OpenKind, RootError};

fn map_status(s: i32) -> Skip {
    let reason = match s {
        nt::STATUS_SHARING_VIOLATION => SkipReason::InUse,
        nt::STATUS_ACCESS_DENIED => SkipReason::AccessDenied,
        nt::STATUS_OBJECT_NAME_NOT_FOUND
        | nt::STATUS_OBJECT_PATH_NOT_FOUND
        | nt::STATUS_DELETE_PENDING
        | nt::STATUS_FILE_IS_A_DIRECTORY
        | nt::STATUS_NOT_A_DIRECTORY => SkipReason::Changed,
        _ => SkipReason::Other,
    };
    Skip::with(reason, nt::status_name(s))
}

fn map_win32(e: u32) -> Skip {
    match e {
        ERROR_SHARING_VIOLATION => Skip::with(SkipReason::InUse, "SHARING_VIOLATION"),
        ERROR_ACCESS_DENIED => Skip::with(SkipReason::AccessDenied, "ACCESS_DENIED"),
        other => Skip::with(SkipReason::Other, format!("error {other}")),
    }
}

/// Opens every directory of `rel` below `root` (not the last component).
fn open_parent_chain(root: &Path, rel: &RelPath) -> Result<(OwnedHandle, String), Skip> {
    let mut cur = nt::open_root_dir(root, 0).map_err(|e| match e {
        RootError::IsLink => Skip::with(SkipReason::LinkOrCloud, "root is a link"),
        RootError::AccessDenied => Skip::with(SkipReason::AccessDenied, "ACCESS_DENIED"),
        _ => Skip::with(SkipReason::Changed, "root unavailable"),
    })?;
    let comps: Vec<&str> = rel.components().collect();
    let Some((last, dirs)) = comps.split_last() else {
        return Err(Skip::with(SkipReason::UnsafePath, "empty path"));
    };
    for d in dirs {
        let h = nt::open_relative(
            &cur,
            d,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            OpenKind::Directory,
        )
        .map_err(map_status)?;
        let (attrs, _) = nt::attribute_tag(&h).map_err(map_win32)?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs & CLOUD_ATTRS != 0 {
            return Err(Skip::with(
                SkipReason::LinkOrCloud,
                "path component is a link",
            ));
        }
        cur = h;
    }
    Ok((cur, (*last).to_string()))
}

/// Marks the handle for deletion with POSIX semantics (the name disappears
/// immediately); falls back to classic disposition where Ex is unsupported.
fn delete_on_handle(h: &OwnedHandle) -> Result<(), u32> {
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: valid handle and a correctly sized input struct.
    let ok = unsafe {
        SetFileInformationByHandle(
            h.raw(),
            FileDispositionInfoEx,
            &ex as *const _ as *const _,
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    // SAFETY: trivially safe.
    let e = unsafe { GetLastError() };
    if !matches!(
        e,
        ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION
    ) {
        return Err(e);
    }
    let classic = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: as above.
    let ok = unsafe {
        SetFileInformationByHandle(
            h.raw(),
            FileDispositionInfo,
            &classic as *const _ as *const _,
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        // SAFETY: trivially safe.
        Err(unsafe { GetLastError() })
    }
}

pub fn delete_file(
    root: &Path,
    rel: &RelPath,
    check: &dyn Fn(&OpenedFile) -> Result<(), Skip>,
) -> Result<(), Skip> {
    let (parent, name) = open_parent_chain(root, rel)?;
    let h = nt::open_relative(
        &parent,
        &name,
        DELETE | FILE_READ_ATTRIBUTES,
        OpenKind::File,
    )
    .map_err(map_status)?;
    let (attrs, _) = nt::attribute_tag(&h).map_err(map_win32)?;
    let (volume_serial, file_id) = nt::file_id(&h).map_err(map_win32)?;
    let std_info = nt::standard(&h).map_err(map_win32)?;
    let (times, _) = nt::basic(&h).map_err(map_win32)?;
    if std_info.delete_pending {
        return Err(Skip::with(SkipReason::Changed, "DELETE_PENDING"));
    }
    let opened = OpenedFile {
        volume_serial,
        file_id,
        is_dir: std_info.directory,
        readonly: nt::is_readonly(attrs),
        reparse: attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        cloud: attrs & CLOUD_ATTRS != 0,
        link_count: std_info.links,
        alloc_size: std_info.alloc,
        times,
    };
    check(&opened)?;
    delete_on_handle(&h).map_err(map_win32)
}

pub fn remove_dir_if_empty(root: &Path, rel: &RelPath) -> bool {
    let Ok((parent, name)) = open_parent_chain(root, rel) else {
        return false;
    };
    let Ok(h) = nt::open_relative(
        &parent,
        &name,
        DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        OpenKind::Directory,
    ) else {
        return false;
    };
    match nt::attribute_tag(&h) {
        Ok((attrs, _)) if attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0 && attrs & CLOUD_ATTRS == 0 => {
        }
        _ => return false,
    }
    // NTFS refuses to delete a non-empty directory (ERROR_DIR_NOT_EMPTY), so
    // emptiness is checked atomically by the file system. Never recursive.
    match delete_on_handle(&h) {
        Ok(()) => true,
        Err(ERROR_DIR_NOT_EMPTY) => false,
        Err(_) => false,
    }
}
