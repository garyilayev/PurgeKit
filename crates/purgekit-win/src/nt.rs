//! Handle-relative, no-follow opens and handle-based queries.

use std::mem::{size_of, zeroed};
use std::path::Path;
use std::ptr::{null, null_mut};

use purgekit_core::{FileId128, FileTime};
use purgekit_rules::EntryTimes;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError, HANDLE,
    NTSTATUS, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
    FileAttributeTagInfo, FileBasicInfo, FileIdInfo, FileStandardInfo,
    GetFileInformationByHandleEx, OPEN_EXISTING, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::handle::{OwnedHandle, verbatim, wide_no_nul};

pub const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
pub const CLOUD_ATTRS: u32 =
    FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_OFFLINE;

pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034_u32 as i32;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS = 0xC000_003A_u32 as i32;
pub const STATUS_SHARING_VIOLATION: NTSTATUS = 0xC000_0043_u32 as i32;
pub const STATUS_DELETE_PENDING: NTSTATUS = 0xC000_0056_u32 as i32;
pub const STATUS_FILE_IS_A_DIRECTORY: NTSTATUS = 0xC000_00BA_u32 as i32;
pub const STATUS_NOT_A_DIRECTORY: NTSTATUS = 0xC000_0103_u32 as i32;

pub fn status_name(s: NTSTATUS) -> String {
    match s {
        STATUS_ACCESS_DENIED => "ACCESS_DENIED".into(),
        STATUS_OBJECT_NAME_NOT_FOUND => "OBJECT_NAME_NOT_FOUND".into(),
        STATUS_OBJECT_PATH_NOT_FOUND => "OBJECT_PATH_NOT_FOUND".into(),
        STATUS_SHARING_VIOLATION => "SHARING_VIOLATION".into(),
        STATUS_DELETE_PENDING => "DELETE_PENDING".into(),
        STATUS_FILE_IS_A_DIRECTORY => "FILE_IS_A_DIRECTORY".into(),
        STATUS_NOT_A_DIRECTORY => "NOT_A_DIRECTORY".into(),
        other => format!("NTSTATUS 0x{:08X}", other as u32),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootError {
    NotFound,
    AccessDenied,
    IsLink,
    NotDirectory,
    Other(u32),
}

/// Opens a rule root as a directory handle without following a reparse point
/// at the final component. A root that is itself a link is refused.
pub fn open_root_dir(path: &Path, extra_access: u32) -> Result<OwnedHandle, RootError> {
    let w = verbatim(path);
    // SAFETY: `w` is a NUL-terminated wide string that outlives the call.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE | extra_access,
            SHARE_ALL,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let Some(h) = OwnedHandle::new(h) else {
        // SAFETY: trivially safe.
        let e = unsafe { GetLastError() };
        return Err(match e {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => RootError::NotFound,
            ERROR_ACCESS_DENIED => RootError::AccessDenied,
            other => RootError::Other(other),
        });
    };
    let tag = attribute_tag(&h).map_err(RootError::Other)?;
    if tag.0 & FILE_ATTRIBUTE_REPARSE_POINT != 0 || tag.0 & CLOUD_ATTRS != 0 {
        return Err(RootError::IsLink);
    }
    if tag.0 & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(RootError::NotDirectory);
    }
    Ok(h)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenKind {
    Directory,
    File,
}

/// Opens one name relative to `parent` with `NtCreateFile`, never following a
/// reparse point. `name` must be a single component (validated by `RelPath`).
pub fn open_relative(
    parent: &OwnedHandle,
    name: &str,
    access: u32,
    kind: OpenKind,
) -> Result<OwnedHandle, NTSTATUS> {
    debug_assert!(!name.contains(['\\', '/']) && name != "." && name != "..");
    let buf = wide_no_nul(name);
    let bytes = (buf.len() * 2).min(u16::MAX as usize) as u16;
    let us = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: buf.as_ptr() as *mut u16,
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.raw(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let options = FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | FILE_OPEN_FOR_BACKUP_INTENT
        | match kind {
            OpenKind::Directory => FILE_DIRECTORY_FILE,
            OpenKind::File => FILE_NON_DIRECTORY_FILE,
        };
    let mut h: HANDLE = null_mut();
    // SAFETY: zeroed IO_STATUS_BLOCK is a valid initial value.
    let mut iosb: IO_STATUS_BLOCK = unsafe { zeroed() };
    // SAFETY: all pointers reference live locals for the duration of the call.
    let status = unsafe {
        NtCreateFile(
            &mut h,
            access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            null(),
            0,
            SHARE_ALL,
            FILE_OPEN,
            options,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(status);
    }
    OwnedHandle::new(h).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
}

fn query<T>(h: &OwnedHandle, class: i32) -> Result<T, u32> {
    // SAFETY: T is a plain C struct; zeroed is valid and the call writes at
    // most size_of::<T>() bytes.
    unsafe {
        let mut out: T = zeroed();
        if GetFileInformationByHandleEx(
            h.raw(),
            class,
            &mut out as *mut T as *mut _,
            size_of::<T>() as u32,
        ) == 0
        {
            return Err(GetLastError());
        }
        Ok(out)
    }
}

/// (attributes, reparse tag)
pub fn attribute_tag(h: &OwnedHandle) -> Result<(u32, u32), u32> {
    let t: FILE_ATTRIBUTE_TAG_INFO = query(h, FileAttributeTagInfo)?;
    Ok((t.FileAttributes, t.ReparseTag))
}

/// (volume serial, 128-bit file ID)
pub fn file_id(h: &OwnedHandle) -> Result<(u64, FileId128), u32> {
    let i: FILE_ID_INFO = query(h, FileIdInfo)?;
    Ok((i.VolumeSerialNumber, FileId128(i.FileId.Identifier)))
}

pub struct Standard {
    pub alloc: u64,
    pub links: u32,
    pub directory: bool,
    pub delete_pending: bool,
}

pub fn standard(h: &OwnedHandle) -> Result<Standard, u32> {
    let s: FILE_STANDARD_INFO = query(h, FileStandardInfo)?;
    Ok(Standard {
        alloc: s.AllocationSize.max(0) as u64,
        links: s.NumberOfLinks,
        directory: s.Directory,
        delete_pending: s.DeletePending,
    })
}

pub fn basic(h: &OwnedHandle) -> Result<(EntryTimes, u32), u32> {
    let b: FILE_BASIC_INFO = query(h, FileBasicInfo)?;
    Ok((
        EntryTimes {
            created: ft(b.CreationTime),
            modified: ft(b.LastWriteTime),
            changed: ft(b.ChangeTime),
        },
        b.FileAttributes,
    ))
}

pub fn ft(v: i64) -> FileTime {
    FileTime(v.max(0) as u64)
}

pub fn is_readonly(attrs: u32) -> bool {
    attrs & FILE_ATTRIBUTE_READONLY != 0
}
