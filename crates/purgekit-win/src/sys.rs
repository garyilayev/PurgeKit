//! System queries: known folders, processes, free space, Recycle Bin,
//! registry presence, drives, seek penalty and background priority.

use std::collections::HashSet;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use purgekit_core::{KnownFolder, SkipReason};
use purgekit_engine::backend::{Skip, VolumeInfo};
use windows_sys::Win32::Foundation::{HANDLE, S_OK};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetLongPathNameW,
    GetVolumeInformationW, OPEN_EXISTING,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    DEVICE_SEEK_PENALTY_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
    STORAGE_PROPERTY_QUERY, StorageDeviceSeekPenaltyProperty,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_LocalAppDataLow, FOLDERID_ProgramData, FOLDERID_RoamingAppData,
    FOLDERID_Windows, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHEmptyRecycleBinW,
    SHGetKnownFolderPath, SHQUERYRBINFO, SHQueryRecycleBinW,
};
use windows_sys::core::GUID;

use crate::handle::{OwnedHandle, from_wide, wide};
use crate::nt::SHARE_ALL;

const DRIVE_FIXED: u32 = 3;

fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut p: windows_sys::core::PWSTR = null_mut();
    // SAFETY: p receives a CoTaskMem string we free below.
    let hr = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut p) };
    if hr != S_OK || p.is_null() {
        if !p.is_null() {
            // SAFETY: allocated by the shell.
            unsafe { CoTaskMemFree(p as *const _) };
        }
        return None;
    }
    // SAFETY: p is a valid NUL-terminated string.
    let s = unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        CoTaskMemFree(p as *const _);
        s
    };
    Some(PathBuf::from(s))
}

type GetTempPath2Fn = unsafe extern "system" fn(u32, *mut u16) -> u32;

/// `GetTempPath2W` where available (looked up at run time so the binary
/// still loads on older Windows 10 builds), else `GetTempPathW`. Short (8.3)
/// components are expanded, since the protected check refuses short names.
fn temp_dir() -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    // SAFETY: kernel32 is always loaded; the transmuted pointer has the
    // documented GetTempPath2W signature.
    let len = unsafe {
        let k32 = GetModuleHandleW(wide("kernel32.dll").as_ptr());
        let f = if k32.is_null() {
            None
        } else {
            GetProcAddress(k32, c"GetTempPath2W".as_ptr() as *const u8)
        };
        match f {
            Some(f) => {
                let f: GetTempPath2Fn = std::mem::transmute(f);
                f(buf.len() as u32, buf.as_mut_ptr())
            }
            None => windows_sys::Win32::Storage::FileSystem::GetTempPathW(
                buf.len() as u32,
                buf.as_mut_ptr(),
            ),
        }
    };
    if len == 0 || len as usize >= buf.len() {
        return None;
    }
    let short = from_wide(&buf[..len as usize]);
    Some(long_path(Path::new(short.trim_end_matches('\\'))))
}

pub fn long_path(p: &Path) -> PathBuf {
    let w = wide(p);
    let mut out = vec![0u16; 32_768];
    // SAFETY: buffers are valid for their stated lengths.
    let n = unsafe { GetLongPathNameW(w.as_ptr(), out.as_mut_ptr(), out.len() as u32) };
    if n == 0 || n as usize >= out.len() {
        return p.to_path_buf();
    }
    PathBuf::from(from_wide(&out[..n as usize]))
}

pub fn resolve(folder: KnownFolder) -> Option<PathBuf> {
    let p = match folder {
        KnownFolder::Temp => return temp_dir(),
        KnownFolder::LocalAppData => known_folder(&FOLDERID_LocalAppData),
        KnownFolder::RoamingAppData => known_folder(&FOLDERID_RoamingAppData),
        KnownFolder::LocalAppDataLow => known_folder(&FOLDERID_LocalAppDataLow),
        KnownFolder::ProgramData => known_folder(&FOLDERID_ProgramData),
        KnownFolder::Windows => known_folder(&FOLDERID_Windows),
    }?;
    Some(long_path(&p))
}

pub fn running_processes() -> HashSet<String> {
    let mut out = HashSet::new();
    // SAFETY: snapshot handle is owned and closed; entry struct is sized.
    unsafe {
        let Some(snap) = OwnedHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) else {
            return out;
        };
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap.raw(), &mut e) != 0 {
            loop {
                out.insert(from_wide(&e.szExeFile).to_lowercase());
                if Process32NextW(snap.raw(), &mut e) == 0 {
                    break;
                }
            }
        }
    }
    out
}

pub fn free_space(path: &Path) -> Option<u64> {
    let w = wide(path);
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY: out-pointers are valid locals.
    let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) };
    (ok != 0).then_some(free)
}

pub fn recycle_bin_query() -> Option<(u64, u64)> {
    // SAFETY: zeroed struct with cbSize set, as documented.
    unsafe {
        let mut info: SHQUERYRBINFO = zeroed();
        info.cbSize = size_of::<SHQUERYRBINFO>() as u32;
        if SHQueryRecycleBinW(null(), &mut info) != S_OK {
            return None;
        }
        Some((info.i64Size.max(0) as u64, info.i64NumItems.max(0) as u64))
    }
}

pub fn recycle_bin_empty() -> Result<(), Skip> {
    // SAFETY: no window, all drives, no UI.
    let hr = unsafe {
        SHEmptyRecycleBinW(
            null_mut(),
            null(),
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
        )
    };
    // E_UNEXPECTED is returned when the bin is already empty.
    if hr == S_OK || hr == 0x8000_FFFF_u32 as i32 {
        Ok(())
    } else {
        Err(Skip::with(
            SkipReason::Other,
            format!("HRESULT 0x{:08X}", hr as u32),
        ))
    }
}

/// Read-only presence check. Accepts `HKCU\...` / `HKLM\...`.
pub fn registry_key_exists(key: &str) -> bool {
    let (hive, sub): (HKEY, &str) = if let Some(s) = key.strip_prefix(r"HKCU\") {
        (HKEY_CURRENT_USER, s)
    } else if let Some(s) = key.strip_prefix(r"HKLM\") {
        (HKEY_LOCAL_MACHINE, s)
    } else {
        return false;
    };
    let w = wide(sub);
    let mut hk: HKEY = null_mut();
    // SAFETY: valid hive, NUL-terminated subkey, out-pointer local.
    unsafe {
        if RegOpenKeyExW(hive, w.as_ptr(), 0, KEY_READ, &mut hk) == 0 {
            RegCloseKey(hk);
            true
        } else {
            false
        }
    }
}

pub fn volumes() -> Vec<VolumeInfo> {
    let mut out = Vec::new();
    // SAFETY: trivially safe.
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root = format!("{letter}:\\");
        let w = wide(&root);
        // SAFETY: NUL-terminated root path.
        if unsafe { GetDriveTypeW(w.as_ptr()) } != DRIVE_FIXED {
            continue;
        }
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        // SAFETY: out-pointers are valid locals.
        if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) } == 0 {
            continue;
        }
        let mut label = vec![0u16; 261];
        // SAFETY: label buffer sized as declared; optional outputs null.
        unsafe {
            GetVolumeInformationW(
                w.as_ptr(),
                label.as_mut_ptr(),
                label.len() as u32,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                0,
            );
        }
        out.push(VolumeInfo {
            name: format!("{letter}:"),
            label: from_wide(&label),
            root: PathBuf::from(root),
            total,
            free,
        });
    }
    out
}

/// True if the drive holding `path` reports a seek penalty (rotational disk).
pub fn has_seek_penalty(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let Some(letter) = s.chars().next().filter(|c| c.is_ascii_alphabetic()) else {
        return false;
    };
    let dev = wide(format!(r"\\.\{letter}:"));
    // SAFETY: zero access is enough for IOCTL_STORAGE_QUERY_PROPERTY; all
    // buffers are sized locals.
    unsafe {
        let h: HANDLE = CreateFileW(
            dev.as_ptr(),
            0,
            SHARE_ALL,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        let Some(h) = OwnedHandle::new(h) else {
            return false;
        };
        let mut q: STORAGE_PROPERTY_QUERY = zeroed();
        q.PropertyId = StorageDeviceSeekPenaltyProperty;
        q.QueryType = PropertyStandardQuery;
        let mut d: DEVICE_SEEK_PENALTY_DESCRIPTOR = zeroed();
        let mut ret = 0u32;
        let ok = DeviceIoControl(
            h.raw(),
            IOCTL_STORAGE_QUERY_PROPERTY,
            &q as *const _ as *const _,
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            &mut d as *mut _ as *mut _,
            size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            &mut ret,
            null_mut(),
        );
        ok != 0 && d.IncursSeekPenalty
    }
}

/// Puts the calling thread in background mode (low I/O and memory priority).
pub fn enter_background_mode() {
    // SAFETY: affects only the current thread.
    unsafe {
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    }
}
