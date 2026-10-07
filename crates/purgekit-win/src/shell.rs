//! Small UI helpers: local time formatting and plain-text clipboard.

use std::mem::zeroed;
use std::ptr::{null, null_mut};

use purgekit_core::FileTime;
use windows_sys::Win32::Foundation::{FILETIME, GlobalFree, SYSTEMTIME};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

const CF_UNICODETEXT: u32 = 13;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn local(t: FileTime) -> Option<SYSTEMTIME> {
    let ft = FILETIME {
        dwLowDateTime: t.0 as u32,
        dwHighDateTime: (t.0 >> 32) as u32,
    };
    // SAFETY: out-structs are valid locals.
    unsafe {
        let mut utc: SYSTEMTIME = zeroed();
        let mut loc: SYSTEMTIME = zeroed();
        if FileTimeToSystemTime(&ft, &mut utc) == 0
            || SystemTimeToTzSpecificLocalTime(null(), &utc, &mut loc) == 0
        {
            return None;
        }
        Some(loc)
    }
}

/// "Oct 7, 2026"
pub fn format_date(t: FileTime) -> String {
    match local(t) {
        Some(s) if (1..=12).contains(&s.wMonth) => {
            format!("{} {}, {}", MONTHS[s.wMonth as usize - 1], s.wDay, s.wYear)
        }
        _ => String::new(),
    }
}

/// "Oct 7, 2026, 4:05 PM"
pub fn format_date_time(t: FileTime) -> String {
    match local(t) {
        Some(s) if (1..=12).contains(&s.wMonth) => {
            let (h, ampm) = match s.wHour {
                0 => (12, "AM"),
                1..=11 => (s.wHour, "AM"),
                12 => (12, "PM"),
                h => (h - 12, "PM"),
            };
            format!(
                "{} {}, {}, {}:{:02} {}",
                MONTHS[s.wMonth as usize - 1],
                s.wDay,
                s.wYear,
                h,
                s.wMinute,
                ampm
            )
        }
        _ => String::new(),
    }
}

/// Puts plain text on the clipboard.
pub fn set_clipboard_text(text: &str) -> bool {
    let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = units.len() * 2;
    // SAFETY: standard clipboard sequence; on success the system owns the
    // memory, on failure we free it.
    unsafe {
        if OpenClipboard(null_mut()) == 0 {
            return false;
        }
        EmptyClipboard();
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if mem.is_null() {
            CloseClipboard();
            return false;
        }
        let p = GlobalLock(mem) as *mut u16;
        if p.is_null() {
            GlobalFree(mem);
            CloseClipboard();
            return false;
        }
        std::ptr::copy_nonoverlapping(units.as_ptr(), p, units.len());
        GlobalUnlock(mem);
        let ok = !SetClipboardData(CF_UNICODETEXT, mem).is_null();
        if !ok {
            GlobalFree(mem);
        }
        CloseClipboard();
        ok
    }
}
