use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// Owned kernel handle, closed on drop.
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

// SAFETY: a kernel handle is a process-wide value; sharing it between threads
// is fine. All operations on it go through thread-safe kernel calls.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    /// Takes ownership of `h` unless it is null or `INVALID_HANDLE_VALUE`.
    pub fn new(h: HANDLE) -> Option<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(OwnedHandle(h))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// NUL-terminated UTF-16.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// UTF-16 without terminator (for `UNICODE_STRING`).
pub fn wide_no_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// `\\?\` form of an absolute path, so `MAX_PATH` never applies.
pub fn verbatim(path: &Path) -> Vec<u16> {
    let s = path.as_os_str().to_string_lossy();
    let s = s.replace('/', "\\");
    if s.starts_with(r"\\?\") {
        wide(&s)
    } else if let Some(unc) = s.strip_prefix(r"\\") {
        wide(format!(r"\\?\UNC\{unc}"))
    } else {
        wide(format!(r"\\?\{s}"))
    }
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
