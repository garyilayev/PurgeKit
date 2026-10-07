//! Elevated helper launch (`ShellExecuteExW` with `runas`) and the named pipe
//! between the main app (server) and the helper (client).
//!
//! The pipe's DACL admits only the invoking user's SID and elevated
//! Administrators (needed when a standard user elevates with another account).
//! The server also verifies that the connecting client is the process it
//! launched. Remote clients are rejected.

use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_CANCELLED, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetExitCodeProcess, GetProcessId, OpenProcessToken,
    WaitForMultipleObjects, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::handle::{OwnedHandle, wide};

const MAX_MESSAGE: usize = 64 << 20;

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// String SID of the current process user.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: token handle owned; buffer sized from the first call; the SID
    // string is LocalFree'd.
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return Err(last_error());
        }
        let tok = OwnedHandle::new(tok).ok_or_else(last_error)?;
        let mut len = 0u32;
        GetTokenInformation(tok.raw(), TokenUser, null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        if GetTokenInformation(
            tok.raw(),
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            len,
            &mut len,
        ) == 0
        {
            return Err(last_error());
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s: *mut u16 = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
            return Err(last_error());
        }
        let n = (0..).take_while(|&i| *s.add(i) != 0).count();
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s as *mut _);
        Ok(out)
    }
}

/// A unique pipe name for one clean.
pub fn new_pipe_name() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(r"\\.\pipe\purgekit-{}-{:x}", std::process::id(), t)
}

#[derive(Debug)]
pub enum LaunchError {
    /// The user declined the UAC prompt.
    Cancelled,
    Failed(io::Error),
}

pub struct ElevatedProcess {
    handle: OwnedHandle,
    pub pid: u32,
}

impl ElevatedProcess {
    /// Waits up to `ms`; returns the exit code if the process ended.
    pub fn wait(&self, ms: u32) -> Option<u32> {
        // SAFETY: valid process handle.
        unsafe {
            if WaitForSingleObject(self.handle.raw(), ms) != WAIT_OBJECT_0 {
                return None;
            }
            let mut code = 0u32;
            (GetExitCodeProcess(self.handle.raw(), &mut code) != 0).then_some(code)
        }
    }
}

/// Starts `exe` elevated with one UAC prompt.
pub fn launch_elevated(exe: &Path, params: &str) -> Result<ElevatedProcess, LaunchError> {
    let verb = wide("runas");
    let file = wide(exe);
    let args = wide(params);
    // SAFETY: all strings outlive the call; struct zeroed with cbSize set.
    unsafe {
        let mut sei: SHELLEXECUTEINFOW = zeroed();
        sei.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = file.as_ptr();
        sei.lpParameters = args.as_ptr();
        sei.nShow = SW_HIDE;
        if ShellExecuteExW(&mut sei) == 0 {
            return Err(if GetLastError() == ERROR_CANCELLED {
                LaunchError::Cancelled
            } else {
                LaunchError::Failed(last_error())
            });
        }
        let handle = OwnedHandle::new(sei.hProcess)
            .ok_or_else(|| LaunchError::Failed(io::Error::other("no process handle")))?;
        let pid = GetProcessId(handle.raw());
        Ok(ElevatedProcess { handle, pid })
    }
}

/// Server end of the helper pipe (main app).
pub struct PipeServer {
    pipe: OwnedHandle,
    event: OwnedHandle,
}

impl PipeServer {
    pub fn create(name: &str) -> io::Result<Self> {
        let sid = current_user_sid()?;
        let sddl = wide(format!("D:P(A;;GA;;;{sid})(A;;GA;;;BA)"));
        // SAFETY: SD allocated by the API and LocalFree'd after the pipe exists.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ) == 0
            {
                return Err(last_error());
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let w = wide(name);
            let h = CreateNamedPipeW(
                w.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            );
            LocalFree(sd as *mut _);
            let pipe = OwnedHandle::new(h).ok_or_else(last_error)?;
            let event =
                OwnedHandle::new(CreateEventW(null(), 1, 0, null())).ok_or_else(last_error)?;
            Ok(PipeServer { pipe, event })
        }
    }

    fn overlapped(&self) -> OVERLAPPED {
        // SAFETY: zeroed OVERLAPPED is valid; we set the event.
        let mut ov: OVERLAPPED = unsafe { zeroed() };
        ov.hEvent = self.event.raw();
        ov
    }

    /// Waits for `process` to connect. Fails if it exits first, if the wait
    /// times out, or if a different process connects.
    pub fn accept(&self, process: &ElevatedProcess, timeout_ms: u32) -> io::Result<()> {
        let mut ov = self.overlapped();
        // SAFETY: `ov` lives until the operation completes or the handle is
        // closed (which cancels it).
        unsafe {
            if ConnectNamedPipe(self.pipe.raw(), &mut ov) == 0 {
                match GetLastError() {
                    ERROR_PIPE_CONNECTED => {}
                    ERROR_IO_PENDING => {
                        let handles = [self.event.raw(), process.handle.raw()];
                        match WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout_ms) {
                            WAIT_OBJECT_0 => {
                                let mut n = 0u32;
                                if GetOverlappedResult(self.pipe.raw(), &ov, &mut n, 0) == 0 {
                                    return Err(last_error());
                                }
                            }
                            WAIT_TIMEOUT => {
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "helper did not connect",
                                ));
                            }
                            _ => return Err(io::Error::other("helper exited before connecting")),
                        }
                    }
                    _ => return Err(last_error()),
                }
            }
            let mut client = 0u32;
            if GetNamedPipeClientProcessId(self.pipe.raw(), &mut client) == 0
                || client != process.pid
            {
                DisconnectNamedPipe(self.pipe.raw());
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unexpected pipe client",
                ));
            }
        }
        Ok(())
    }

    fn io(&self, write: bool, buf: *mut u8, len: usize) -> io::Result<usize> {
        let mut ov = self.overlapped();
        let mut n = 0u32;
        // SAFETY: buf is valid for len bytes for the whole (waited) operation.
        unsafe {
            let ok = if write {
                WriteFile(self.pipe.raw(), buf, len as u32, null_mut(), &mut ov)
            } else {
                ReadFile(self.pipe.raw(), buf, len as u32, null_mut(), &mut ov)
            };
            if ok == 0 {
                let e = GetLastError();
                if e == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                if e != ERROR_IO_PENDING {
                    return Err(last_error());
                }
            }
            if GetOverlappedResult(self.pipe.raw(), &ov, &mut n, 1) == 0 {
                if GetLastError() == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                return Err(last_error());
            }
        }
        Ok(n as usize)
    }

    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        let mut framed = (msg.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(msg);
        let mut off = 0;
        while off < framed.len() {
            let n = self.io(true, framed[off..].as_mut_ptr(), framed.len() - off)?;
            if n == 0 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            off += n;
        }
        Ok(())
    }

    pub fn recv(&self) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_exact(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = self.io(false, buf[off..].as_mut_ptr(), buf.len() - off)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            off += n;
        }
        Ok(())
    }
}

/// Client end (helper). Connects with identification-level impersonation
/// only and checks that the server is the expected process.
pub fn connect_client(name: &str, expected_server_pid: u32) -> io::Result<File> {
    let w = wide(name);
    // SAFETY: NUL-terminated name; the handle is moved into a File.
    unsafe {
        let h = CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        );
        let h = OwnedHandle::new(h).ok_or_else(last_error)?;
        let mut server = 0u32;
        if GetNamedPipeServerProcessId(h.raw(), &mut server) == 0 || server != expected_server_pid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected pipe server",
            ));
        }
        let raw = h.raw();
        std::mem::forget(h);
        Ok(File::from_raw_handle(raw as _))
    }
}

/// Framing helpers for the client side.
pub fn write_msg(f: &mut impl io::Write, msg: &[u8]) -> io::Result<()> {
    f.write_all(&(msg.len() as u32).to_le_bytes())?;
    f.write_all(msg)?;
    f.flush()
}

pub fn read_msg(f: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    f.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}
