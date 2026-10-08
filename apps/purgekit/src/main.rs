//! PurgeKit main app (runs as the invoking user).
//!
//! The Slint event loop never touches the file system. Scans and cleans run on
//! worker threads; results come back through `upgrade_in_event_loop`, at most
//! one progress update per ~100 ms.

// `deny`, not `forbid`: Slint's generated UI code opts in with `allow(unsafe_code)`.
// Hand-written code in this crate must not use `unsafe`; Win32 calls live in purgekit-win.
#![deny(unsafe_code)]
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod diagnostics;
mod logging;
mod store;
mod view;

#[cfg(windows)]
mod controller;
#[cfg(windows)]
mod launch;

slint::include_modules!();

#[cfg(windows)]
fn main() -> Result<(), slint::PlatformError> {
    controller::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("PurgeKit runs on Windows only.");
}
