//! Dev tasks. `cargo run -p xtask -- check-imports [profile]`
//!
//! Release gate: neither binary may import a networking DLL. This turns "no
//! networking code" from a promise into a verifiable claim.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use object::read::pe::{PeFile32, PeFile64};
use object::{LittleEndian as LE, pe};

const BANNED: &[&str] = &[
    "ws2_32.dll",
    "winhttp.dll",
    "wininet.dll",
    "wsock32.dll",
    "mswsock.dll",
    "dnsapi.dll",
    "iphlpapi.dll",
    "urlmon.dll",
    "webio.dll",
];
const BINARIES: &[&str] = &["purgekit.exe", "purgekit-helper.exe"];

fn imported_dlls(data: &[u8]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    macro_rules! collect {
        ($file:expr) => {{
            let file = $file.map_err(|e| e.to_string())?;
            if let Some(table) = file.import_table().map_err(|e| e.to_string())? {
                let mut descs = table.descriptors().map_err(|e| e.to_string())?;
                while let Some(d) = descs.next().map_err(|e| e.to_string())? {
                    let name = table.name(d.name.get(LE)).map_err(|e| e.to_string())?;
                    out.push(String::from_utf8_lossy(name).to_lowercase());
                }
            }
            let dirs = file.data_directories();
            if let Some(table) = dirs
                .delay_load_import_table(file.data(), &file.section_table())
                .map_err(|e| e.to_string())?
            {
                let mut descs = table.descriptors().map_err(|e| e.to_string())?;
                while let Some(d) = descs.next().map_err(|e| e.to_string())? {
                    let name = table
                        .name(d.dll_name_rva.get(LE))
                        .map_err(|e| e.to_string())?;
                    out.push(String::from_utf8_lossy(name).to_lowercase());
                }
            }
        }};
    }
    match object::FileKind::parse(data).map_err(|e| e.to_string())? {
        object::FileKind::Pe64 => collect!(PeFile64::parse(data)),
        object::FileKind::Pe32 => collect!(PeFile32::parse(data)),
        k => return Err(format!("not a PE file ({k:?})")),
    }
    let _ = pe::IMAGE_DIRECTORY_ENTRY_IMPORT;
    out.sort();
    out.dedup();
    Ok(out)
}

fn check_imports(profile: &str) -> ExitCode {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join(profile);
    let mut failed = false;
    for bin in BINARIES {
        let path = dir.join(bin);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "FAIL {bin}: cannot read {} ({e}); build with `cargo build --{profile}` first",
                    path.display()
                );
                failed = true;
                continue;
            }
        };
        match imported_dlls(&data) {
            Ok(dlls) => {
                let bad: Vec<&String> = dlls
                    .iter()
                    .filter(|d| BANNED.contains(&d.as_str()))
                    .collect();
                if bad.is_empty() {
                    println!("ok   {bin}: {} DLLs, none networking", dlls.len());
                } else {
                    eprintln!("FAIL {bin}: imports {bad:?}");
                    failed = true;
                }
            }
            Err(e) => {
                eprintln!("FAIL {bin}: {e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check-imports") => {
            check_imports(args.get(1).map(String::as_str).unwrap_or("release"))
        }
        _ => {
            eprintln!("usage: cargo run -p xtask -- check-imports [release|debug]");
            ExitCode::from(2)
        }
    }
}
