//! PurgeKit elevated helper.
//!
//! Launched once per clean by `purgekit.exe` with `runas`. It accepts rule IDs
//! on the command line, never paths. Exclusions and selected file IDs arrive
//! over a named pipe that only the invoking user can open; both can only
//! narrow what the helper's own scan finds. It deletes with the same
//! handle-based, no-follow procedure as the main app, reports back, and exits.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), windows_subsystem = "windows")]

use std::process::ExitCode;

#[cfg(windows)]
fn run() -> Result<(), (u8, String)> {
    use purgekit_engine::CancelToken;
    use purgekit_engine::helper::{
        APP_VERSION, HelperRequest, HelperResponse, execute, parse_rule_ids,
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let (Some(pipe), Some(server_pid), Some(version), Some(rules)) = (
        get("--pipe"),
        get("--server-pid"),
        get("--version"),
        get("--rules"),
    ) else {
        return Err((
            2,
            "usage: purgekit-helper --pipe NAME --server-pid PID --version V --rules ID[,ID]"
                .into(),
        ));
    };
    if version != APP_VERSION {
        return Err((
            3,
            format!("version mismatch: app {version}, helper {APP_VERSION}"),
        ));
    }
    if !pipe.starts_with(r"\.\pipe\purgekit-") {
        return Err((2, "invalid pipe name".into()));
    }
    let server_pid: u32 = server_pid
        .parse()
        .map_err(|_| (2, "invalid server pid".to_string()))?;
    let rule_ids: Vec<String> = rules.split(',').map(str::to_string).collect();
    let set = purgekit_rules::builtin();
    parse_rule_ids(set, &rule_ids).map_err(|e| (4, e))?;

    let mut conn =
        purgekit_win::elevate::connect_client(&pipe, server_pid).map_err(|e| (5, e.to_string()))?;
    let req_bytes = purgekit_win::elevate::read_msg(&mut conn).map_err(|e| (5, e.to_string()))?;
    let response = match serde_json::from_slice::<HelperRequest>(&req_bytes) {
        Ok(req) => execute(
            &purgekit_win::WinFs,
            set,
            &rule_ids,
            &req,
            &CancelToken::new(),
        ),
        Err(e) => HelperResponse::Refused(format!("bad request: {e}")),
    };
    let out = serde_json::to_vec(&response).map_err(|e| (6, e.to_string()))?;
    purgekit_win::elevate::write_msg(&mut conn, &out).map_err(|e| (5, e.to_string()))?;
    Ok(())
}

#[cfg(not(windows))]
fn run() -> Result<(), (u8, String)> {
    Err((1, "Windows only".into()))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("purgekit-helper: {msg}");
            ExitCode::from(code)
        }
    }
}
