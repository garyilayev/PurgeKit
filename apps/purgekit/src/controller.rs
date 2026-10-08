//! Wires the UI to the engine.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use purgekit_core::format::{format_bytes, format_count};
use purgekit_core::{FileTime, KnownFolder, SkipReason};
use purgekit_engine::backend::{FsBackend, VolumeInfo};
use purgekit_engine::events::ScanEvent;
use purgekit_engine::helper::{APP_VERSION, HelperResponse, build_request};
use purgekit_engine::tree::NodeKind;
use purgekit_engine::{
    CancelToken, CleanOptions, CleanReport, CleanupPlan, Exclusions, ScanOptions, ScanResult,
    clean, scan,
};
use purgekit_rules::{Mechanism, RuleIdx, builtin, builtin_version};
use purgekit_win::WinFs;
use purgekit_win::elevate::{LaunchError, PipeServer, launch_elevated, new_pipe_name};
use purgekit_win::shell::{format_date, format_date_time, set_clipboard_text};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::launch::{self, LaunchTimer};
use crate::store::{HistoryEntry, Settings, Store};
use crate::view::{self, Ctx, Explorer, Row};
use crate::{
    App, AppWindow, BlockedRow, CategoryRow, DetailsData, DriveRow, SkipRow, TextRow, TreeRow,
};

const RELEASES_URL: &str = "https://github.com/garyilayev/PurgeKit/releases";
const SLINT_URL: &str = "https://slint.dev";

mod state {
    pub const IDLE: i32 = 0;
    pub const SCANNING: i32 = 1;
    pub const RESULTS: i32 = 2;
    pub const REVIEW: i32 = 3;
    pub const CLEANING: i32 = 4;
    pub const DONE: i32 = 5;
}

struct Model_ {
    store: Store,
    settings: Settings,
    exclusions: Exclusions,
    history: Vec<HistoryEntry>,
    scan: Option<ScanResult>,
    explorer: Explorer,
    rows: Vec<Row>,
    cancel: Option<CancelToken>,
    notices: Vec<String>,
    /// Fixed volumes for the Space page. Read on worker threads only (see
    /// `refresh_volumes`), never on the event loop.
    volumes: Vec<VolumeInfo>,
}

type Shared = Arc<Mutex<Model_>>;

fn s(v: impl Into<SharedString>) -> SharedString {
    v.into()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn run() -> Result<(), slint::PlatformError> {
    let mut timer = LaunchTimer::start(purgekit_win::process_age());
    // Compiling the embedded rules takes ~25 ms; overlap it with window
    // creation. The first `builtin()` on this thread (in `refresh_all`) waits
    // for it if it is not done yet.
    std::thread::spawn(|| {
        let _ = builtin();
    });
    let data_dir = WinFs
        .resolve(KnownFolder::LocalAppData)
        .unwrap_or_else(std::env::temp_dir)
        .join("PurgeKit");
    timer.mark("data_dir");
    crate::logging::init(data_dir.join("logs"));
    tracing::info!(version = APP_VERSION, rules = %builtin_version(), "PurgeKit starting");
    timer.mark("logging");

    let store = Store::new(data_dir);
    let mut notices = Vec::new();
    let settings = store.load_settings(&mut notices);
    let exclusions = store.load_exclusions(&mut notices);
    let history = store.load_history(&mut notices);
    timer.mark("store");
    let model: Shared = Arc::new(Mutex::new(Model_ {
        store,
        settings,
        exclusions,
        history,
        scan: None,
        explorer: Explorer::default(),
        rows: Vec::new(),
        cancel: None,
        notices,
        volumes: Vec::new(),
    }));

    let ui = AppWindow::new()?;
    timer.mark("window_new");
    let app = ui.global::<App>();
    app.set_rows(ModelRc::from(Rc::new(VecModel::<TreeRow>::default())));
    refresh_all(&ui, &mut model.lock().unwrap());
    refresh_volumes(&model, &ui.as_weak());
    timer.mark("refresh");

    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_scan(move || start_scan(&m, &w));
    }
    {
        let m = model.clone();
        app.on_retry({
            let w = ui.as_weak();
            move || start_scan(&m, &w)
        });
    }
    {
        let m = model.clone();
        app.on_cancel(move || {
            if let Some(c) = &m.lock().unwrap().cancel {
                c.cancel();
            }
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_clean(move || start_clean(&m, &w));
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_review(move || {
            let ui = w.unwrap();
            ui.global::<App>().set_clean_state(state::REVIEW);
            refresh_rows(&ui, &mut m.lock().unwrap());
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_back_home(move || {
            let ui = w.unwrap();
            ui.global::<App>().set_clean_state(state::RESULTS);
            refresh_all(&ui, &mut m.lock().unwrap());
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_done(move || {
            let ui = w.unwrap();
            ui.global::<App>().set_clean_state(state::IDLE);
            refresh_all(&ui, &mut m.lock().unwrap());
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_dismiss_notice(move || {
            let mut g = m.lock().unwrap();
            if !g.notices.is_empty() {
                g.notices.remove(0);
            }
            refresh_all(&w.unwrap(), &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_toggle_category(move |node| {
            let mut g = m.lock().unwrap();
            let show = g.settings.show_advanced;
            if let Some(r) = g.scan.as_mut() {
                view::toggle(r, builtin(), show, node as u32);
            }
            refresh_all(&w.unwrap(), &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_toggle_row(move |node| {
            if node < 0 {
                return;
            }
            let mut g = m.lock().unwrap();
            let show = g.settings.show_advanced;
            if let Some(r) = g.scan.as_mut() {
                view::toggle(r, builtin(), show, node as u32);
            }
            let ui = w.unwrap();
            refresh_home(&ui, &g);
            refresh_rows(&ui, &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_expand_row(move |node| {
            if node < 0 {
                return;
            }
            let mut g = m.lock().unwrap();
            let n = node as u32;
            if !g.explorer.expanded.remove(&n) {
                g.explorer.expanded.insert(n);
            }
            refresh_rows(&w.unwrap(), &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_select_row(move |node| {
            let mut g = m.lock().unwrap();
            g.explorer.current = (node >= 0).then_some(node as u32);
            let ui = w.unwrap();
            let idx = g
                .rows
                .iter()
                .position(|r| matches!(r, Row::Node { id, .. } if *id as i32 == node))
                .map(|i| i as i32)
                .unwrap_or(-1);
            ui.global::<App>().set_current_row(idx);
            refresh_details(&ui, &g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_search_changed(move |text| {
            let mut g = m.lock().unwrap();
            g.explorer.query = text.to_string();
            refresh_rows(&w.unwrap(), &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_sort_changed(move |i| {
            let mut g = m.lock().unwrap();
            g.explorer.sort = view::SortBy::from_index(i);
            refresh_rows(&w.unwrap(), &mut g);
        });
    }
    {
        let m = model.clone();
        app.on_open_location(move |node| {
            let g = m.lock().unwrap();
            if let Some((path, is_file)) = node_path(&g, node) {
                let mut cmd = std::process::Command::new("explorer.exe");
                if is_file {
                    cmd.arg(format!("/select,{}", path.display()));
                } else {
                    cmd.arg(&path);
                }
                let _ = cmd.spawn();
            }
        });
    }
    {
        let m = model.clone();
        app.on_copy_path(move |node| {
            let g = m.lock().unwrap();
            if let Some((path, _)) = node_path(&g, node) {
                set_clipboard_text(&path.display().to_string());
            }
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_exclude_row(move |node| {
            if node < 0 {
                return;
            }
            let mut g = m.lock().unwrap();
            let excl = g
                .scan
                .as_mut()
                .and_then(|r| r.tree.exclude(node as u32, builtin()));
            if let Some(e) = excl {
                tracing::info!(kind = ?std::mem::discriminant(&e), "exclusion added");
                g.exclusions.add(e);
                let ex = g.exclusions.clone();
                g.store.save_exclusions(&ex);
            }
            if g.explorer.current == Some(node as u32) {
                g.explorer.current = None;
            }
            refresh_all(&w.unwrap(), &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_set_scan_on_launch(move |v| {
            let mut g = m.lock().unwrap();
            g.settings.scan_on_launch = v;
            let st = g.settings.clone();
            g.store.save_settings(&st);
            refresh_settings(&w.unwrap(), &g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_set_show_advanced(move |v| {
            let mut g = m.lock().unwrap();
            g.settings.show_advanced = v;
            let st = g.settings.clone();
            g.store.save_settings(&st);
            refresh_all(&w.unwrap(), &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_remove_exclusion(move |i| {
            let mut g = m.lock().unwrap();
            if i >= 0 && (i as usize) < g.exclusions.items.len() {
                g.exclusions.items.remove(i as usize);
                let ex = g.exclusions.clone();
                g.store.save_exclusions(&ex);
                g.notices
                    .push("Exclusion removed. Rescan to see the item again.".into());
            }
            refresh_all(&w.unwrap(), &mut g);
        });
    }
    {
        let (m, w) = (model.clone(), ui.as_weak());
        app.on_export_diagnostics(move || {
            let (summary, dir) = {
                let g = m.lock().unwrap();
                (diagnostics_summary(&g), g.store.dir().to_path_buf())
            };
            w.unwrap()
                .global::<App>()
                .set_diagnostics_status(s("Saving diagnostics…"));
            // Zipping up to 25 MB of logs: off the event loop.
            let w = w.clone();
            std::thread::spawn(move || {
                crate::logging::flush();
                let status = match crate::diagnostics::export(&dir, &summary) {
                    Ok(path) => {
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let _ = std::process::Command::new("explorer.exe")
                            .arg(format!("/select,{}", path.display()))
                            .spawn();
                        format!("Saved %LOCALAPPDATA%\\PurgeKit\\{name}")
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "diagnostics export failed");
                        "Diagnostics could not be saved.".to_string()
                    }
                };
                let _ = w.upgrade_in_event_loop(move |ui| {
                    ui.global::<App>().set_diagnostics_status(s(status));
                });
            });
        });
    }
    app.on_check_updates(|| {
        // Opens the releases page in the browser. PurgeKit itself never connects.
        let _ = std::process::Command::new("explorer.exe")
            .arg(RELEASES_URL)
            .spawn();
    });
    app.on_open_slint(|| {
        // Slint attribution link. Opens the browser; PurgeKit itself never connects.
        let _ = std::process::Command::new("explorer.exe")
            .arg(SLINT_URL)
            .spawn();
    });

    if model.lock().unwrap().settings.scan_on_launch {
        start_scan(&model, &ui.as_weak());
    }
    timer.mark("wiring");
    let report = report_first_frame(&ui, timer);
    let result = ui.run();
    if let Some(h) = report.take() {
        let _ = h.join();
    }
    // The event loop has ended: wait for queued saves and log lines.
    model.lock().unwrap().store.sync();
    crate::logging::flush();
    result
}

/// Reads the volume list on a worker thread, then redraws the Space page.
fn refresh_volumes(m: &Shared, w: &slint::Weak<AppWindow>) {
    let (m, w) = (m.clone(), w.clone());
    std::thread::spawn(move || {
        let v = WinFs.volumes();
        m.lock().unwrap().volumes = v;
        let _ = w.upgrade_in_event_loop(move |ui| refresh_space(&ui, &m.lock().unwrap()));
    });
}

/// Logs the launch breakdown once the first frame is rendered. The log write
/// runs on a short-lived thread so the event loop does no file I/O.
fn report_first_frame(ui: &AppWindow, timer: LaunchTimer) -> Rc<Cell<Option<JoinHandle<()>>>> {
    let handle = Rc::new(Cell::new(None));
    let finish = {
        let handle = handle.clone();
        let mut timer = Some(timer);
        move |phase: &'static str| {
            let Some(mut t) = timer.take() else {
                return;
            };
            t.mark(phase);
            let line = t.summary();
            let mode = t.mode;
            handle.set(Some(std::thread::spawn(move || {
                tracing::info!(timings = %line, "launch to first frame");
                if mode != launch::Mode::Log {
                    eprintln!("launch: {line}");
                }
            })));
            if mode == launch::Mode::PrintAndExit {
                let _ = slint::quit_event_loop();
            }
        }
    };
    let finish = Rc::new(RefCell::new(finish));
    let f = finish.clone();
    let notifier = ui.window().set_rendering_notifier(move |state, _| {
        if matches!(state, slint::RenderingState::AfterRendering) {
            (f.borrow_mut())("first_frame");
        }
    });
    if notifier.is_err() {
        // Renderer without notifier support: fall back to the first event-loop turn.
        slint::Timer::single_shot(Duration::ZERO, move || {
            (finish.borrow_mut())("event_loop");
        });
    }
    handle
}

// ------------------------------------------------------------------ scan

fn start_scan(m: &Shared, w: &slint::Weak<AppWindow>) {
    let cancel = CancelToken::new();
    let exclusions = {
        let mut g = m.lock().unwrap();
        if g.cancel.is_some() {
            return;
        }
        g.cancel = Some(cancel.clone());
        g.exclusions.clone()
    };
    if let Some(ui) = w.upgrade() {
        let app = ui.global::<App>();
        app.set_page(0);
        app.set_clean_state(state::SCANNING);
        app.set_scan_text(s("Starting scan…"));
    }
    let (m, w) = (m.clone(), w.clone());
    std::thread::spawn(move || {
        let w2 = w.clone();
        let on_event = move |ev: ScanEvent| {
            if let ScanEvent::Progress(p) = ev
                && !p.current.is_empty()
            {
                let text = format!(
                    "Scanning {}… {} found",
                    p.current,
                    format_bytes(p.bytes_found)
                );
                let _ =
                    w2.upgrade_in_event_loop(move |ui| ui.global::<App>().set_scan_text(s(text)));
            }
        };
        let result = scan(
            &WinFs,
            &ScanOptions {
                rules: builtin(),
                exclusions: &exclusions,
                only: None,
                threads: None,
            },
            &cancel,
            &on_event,
        );
        tracing::info!(
            ms = result.duration.as_millis() as u64,
            partial = result.partial,
            reparse_skipped = result.diagnostics.reparse_skipped,
            cloud_skipped = result.diagnostics.cloud_skipped,
            protected_skipped = result.diagnostics.protected_skipped,
            "scan finished"
        );
        let volumes = WinFs.volumes();
        {
            let mut g = m.lock().unwrap();
            g.scan = Some(result);
            g.explorer = Explorer::default();
            g.cancel = None;
            g.volumes = volumes;
        }
        let _ = w.upgrade_in_event_loop(move |ui| {
            ui.global::<App>().set_clean_state(state::RESULTS);
            refresh_all(&ui, &mut m.lock().unwrap());
        });
    });
}

// ------------------------------------------------------------------ clean

fn total_free(v: &[VolumeInfo]) -> Option<u64> {
    if v.is_empty() {
        None
    } else {
        Some(v.iter().map(|d| d.free).sum())
    }
}

fn start_clean(m: &Shared, w: &slint::Weak<AppWindow>) {
    let cancel = CancelToken::new();
    let (plan, exclusions, roots): (CleanupPlan, Exclusions, Vec<(RuleIdx, PathBuf)>) = {
        let mut g = m.lock().unwrap();
        if g.cancel.is_some() {
            return;
        }
        let Some(r) = g.scan.as_ref() else { return };
        let plan = r.tree.build_plan(builtin());
        if plan.is_empty() {
            return;
        }
        let roots = r
            .statuses
            .iter()
            .filter_map(|st| st.root.clone().map(|p| (st.rule, p)))
            .collect();
        let ex = g.exclusions.clone();
        g.cancel = Some(cancel.clone());
        (plan, ex, roots)
    };
    if let Some(ui) = w.upgrade() {
        let app = ui.global::<App>();
        app.set_clean_state(state::CLEANING);
        app.set_clean_progress(0.0);
        app.set_clean_progress_text(s("Cleaning…"));
    }
    let (m, w) = (m.clone(), w.clone());
    std::thread::spawn(move || {
        let rules = builtin();
        let free_before = total_free(&WinFs.volumes());
        let root_of = |r: RuleIdx| roots.iter().find(|(i, _)| *i == r).map(|(_, p)| p.clone());
        let last = Mutex::new(Instant::now() - Duration::from_secs(1));
        let w2 = w.clone();
        let on_progress = move |p: purgekit_engine::events::CleanProgress| {
            let mut l = last.lock().unwrap();
            if l.elapsed() < Duration::from_millis(100) && p.done_files < p.total_files {
                return;
            }
            *l = Instant::now();
            let frac = if p.total_files == 0 {
                1.0
            } else {
                p.done_files as f32 / p.total_files as f32
            };
            let text = format!(
                "Cleaning… {} of {} files",
                format_count(p.done_files),
                format_count(p.total_files)
            );
            let _ = w2.upgrade_in_event_loop(move |ui| {
                let app = ui.global::<App>();
                app.set_clean_progress(frac);
                app.set_clean_progress_text(s(text));
            });
        };
        let mut report = match clean(
            &WinFs,
            &plan,
            &CleanOptions {
                rules,
                exclusions: &exclusions,
                root_of: &root_of,
                include_elevated: false,
            },
            &cancel,
            &on_progress,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "plan rejected");
                let mut r = CleanReport::default();
                r.skipped
                    .entry(SkipReason::Other)
                    .or_default()
                    .details
                    .push("The cleanup plan failed a safety check. Nothing was deleted.".into());
                r
            }
        };

        if !cancel.is_cancelled()
            && let Some(req) = build_request(&plan, rules, &exclusions)
        {
            let _ = w.upgrade_in_event_loop(|ui| {
                ui.global::<App>()
                    .set_clean_progress_text(s("Waiting for administrator permission…"))
            });
            let elevated_bytes: u64 = plan
                .candidates()
                .iter()
                .filter(|c| req.rule_ids.contains(&rules.get(c.rule).id))
                .map(|c| c.alloc_size)
                .sum();
            match run_helper(&req) {
                Ok(HelperResponse::Done(r)) => {
                    report.elevated_pending.clear();
                    report.merge(r);
                }
                Ok(HelperResponse::Refused(msg)) => {
                    tracing::error!(%msg, "helper refused");
                    add_skip(
                        &mut report,
                        SkipReason::Other,
                        req.allowed.len() as u64,
                        elevated_bytes,
                        &req.rule_ids,
                        msg,
                    );
                }
                Err(HelperError::Declined) => {
                    add_skip(
                        &mut report,
                        SkipReason::AccessDenied,
                        req.allowed.len() as u64,
                        elevated_bytes,
                        &req.rule_ids,
                        "Administrator permission was declined".into(),
                    );
                }
                Err(HelperError::Failed(e)) => {
                    tracing::error!(error = %e, "helper failed");
                    add_skip(
                        &mut report,
                        SkipReason::Other,
                        req.allowed.len() as u64,
                        elevated_bytes,
                        &req.rule_ids,
                        e,
                    );
                }
            }
        }
        // Measured, not estimated: the volume's actual free-space change.
        let volumes_after = WinFs.volumes();
        if let (Some(b), Some(a)) = (free_before, total_free(&volumes_after)) {
            report.measured_freed = Some(a as i64 - b as i64);
        }
        tracing::info!(
            deleted = report.deleted_files,
            skipped = report.skipped_count(),
            estimate = report.deleted_bytes,
            measured = report.measured_freed.unwrap_or(0),
            "clean finished"
        );

        {
            let mut g = m.lock().unwrap();
            let mut cats: Vec<String> = plan
                .candidates()
                .iter()
                .map(|c| rules.get(c.rule).category.label().to_string())
                .collect();
            if plan.empty_recycle_bin() {
                cats.push("Windows".into());
            }
            cats.sort();
            cats.dedup();
            g.history.push(HistoryEntry {
                timestamp: now_unix(),
                categories: cats,
                estimated_bytes: report.deleted_bytes,
                measured_bytes: report.measured_freed,
                files_deleted: report.deleted_files,
                files_skipped: report.skipped_count(),
                error_categories: report.skipped.keys().map(|k| format!("{k:?}")).collect(),
            });
            let h = g.history.clone();
            g.store.save_history(&h);
            g.scan = None;
            g.cancel = None;
            g.volumes = volumes_after;
        }
        let _ = w.upgrade_in_event_loop(move |ui| {
            show_report(&ui, &report);
            ui.global::<App>().set_clean_state(state::DONE);
            refresh_all(&ui, &mut m.lock().unwrap());
        });
    });
}

fn add_skip(
    report: &mut CleanReport,
    reason: SkipReason,
    count: u64,
    bytes: u64,
    rule_ids: &[String],
    detail: String,
) {
    let g = report.skipped.entry(reason).or_default();
    g.count += count;
    g.bytes += bytes;
    g.rules.extend(rule_ids.iter().cloned());
    g.details.push(detail);
}

enum HelperError {
    Declined,
    Failed(String),
}

/// One UAC prompt; rule IDs on the command line, the rest over the pipe.
fn run_helper(req: &purgekit_engine::helper::HelperRequest) -> Result<HelperResponse, HelperError> {
    let exe = std::env::current_exe()
        .map_err(|e| HelperError::Failed(e.to_string()))?
        .with_file_name("purgekit-helper.exe");
    if !exe.exists() {
        return Err(HelperError::Failed("purgekit-helper.exe is missing".into()));
    }
    let name = new_pipe_name();
    let server = PipeServer::create(&name).map_err(|e| HelperError::Failed(e.to_string()))?;
    let params = format!(
        "--pipe {name} --server-pid {} --version {APP_VERSION} --rules {}",
        std::process::id(),
        req.rule_ids.join(",")
    );
    let proc = match launch_elevated(&exe, &params) {
        Ok(p) => p,
        Err(LaunchError::Cancelled) => return Err(HelperError::Declined),
        Err(LaunchError::Failed(e)) => return Err(HelperError::Failed(e.to_string())),
    };
    server
        .accept(&proc, 60_000)
        .map_err(|e| HelperError::Failed(e.to_string()))?;
    let body = serde_json::to_vec(req).map_err(|e| HelperError::Failed(e.to_string()))?;
    server
        .send(&body)
        .map_err(|e| HelperError::Failed(e.to_string()))?;
    let resp = server
        .recv()
        .map_err(|e| HelperError::Failed(e.to_string()))?;
    let _ = proc.wait(5_000);
    serde_json::from_slice(&resp).map_err(|e| HelperError::Failed(e.to_string()))
}

fn show_report(ui: &AppWindow, r: &CleanReport) {
    let app = ui.global::<App>();
    let rules = builtin();
    let headline = match r.measured_freed {
        Some(m) if m > 0 => format!("{} recovered", format_bytes(m as u64)),
        _ if r.deleted_bytes > 0 => format!("{} cleaned", format_bytes(r.deleted_bytes)),
        _ => "Nothing was removed".to_string(),
    };
    app.set_done_headline(s(headline));
    let mut sub = format!("{} files removed.", format_count(r.deleted_files));
    if r.recycle_bin_emptied {
        sub.push_str(" The Recycle Bin was emptied.");
    }
    if r.cancelled {
        sub.push_str(" Cleaning was cancelled; the remaining items were not touched.");
    }
    app.set_done_sub(s(sub));
    let gap = if r.measurement_gap() {
        format!(
            "Estimated {}, measured {}. Other apps also write to the disk while PurgeKit cleans, so the two numbers can differ.",
            format_bytes(r.deleted_bytes),
            match r.measured_freed {
                Some(m) if m >= 0 => format_bytes(m as u64),
                Some(m) => format!("-{}", format_bytes(m.unsigned_abs())),
                None => "unknown".into(),
            }
        )
    } else {
        String::new()
    };
    app.set_gap_note(s(gap));
    let skips: Vec<SkipRow> = r
        .skipped
        .iter()
        .map(|(reason, g)| {
            let apps: Vec<&str> = g
                .rules
                .iter()
                .filter_map(|id| rules.find(id))
                // Only rules with an owning app can name it ("Chrome is using them").
                .filter(|(_, rule)| !rule.process_deps.is_empty())
                .map(|(_, rule)| view::app_name(&rule.display_name))
                .collect();
            let who = apps.join(", ");
            let text = match reason {
                SkipReason::InUse | SkipReason::AppRunning if !who.is_empty() => {
                    format!(
                        "{} files skipped — {} is using them. Close it and retry.",
                        format_count(g.count),
                        who
                    )
                }
                SkipReason::InUse => format!(
                    "{} files skipped — another program is using them. They are usually removed next time.",
                    format_count(g.count)
                ),
                _ => format!(
                    "{} files skipped — {}.",
                    format_count(g.count),
                    reason.describe()
                ),
            };
            SkipRow {
                text: s(text),
                details: s(g.details.join("\n")),
                retry: matches!(reason, SkipReason::InUse | SkipReason::AppRunning),
            }
        })
        .collect();
    app.set_skips(ModelRc::from(Rc::new(VecModel::from(skips))));
}

// ------------------------------------------------------------------ refresh

fn refresh_all(ui: &AppWindow, g: &mut Model_) {
    refresh_home(ui, g);
    refresh_rows(ui, g);
    refresh_settings(ui, g);
    refresh_space(ui, g);
    let app = ui.global::<App>();
    app.set_notice(s(g.notices.first().cloned().unwrap_or_default()));
    let footer = match g.history.last() {
        Some(h) => {
            let bytes = h
                .measured_bytes
                .filter(|m| *m > 0)
                .map(|m| m as u64)
                .unwrap_or(h.estimated_bytes);
            format!(
                "Last cleaned {} · {} recovered",
                format_date(FileTime::from_unix_secs(h.timestamp)),
                format_bytes(bytes)
            )
        }
        // Nothing to report yet; the UI hides an empty footer.
        None => String::new(),
    };
    app.set_footer(s(footer));
    if app.get_clean_state() == state::RESULTS && g.scan.is_none() {
        app.set_clean_state(state::IDLE);
    }
}

fn refresh_home(ui: &AppWindow, g: &Model_) {
    let app = ui.global::<App>();
    let Some(r) = g.scan.as_ref() else {
        app.set_can_clean(false);
        return;
    };
    let ctx = Ctx {
        result: r,
        rules: builtin(),
        show_advanced: g.settings.show_advanced,
    };
    let h = view::home(&ctx);
    app.set_headline(s(h.headline));
    app.set_clean_label(s(h.clean_label));
    app.set_can_clean(h.can_clean);
    app.set_selection_summary(s(h.selection_summary));
    app.set_advanced_hint(s(h.advanced_hint));
    let mut note = format!("Scanned {}", format_date_time(r.started));
    if r.partial {
        note.push_str(" · The scan was cancelled, so these results are partial.");
    }
    app.set_partial_note(s(note));
    let cats: Vec<CategoryRow> = h
        .categories
        .into_iter()
        .map(|c| CategoryRow {
            node: c.node,
            name: s(c.name),
            detail: s(c.detail),
            size: s(c.size),
            check: c.check,
        })
        .collect();
    app.set_categories(ModelRc::from(Rc::new(VecModel::from(cats))));
    let blocked: Vec<BlockedRow> = h
        .blocked
        .into_iter()
        .map(|b| BlockedRow {
            app: s(b.app),
            size: s(b.size),
        })
        .collect();
    app.set_blocked(ModelRc::from(Rc::new(VecModel::from(blocked))));
    app.set_blocked_summary(s(h.blocked_summary));
}

fn refresh_rows(ui: &AppWindow, g: &mut Model_) {
    let app = ui.global::<App>();
    let rows_model = app.get_rows();
    let Some(vm) = rows_model.as_any().downcast_ref::<VecModel<TreeRow>>() else {
        return;
    };
    let Some(r) = g.scan.as_ref() else {
        vm.set_vec(Vec::new());
        g.rows.clear();
        return;
    };
    let ctx = Ctx {
        result: r,
        rules: builtin(),
        show_advanced: g.settings.show_advanced,
    };
    let rows = view::flatten(&ctx, &g.explorer);
    let data: Vec<TreeRow> = rows
        .iter()
        .map(|row| {
            let d = view::row_data(&ctx, &g.explorer, row, &format_date);
            TreeRow {
                node: d.node,
                depth: d.depth,
                name: s(d.name),
                size: s(d.size),
                modified: s(d.modified),
                badge: s(d.badge),
                badge_tone: d.badge_tone,
                check: d.check,
                expandable: d.expandable,
                expanded: d.expanded,
                aggregate: d.aggregate,
                blocked: d.blocked,
            }
        })
        .collect();
    // Same shape: update in place so the list keeps its scroll position.
    if vm.row_count() == data.len() {
        for (i, d) in data.into_iter().enumerate() {
            if vm.row_data(i).as_ref() != Some(&d) {
                vm.set_row_data(i, d);
            }
        }
    } else {
        vm.set_vec(data);
    }
    let current = g.explorer.current;
    let idx = current
        .and_then(|c| {
            rows.iter()
                .position(|r| matches!(r, Row::Node { id, .. } if *id == c))
        })
        .map(|i| i as i32)
        .unwrap_or(-1);
    app.set_current_row(idx);
    g.rows = rows;
    refresh_details(ui, g);
}

fn refresh_details(ui: &AppWindow, g: &Model_) {
    let app = ui.global::<App>();
    let empty = DetailsData::default();
    let (Some(r), Some(i)) = (g.scan.as_ref(), g.explorer.current) else {
        app.set_details(empty);
        return;
    };
    let t = &r.tree;
    if i as usize >= t.len() {
        app.set_details(empty);
        return;
    }
    let n = t.node(i);
    let rules = builtin();
    let (what, why, after, rule_name, tier) =
        if n.kind == NodeKind::Category || n.kind == NodeKind::Root {
            (
                format!("All {} results PurgeKit found.", n.name),
                "Every item below is matched by a rule that explains why it is safe.".to_string(),
                "Select an item below to see what happens after it is removed.".to_string(),
                String::new(),
                String::new(),
            )
        } else {
            let rule = rules.get(n.rule);
            (
                rule.what.clone(),
                rule.why_safe.clone(),
                rule.after_effects.clone(),
                rule.display_name.clone(),
                rule.tier.label().to_string(),
            )
        };
    let location = node_path(g, i as i32)
        .map(|(p, _)| p.display().to_string())
        .unwrap_or_else(|| {
            if n.kind == NodeKind::Cleaner && rules.get(n.rule).mechanism == Mechanism::RecycleBin {
                "All drives".into()
            } else {
                String::new()
            }
        });
    app.set_details(DetailsData {
        visible: true,
        title: s(n.name.to_string()),
        what: s(what),
        why: s(why),
        after: s(after),
        location: s(location),
        size: s(format_bytes(n.total_logical)),
        files: s(format!("{} files", format_count(n.file_count as u64))),
        modified: s(if n.modified.0 > 0 {
            format_date(n.modified)
        } else {
            "—".into()
        }),
        rule: s(rule_name),
        tier: s(tier),
    });
}

fn refresh_settings(ui: &AppWindow, g: &Model_) {
    let app = ui.global::<App>();
    app.set_scan_on_launch(g.settings.scan_on_launch);
    app.set_show_advanced(g.settings.show_advanced);
    let ex: Vec<TextRow> = g
        .exclusions
        .items
        .iter()
        .map(|e| TextRow {
            text: s(e.describe()),
        })
        .collect();
    app.set_exclusions(ModelRc::from(Rc::new(VecModel::from(ex))));
    let hist: Vec<TextRow> = g
        .history
        .iter()
        .rev()
        .take(50)
        .map(|h| {
            let bytes = h
                .measured_bytes
                .filter(|m| *m > 0)
                .map(|m| m as u64)
                .unwrap_or(h.estimated_bytes);
            TextRow {
                text: s(format!(
                    "{} — {} recovered, {} files removed, {} skipped ({})",
                    format_date_time(FileTime::from_unix_secs(h.timestamp)),
                    format_bytes(bytes),
                    format_count(h.files_deleted),
                    format_count(h.files_skipped),
                    h.categories.join(", ")
                )),
            }
        })
        .collect();
    app.set_history(ModelRc::from(Rc::new(VecModel::from(hist))));
    app.set_about(s(format!(
        "PurgeKit {APP_VERSION} · Rules {} · Free to use. Local only. No account, no ads.",
        builtin().version
    )));
}

fn refresh_space(ui: &AppWindow, g: &Model_) {
    let app = ui.global::<App>();
    let rows: Vec<DriveRow> = g
        .volumes
        .iter()
        .map(|d| {
            let used = d.total.saturating_sub(d.free);
            // Same rule as Home's category sizes: only visible cleaners whose app
            // is not running. Blocked bytes are reported separately.
            let found: Option<(u64, u64)> = g.scan.as_ref().map(|r| {
                let ctx = Ctx {
                    result: r,
                    rules: builtin(),
                    show_advanced: g.settings.show_advanced,
                };
                let (mut now, mut blocked) = (0u64, 0u64);
                for c in r.tree.cleaners() {
                    let on_drive = r.root_of(r.tree.node(c).rule).is_some_and(|p| {
                        p.to_string_lossy()
                            .to_uppercase()
                            .starts_with(&d.name.to_uppercase())
                    });
                    if !on_drive || !ctx.visible(c) {
                        continue;
                    }
                    let bytes = r.tree.node(c).total_alloc;
                    if ctx.is_blocked(c) {
                        blocked += bytes;
                    } else {
                        now += bytes;
                    }
                }
                (now, blocked)
            });
            let cleanable = found.map(|(now, _)| now);
            let total = d.total.max(1) as f32;
            let label = if d.label.is_empty() {
                d.name.clone()
            } else {
                format!("{} ({})", d.label, d.name)
            };
            let text = match found {
                Some((now, blocked)) if blocked > 0 => format!(
                    "{} free of {} · {} can be cleaned · {} more after you close open apps",
                    format_bytes(d.free),
                    format_bytes(d.total),
                    format_bytes(now),
                    format_bytes(blocked)
                ),
                Some((now, _)) => format!(
                    "{} free of {} · {} can be cleaned",
                    format_bytes(d.free),
                    format_bytes(d.total),
                    format_bytes(now)
                ),
                None => format!("{} free of {}", format_bytes(d.free), format_bytes(d.total)),
            };
            DriveRow {
                name: s(label),
                used_frac: used as f32 / total,
                clean_frac: (cleanable.unwrap_or(0).min(used)) as f32 / total,
                text: s(text),
            }
        })
        .collect();
    app.set_drives(ModelRc::from(Rc::new(VecModel::from(rows))));
    app.set_space_note(s(if g.scan.is_some() {
        "The highlighted part of each bar is what the last scan found to clean."
    } else {
        "Scan your PC to see how much of each drive can be cleaned."
    }));
}

// ------------------------------------------------------------------ helpers

/// Absolute path of a tree node, and whether it is a file.
fn node_path(g: &Model_, node: i32) -> Option<(PathBuf, bool)> {
    if node < 0 {
        return None;
    }
    let r = g.scan.as_ref()?;
    let t = &r.tree;
    let i = node as u32;
    let n = t.node(i);
    let cleaner = t.cleaner_of(i)?;
    let mut p = r.root_of(t.node(cleaner).rule)?;
    if let Some(rel) = t.rel_path(i) {
        for c in rel.components() {
            p.push(c);
        }
    }
    Some((p, n.kind == NodeKind::File))
}

fn diagnostics_summary(g: &Model_) -> String {
    let mut out = format!(
        "PurgeKit {APP_VERSION}\nRules {}\nOS {} {}\nExclusions: {}\nHistory entries: {}\n",
        builtin().version,
        std::env::consts::OS,
        std::env::consts::ARCH,
        g.exclusions.items.len(),
        g.history.len()
    );
    if let Some(r) = &g.scan {
        let d = &r.diagnostics;
        out.push_str(&format!(
            "Last scan: {} ms, partial={}, nodes={}, reparse_skipped={}, cloud_skipped={}, bad_names={}, unreadable_dirs={}, protected_skipped={}, roots_missing={}, roots_unavailable={}\n",
            r.duration.as_millis(),
            r.partial,
            r.tree.len(),
            d.reparse_skipped,
            d.cloud_skipped,
            d.bad_names,
            d.unreadable_dirs,
            d.protected_skipped,
            d.roots_missing,
            d.roots_unavailable
        ));
        for st in &r.statuses {
            let rule = builtin().get(st.rule);
            let root = rule.root.as_ref().map(|r| r.log_form()).unwrap_or_default();
            out.push_str(&format!(
                "  {} present={} blocked={} root={}\n",
                rule.id,
                st.present,
                !st.blocking.is_empty(),
                root
            ));
        }
    }
    out
}
