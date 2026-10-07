//! Scanner: walks rule roots in parallel and builds the result tree.
//! It reads metadata only and never deletes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use purgekit_core::{CandidateId, Category, FileTime, RelPath, protected};
use purgekit_rules::{Detect, Mechanism, Rule, RuleIdx, RuleSet};
use rayon::prelude::*;

use crate::backend::{FsBackend, FsError, WalkEntry, WalkSkip, WalkVisitor};
use crate::cancel::CancelToken;
use crate::events::{Progress, ScanEvent};
use crate::exclusions::Exclusions;
use crate::plan::path_components;
use crate::tree::{CleanerInput, FoundFile, ResultTree};

#[derive(Debug, Clone, Default)]
pub struct ScanDiagnostics {
    pub reparse_skipped: u64,
    pub cloud_skipped: u64,
    pub bad_names: u64,
    pub unreadable_dirs: u64,
    pub protected_skipped: u64,
    pub roots_missing: u64,
    pub roots_unavailable: u64,
}

#[derive(Debug, Clone)]
pub struct RuleStatus {
    pub rule: RuleIdx,
    /// Resolved root, if the rule has one and it exists.
    pub root: Option<PathBuf>,
    pub present: bool,
    /// Running processes that block this rule (`process_deps`).
    pub blocking: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub tree: ResultTree,
    pub rules_version: String,
    pub started: FileTime,
    pub duration: Duration,
    /// True if cancelled: results are partial.
    pub partial: bool,
    pub statuses: Vec<RuleStatus>,
    pub diagnostics: ScanDiagnostics,
}

impl ScanResult {
    pub fn status(&self, rule: RuleIdx) -> Option<&RuleStatus> {
        self.statuses.iter().find(|s| s.rule == rule)
    }

    pub fn root_of(&self, rule: RuleIdx) -> Option<PathBuf> {
        self.status(rule).and_then(|s| s.root.clone())
    }
}

pub struct ScanOptions<'a> {
    pub rules: &'a RuleSet,
    pub exclusions: &'a Exclusions,
    /// Restrict the scan to these rules (the helper scans only its rules).
    pub only: Option<&'a [RuleIdx]>,
    pub threads: Option<usize>,
}

/// Resolves a rule root to an absolute path.
pub fn resolve_root(backend: &dyn FsBackend, rule: &Rule) -> Option<PathBuf> {
    let spec = rule.root.as_ref()?;
    let mut p = backend.resolve(spec.folder)?;
    for c in spec.rel.components() {
        p.push(c);
    }
    Some(p)
}

struct Counters {
    bytes: AtomicU64,
    files: AtomicU64,
    reparse: AtomicU64,
    cloud: AtomicU64,
    bad: AtomicU64,
    unreadable: AtomicU64,
    protected: AtomicU64,
}

struct RuleVisitor<'a> {
    rule: &'a Rule,
    idx: RuleIdx,
    exclusions: &'a Exclusions,
    root_comps: Vec<String>,
    now: FileTime,
    cancel: &'a CancelToken,
    counters: &'a Counters,
    found: Mutex<Vec<(WalkEntry, RuleIdx)>>,
}

impl RuleVisitor<'_> {
    fn protected(&self, rel: &RelPath) -> bool {
        protected::is_protected_under(self.root_comps.iter().map(String::as_str), rel)
    }
}

impl WalkVisitor for RuleVisitor<'_> {
    fn cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    fn enter_dir(&self, dir: &RelPath) -> bool {
        if self.protected(dir) {
            self.counters.protected.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.rule.should_descend(dir) && !self.exclusions.excludes(self.rule, dir)
    }

    fn files(&self, batch: Vec<WalkEntry>) {
        let mut keep = Vec::new();
        for e in batch {
            // Enforcement point 2: protected entries never become candidates.
            if self.protected(&e.rel) {
                if self.rule.matches_path_raw(&e.rel, false) {
                    self.counters.protected.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
            if !self.rule.matches(&e.rel, false, &e.times, self.now)
                || self.exclusions.excludes(self.rule, &e.rel)
            {
                continue;
            }
            self.counters
                .bytes
                .fetch_add(e.alloc_size, Ordering::Relaxed);
            self.counters.files.fetch_add(1, Ordering::Relaxed);
            keep.push((e, self.idx));
        }
        if !keep.is_empty() {
            self.found.lock().unwrap().extend(keep);
        }
    }

    fn skipped(&self, why: WalkSkip) {
        let c = match why {
            WalkSkip::ReparsePoint => &self.counters.reparse,
            WalkSkip::Cloud => &self.counters.cloud,
            WalkSkip::BadName => &self.counters.bad,
            WalkSkip::Unreadable => &self.counters.unreadable,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Runs a scan. `on_event` receives batched events (at most one `Progress`
/// per ~100 ms) from a background thread; it must be cheap.
pub fn scan(
    backend: &dyn FsBackend,
    opts: &ScanOptions<'_>,
    cancel: &CancelToken,
    on_event: &(dyn Fn(ScanEvent) + Sync),
) -> ScanResult {
    let start = Instant::now();
    let started = FileTime::now();
    let now = started;
    on_event(ScanEvent::Started);

    let rules = opts.rules;
    let running = backend.running_processes();
    let counters = Counters {
        bytes: AtomicU64::new(0),
        files: AtomicU64::new(0),
        reparse: AtomicU64::new(0),
        cloud: AtomicU64::new(0),
        bad: AtomicU64::new(0),
        unreadable: AtomicU64::new(0),
        protected: AtomicU64::new(0),
    };
    let current = Mutex::new(String::new());
    let mut diagnostics = ScanDiagnostics::default();

    let selected: Vec<RuleIdx> = rules
        .iter()
        .map(|(i, _)| i)
        .filter(|i| opts.only.is_none_or(|o| o.contains(i)))
        .filter(|&i| !opts.exclusions.excludes_rule(rules.get(i)))
        .collect();

    let threads = opts.threads.unwrap_or_else(|| {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let hdd = selected
            .iter()
            .filter_map(|&i| resolve_root(backend, rules.get(i)))
            .next()
            .is_some_and(|p| backend.has_seek_penalty(&p));
        if hdd { 2 } else { cpus.min(8) }
    });
    let mut builder = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("purgekit-scan-{i}"));
    if let Some(f) = backend.background_mode_fn() {
        builder = builder.start_handler(move |_| f());
    }
    let pool = builder.build().expect("scan thread pool");

    let mut statuses: Vec<RuleStatus> = Vec::new();
    let mut cleaners: Vec<CleanerInput> = Vec::new();
    let mut all_found: Vec<(WalkEntry, RuleIdx, u64, PathBuf)> = Vec::new();

    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        // Aggregator: one Progress event per 100 ms.
        let done_ref = &done;
        let counters_ref = &counters;
        let current_ref = &current;
        s.spawn(move || {
            while !done_ref.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                on_event(ScanEvent::Progress(Progress {
                    current: current_ref.lock().unwrap().clone(),
                    bytes_found: counters_ref.bytes.load(Ordering::Relaxed),
                    files_found: counters_ref.files.load(Ordering::Relaxed),
                }));
            }
        });

        for cat in Category::ALL {
            if cancel.is_cancelled() {
                break;
            }
            let in_cat: Vec<RuleIdx> = selected
                .iter()
                .copied()
                .filter(|&i| rules.get(i).category == cat)
                .collect();
            if in_cat.is_empty() {
                continue;
            }
            on_event(ScanEvent::CategoryStarted(cat));
            let before_bytes = counters.bytes.load(Ordering::Relaxed);
            let before_files = counters.files.load(Ordering::Relaxed);

            let results: Vec<_> = pool.install(|| {
                in_cat
                    .par_iter()
                    .map(|&idx| {
                        let rule = rules.get(idx);
                        let blocking: Vec<String> = rule
                            .process_deps
                            .iter()
                            .filter(|p| running.contains(*p))
                            .cloned()
                            .collect();
                        *current.lock().unwrap() = rule.display_name.clone();
                        match rule.mechanism {
                            Mechanism::RecycleBin => {
                                let q = if cancel.is_cancelled() {
                                    None
                                } else {
                                    backend.recycle_bin_query()
                                };
                                if let Some((bytes, _)) = q {
                                    counters.bytes.fetch_add(bytes, Ordering::Relaxed);
                                }
                                let status = RuleStatus {
                                    rule: idx,
                                    root: None,
                                    present: q.is_some(),
                                    blocking,
                                };
                                (status, Vec::new(), q, 0u64, None)
                            }
                            Mechanism::Files => {
                                let root = resolve_root(backend, rule);
                                let present = match (&rule.detect, &root) {
                                    (Detect::RegistryKey(k), Some(_)) => {
                                        backend.registry_key_exists(k)
                                    }
                                    (_, Some(_)) => true,
                                    (_, None) => false,
                                };
                                let mut status = RuleStatus {
                                    rule: idx,
                                    root: root.clone(),
                                    present,
                                    blocking,
                                };
                                let Some(root) = root.filter(|_| present) else {
                                    return (status, Vec::new(), None, 0, Some(FsError::NotFound));
                                };
                                let visitor = RuleVisitor {
                                    rule,
                                    idx,
                                    exclusions: opts.exclusions,
                                    root_comps: path_components(&root),
                                    now,
                                    cancel,
                                    counters: &counters,
                                    found: Mutex::new(Vec::new()),
                                };
                                match backend.walk(&root, &visitor) {
                                    Ok(info) => {
                                        let found = visitor.found.into_inner().unwrap();
                                        (status, found, None, info.volume_serial, None)
                                    }
                                    Err(e) => {
                                        status.present = false;
                                        (status, Vec::new(), None, 0, Some(e))
                                    }
                                }
                            }
                        }
                    })
                    .collect()
            });

            for (status, found, virt, volume, err) in results {
                match err {
                    Some(FsError::NotFound) => diagnostics.roots_missing += 1,
                    Some(_) => diagnostics.roots_unavailable += 1,
                    None => {}
                }
                let rule = rules.get(status.rule);
                if let Some(v) = virt {
                    cleaners.push(CleanerInput {
                        rule: status.rule,
                        files: Vec::new(),
                        virtual_size: Some(v),
                        selected: rule.tier.selected_by_default() && status.blocking.is_empty(),
                    });
                }
                if let Some(root) = &status.root {
                    all_found.extend(found.into_iter().map(|(e, r)| (e, r, volume, root.clone())));
                }
                statuses.push(status);
            }

            on_event(ScanEvent::CategoryCompleted {
                category: cat,
                bytes: counters.bytes.load(Ordering::Relaxed) - before_bytes,
                files: counters.files.load(Ordering::Relaxed) - before_files,
            });
        }
        done.store(true, Ordering::Relaxed);
    });

    // Overlapping rules: one candidate per file ID. The most conservative tier
    // among the matching rules wins; among equal tiers the most specific root
    // owns it. The file is placed under the winning rule so its tier label,
    // delete method and plan validation all come from the same rule.
    let mut owner: HashMap<CandidateId, usize> = HashMap::new();
    for (i, (e, r, vol, root)) in all_found.iter().enumerate() {
        let id = CandidateId {
            volume: *vol,
            file_id: e.file_id,
        };
        let better = match owner.get(&id) {
            None => true,
            Some(&j) => {
                let (_, rj, _, root_j) = &all_found[j];
                let (ti, tj) = (rules.get(*r).tier, rules.get(*rj).tier);
                ti > tj || (ti == tj && root.as_os_str().len() > root_j.as_os_str().len())
            }
        };
        if better {
            owner.insert(id, i);
        }
    }
    let mut per_rule: HashMap<RuleIdx, Vec<FoundFile>> = HashMap::new();
    for (_, i) in owner {
        let (e, r, vol, _) = &all_found[i];
        per_rule.entry(*r).or_default().push(FoundFile {
            rule: *r,
            volume: *vol,
            file_id: e.file_id,
            rel: e.rel.clone(),
            logical: e.logical_size,
            alloc: e.alloc_size,
            modified: e.times.modified,
        });
    }
    for (rule, files) in per_rule {
        let status = statuses.iter().find(|s| s.rule == rule);
        let blocked = status.is_some_and(|s| !s.blocking.is_empty());
        cleaners.push(CleanerInput {
            rule,
            files,
            virtual_size: None,
            selected: rules.get(rule).tier.selected_by_default() && !blocked,
        });
    }

    diagnostics.reparse_skipped = counters.reparse.load(Ordering::Relaxed);
    diagnostics.cloud_skipped = counters.cloud.load(Ordering::Relaxed);
    diagnostics.bad_names = counters.bad.load(Ordering::Relaxed);
    diagnostics.unreadable_dirs = counters.unreadable.load(Ordering::Relaxed);
    diagnostics.protected_skipped = counters.protected.load(Ordering::Relaxed);

    let tree = ResultTree::build(rules, cleaners);
    statuses.sort_by_key(|s| s.rule);
    let partial = cancel.is_cancelled();
    let result = ScanResult {
        tree,
        rules_version: rules.version.clone(),
        started,
        duration: start.elapsed(),
        partial,
        statuses,
        diagnostics,
    };
    let total = result.tree.node(0).total_alloc;
    if partial {
        on_event(ScanEvent::Cancelled { bytes: total });
    } else {
        on_event(ScanEvent::Completed { bytes: total });
    }
    result
}
