//! Cleaner: consumes a validated `CleanupPlan` and re-proves every candidate on
//! an open handle before deleting through that same handle.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use purgekit_core::{DeleteMethod, FileTime, RelPath, SkipReason, protected};
use purgekit_rules::{RuleIdx, RuleSet};
use serde::{Deserialize, Serialize};

use crate::backend::{FsBackend, OpenedFile, Skip};
use crate::cancel::CancelToken;
use crate::events::CleanProgress;
use crate::exclusions::Exclusions;
use crate::plan::{CleanupPlan, PlanError, path_components};

/// Skipped items for one plain-language reason.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipGroup {
    pub count: u64,
    pub bytes: u64,
    /// Rule IDs involved, for "Close Chrome and retry" style hints.
    pub rules: BTreeSet<String>,
    /// Up to 20 technical details (error codes) for the expander. No paths.
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanReport {
    pub deleted_files: u64,
    /// Estimated (allocated) bytes of what was deleted.
    pub deleted_bytes: u64,
    pub dirs_removed: u64,
    pub recycle_bin_emptied: bool,
    pub skipped: BTreeMap<SkipReason, SkipGroup>,
    /// Plan estimate for the part this run handled.
    pub estimate: u64,
    /// Measured change in free space across volumes, if it could be read.
    pub measured_freed: Option<i64>,
    pub cancelled: bool,
    /// Rules left for the elevated helper.
    pub elevated_pending: Vec<String>,
}

impl CleanReport {
    fn skip(&mut self, reason: SkipReason, bytes: u64, rule_id: &str, detail: Option<String>) {
        let g = self.skipped.entry(reason).or_default();
        g.count += 1;
        g.bytes += bytes;
        g.rules.insert(rule_id.to_string());
        if let Some(d) = detail
            && g.details.len() < 20
            && !g.details.contains(&d)
        {
            g.details.push(d);
        }
    }

    pub fn skipped_count(&self) -> u64 {
        self.skipped.values().map(|g| g.count).sum()
    }

    /// Merge a helper report into this one.
    pub fn merge(&mut self, other: CleanReport) {
        self.deleted_files += other.deleted_files;
        self.deleted_bytes += other.deleted_bytes;
        self.dirs_removed += other.dirs_removed;
        self.recycle_bin_emptied |= other.recycle_bin_emptied;
        self.estimate += other.estimate;
        self.cancelled |= other.cancelled;
        for (reason, g) in other.skipped {
            let mine = self.skipped.entry(reason).or_default();
            mine.count += g.count;
            mine.bytes += g.bytes;
            mine.rules.extend(g.rules);
            for d in g.details {
                if mine.details.len() < 20 && !mine.details.contains(&d) {
                    mine.details.push(d);
                }
            }
        }
    }

    /// True if measured and estimated recovery differ by more than 10%.
    pub fn measurement_gap(&self) -> bool {
        match self.measured_freed {
            Some(m) if self.deleted_bytes > 0 => {
                let est = self.deleted_bytes as f64;
                ((m as f64 - est).abs() / est) > 0.10
            }
            _ => false,
        }
    }
}

pub struct CleanOptions<'a> {
    pub rules: &'a RuleSet,
    pub exclusions: &'a Exclusions,
    pub root_of: &'a dyn Fn(RuleIdx) -> Option<PathBuf>,
    /// If false, candidates of rules that need elevation are left for the helper.
    pub include_elevated: bool,
}

pub fn clean(
    backend: &dyn FsBackend,
    plan: &CleanupPlan,
    opts: &CleanOptions<'_>,
    cancel: &CancelToken,
    on_progress: &dyn Fn(CleanProgress),
) -> Result<CleanReport, PlanError> {
    plan.validate(opts.rules, opts.exclusions, opts.root_of)?;

    let rules = opts.rules;
    let now = FileTime::now();
    let running = backend.running_processes();
    let mut report = CleanReport::default();

    // Measure free space on every fixed volume (falls back to the roots).
    let mut measure_points: Vec<PathBuf> = backend.volumes().into_iter().map(|v| v.root).collect();
    if measure_points.is_empty() {
        let mut seen = BTreeSet::new();
        for c in plan.candidates() {
            if let Some(r) = (opts.root_of)(c.rule)
                && seen.insert(c.id.volume)
            {
                measure_points.push(r);
            }
        }
    }
    let free_before: Vec<Option<u64>> = measure_points
        .iter()
        .map(|p| backend.free_space(p))
        .collect();

    let mut pending: BTreeSet<RuleIdx> = BTreeSet::new();
    let local: Vec<_> = plan
        .candidates()
        .iter()
        .filter(|c| {
            let elevated = rules.get(c.rule).needs_elevation();
            if elevated && !opts.include_elevated {
                pending.insert(c.rule);
                false
            } else {
                true
            }
        })
        .collect();
    let mut progress = CleanProgress {
        total_files: local.len() as u64,
        ..Default::default()
    };
    report.estimate = local.iter().map(|c| c.alloc_size).sum::<u64>();
    if plan.empty_recycle_bin() {
        report.estimate += plan.recycle_bin_bytes();
    }

    let mut emptied: HashMap<RuleIdx, BTreeSet<RelPath>> = HashMap::new();
    let mut root_comps_cache: HashMap<RuleIdx, (PathBuf, Vec<String>)> = HashMap::new();

    for c in local {
        let rule = rules.get(c.rule);
        if cancel.is_cancelled() {
            report.cancelled = true;
            report.skip(SkipReason::Cancelled, c.alloc_size, &rule.id, None);
            continue;
        }
        if rule.process_deps.iter().any(|p| running.contains(p)) {
            report.skip(SkipReason::AppRunning, c.alloc_size, &rule.id, None);
            continue;
        }
        if c.method != DeleteMethod::Permanent {
            // Recycle-bin deletion of individual files arrives with REVIEW file rules (0.2).
            report.skip(
                SkipReason::Other,
                c.alloc_size,
                &rule.id,
                Some("recycle method unavailable".into()),
            );
            continue;
        }
        let (root, root_comps) = &*root_comps_cache.entry(c.rule).or_insert_with(|| {
            let r = (opts.root_of)(c.rule).unwrap_or_default();
            let comps = path_components(&r);
            (r, comps)
        });
        if root.as_os_str().is_empty() {
            report.skip(
                SkipReason::Changed,
                c.alloc_size,
                &rule.id,
                Some("root unavailable".into()),
            );
            continue;
        }

        let check = |o: &OpenedFile| -> Result<(), Skip> {
            if o.reparse || o.cloud {
                return Err(SkipReason::LinkOrCloud.into());
            }
            if o.is_dir || o.volume_serial != c.id.volume || o.file_id != c.id.file_id {
                return Err(Skip::with(SkipReason::Changed, "identity mismatch"));
            }
            if o.readonly {
                return Err(SkipReason::ReadOnly.into());
            }
            if o.link_count != 1 {
                return Err(SkipReason::HardLinked.into());
            }
            // Enforcement point 4 (main app and helper both run this).
            if protected::is_protected_under(root_comps.iter().map(String::as_str), &c.rel_path) {
                return Err(SkipReason::Protected.into());
            }
            if !rule.matches(&c.rel_path, false, &o.times, now)
                || opts.exclusions.excludes(rule, &c.rel_path)
            {
                return Err(Skip::with(SkipReason::Changed, "no longer matches rule"));
            }
            Ok(())
        };

        match backend.delete_file(root, &c.rel_path, &check) {
            Ok(()) => {
                report.deleted_files += 1;
                report.deleted_bytes += c.alloc_size;
                progress.done_bytes += c.alloc_size;
                let set = emptied.entry(c.rule).or_default();
                let mut p = c.rel_path.parent();
                while let Some(d) = p {
                    if d.is_root() {
                        break;
                    }
                    p = d.parent();
                    set.insert(d);
                }
            }
            Err(skip) => {
                if skip.reason == SkipReason::Protected {
                    tracing::error!(rule = %rule.id, "engine bug: protected file reached deletion");
                }
                report.skip(skip.reason, c.alloc_size, &rule.id, skip.detail);
            }
        }
        progress.done_files += 1;
        on_progress(progress.clone());
    }

    // Remove emptied directories bottom-up; never the rule root, never recursive.
    for (rule_idx, dirs) in emptied {
        let Some((root, root_comps)) = root_comps_cache.get(&rule_idx) else {
            continue;
        };
        let mut dirs: Vec<RelPath> = dirs.into_iter().collect();
        dirs.sort_by_key(|d| std::cmp::Reverse(d.depth()));
        let rule = rules.get(rule_idx);
        for d in dirs {
            if !rule.dir_in_cleaned_area(&d)
                || protected::is_protected_under(root_comps.iter().map(String::as_str), &d)
            {
                continue;
            }
            if backend.remove_dir_if_empty(root, &d) {
                report.dirs_removed += 1;
            }
        }
    }

    if plan.empty_recycle_bin() {
        let rb_rule = rules
            .iter()
            .find(|(_, r)| r.mechanism == purgekit_rules::Mechanism::RecycleBin)
            .map(|(_, r)| r.id.clone())
            .unwrap_or_default();
        if cancel.is_cancelled() {
            report.cancelled = true;
            report.skip(
                SkipReason::Cancelled,
                plan.recycle_bin_bytes(),
                &rb_rule,
                None,
            );
        } else {
            match backend.recycle_bin_empty() {
                Ok(()) => {
                    report.recycle_bin_emptied = true;
                    report.deleted_bytes += plan.recycle_bin_bytes();
                }
                Err(s) => report.skip(s.reason, plan.recycle_bin_bytes(), &rb_rule, s.detail),
            }
        }
    }

    let free_after: Vec<Option<u64>> = measure_points
        .iter()
        .map(|p| backend.free_space(p))
        .collect();
    report.measured_freed = free_before
        .iter()
        .zip(&free_after)
        .map(|(b, a)| Some((*a)? as i64 - (*b)? as i64))
        .sum::<Option<i64>>();
    report.elevated_pending = pending
        .into_iter()
        .map(|r| rules.get(r).id.clone())
        .collect();
    Ok(report)
}
