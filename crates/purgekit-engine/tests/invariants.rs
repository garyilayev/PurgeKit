//! Safety invariants, end to end through scan → selection → plan → clean,
//! on the in-memory backend.

use std::path::PathBuf;

use purgekit_core::{KnownFolder, Selection, SkipReason};
use purgekit_engine::backend::FsBackend;
use purgekit_engine::helper::{HelperResponse, build_request, execute};
use purgekit_engine::plan::PlanError;
use purgekit_engine::testing::MemFs;
use purgekit_engine::tree::NodeKind;
use purgekit_engine::{
    CancelToken, CleanOptions, CleanReport, Exclusion, Exclusions, ScanOptions, ScanResult, clean,
    scan,
};
use purgekit_rules::{RuleIdx, builtin};

const DAY: u64 = 86_400;

fn chrome(fs: &MemFs) -> PathBuf {
    fs.folder(KnownFolder::LocalAppData)
        .join("Google/Chrome/User Data")
}

fn temp(fs: &MemFs) -> PathBuf {
    fs.folder(KnownFolder::Temp)
}

fn wintemp(fs: &MemFs) -> PathBuf {
    fs.folder(KnownFolder::Windows).join("Temp")
}

fn seeded() -> MemFs {
    let fs = MemFs::new();
    let c = chrome(&fs);
    fs.add_file(c.join("Default/Cache/Cache_Data/f_000001"), 100_000, DAY);
    fs.add_file(c.join("Default/Cache/Cache_Data/f_000002"), 50_000, DAY);
    fs.add_file(c.join("Default/Code Cache/js/index"), 20_000, DAY);
    fs.add_file(c.join("Profile 1/GPUCache/data_0"), 8_000, DAY);
    fs.add_file(c.join("Default/Cookies"), 1_000, DAY);
    fs.add_file(c.join("Default/Login Data"), 1_000, DAY);
    fs.add_file(c.join("Default/Bookmarks"), 1_000, DAY);
    fs.add_file(c.join("Local State"), 1_000, DAY);
    // A protected name inside a cache folder: still never a candidate.
    fs.add_file(c.join("Default/Cache/Login Data"), 1_000, DAY);
    let t = temp(&fs);
    fs.add_file(t.join("old.tmp"), 4_000, 3 * DAY);
    fs.add_file(t.join("fresh.tmp"), 4_000, 60);
    fs.add_file(t.join("sub/dir/old.bin"), 9_000, 3 * DAY);
    let w = wintemp(&fs);
    fs.add_file(w.join("setup.log"), 7_000, 5 * DAY);
    fs.add_file(w.join("other.log"), 7_000, 5 * DAY);
    fs
}

fn do_scan(fs: &MemFs, ex: &Exclusions) -> ScanResult {
    scan(
        fs,
        &ScanOptions {
            rules: builtin(),
            exclusions: ex,
            only: None,
            threads: Some(2),
        },
        &CancelToken::new(),
        &|_| {},
    )
}

fn do_clean(
    fs: &MemFs,
    result: &ScanResult,
    ex: &Exclusions,
    include_elevated: bool,
) -> Result<CleanReport, PlanError> {
    let plan = result.tree.build_plan(builtin());
    let root_of = |r: RuleIdx| result.root_of(r);
    clean(
        fs,
        &plan,
        &CleanOptions {
            rules: builtin(),
            exclusions: ex,
            root_of: &root_of,
            include_elevated,
        },
        &CancelToken::new(),
        &|_| {},
    )
}

fn cleaner_node(result: &ScanResult, rule_id: &str) -> Option<u32> {
    let (idx, _) = builtin().find(rule_id)?;
    result
        .tree
        .cleaners()
        .find(|&c| result.tree.node(c).rule == idx)
}

fn find_node(result: &ScanResult, rule_id: &str, rel: &str) -> u32 {
    let t = &result.tree;
    let start = cleaner_node(result, rule_id).expect("cleaner");
    let mut cur = start;
    for comp in rel.split('/') {
        cur = t
            .children(cur)
            .find(|&c| t.node(c).name.eq_ignore_ascii_case(comp))
            .unwrap_or_else(|| panic!("{rel}: no {comp}"));
    }
    cur
}

#[test]
fn scan_finds_only_rule_matches_and_never_protected_data() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let chrome_files = r
        .tree
        .node(cleaner_node(&r, "chrome.cache").unwrap())
        .file_count;
    assert_eq!(chrome_files, 4, "cache files only");
    assert!(
        r.diagnostics.protected_skipped >= 1,
        "Login Data inside Cache was dropped"
    );
    let temp_files = r
        .tree
        .node(cleaner_node(&r, "windows.user_temp").unwrap())
        .file_count;
    assert_eq!(temp_files, 2, "fresh.tmp is younger than 24h");
}

#[test]
fn defaults_follow_tier() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let chrome = cleaner_node(&r, "chrome.cache").unwrap();
    assert_eq!(r.tree.selection(chrome), Selection::Checked);
    let wt = cleaner_node(&r, "windows.system_temp").unwrap();
    assert_eq!(
        r.tree.selection(wt),
        Selection::Unchecked,
        "ADVANCED starts unchecked"
    );
}

#[test]
fn clean_deletes_selected_and_keeps_everything_else() {
    let fs = seeded();
    let before = fs.snapshot();
    let r = do_scan(&fs, &Exclusions::default());
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert_eq!(report.deleted_files, 6);
    assert_eq!(report.skipped_count(), 0, "{:?}", report.skipped);
    let c = chrome(&fs);
    for keep in [
        "Default/Cookies",
        "Default/Login Data",
        "Default/Bookmarks",
        "Local State",
        "Default/Cache/Login Data",
    ] {
        assert!(fs.exists(c.join(keep)), "{keep} must survive");
    }
    assert!(fs.exists(temp(&fs).join("fresh.tmp")));
    assert!(
        fs.exists(wintemp(&fs).join("setup.log")),
        "ADVANCED not selected"
    );
    // Root directories survive; emptied subdirectories are removed.
    assert!(fs.exists(temp(&fs)));
    assert!(!fs.exists(temp(&fs).join("sub")));
    assert!(
        fs.exists(c.join("Default/Cache")),
        "still holds the protected file"
    );
    assert!(
        fs.exists(c.join("Profile 1/GPUCache")),
        "app folders are kept even when emptied"
    );
    assert!(
        !fs.exists(c.join("Default/Code Cache/js")),
        "emptied folders inside the cache are removed"
    );
    // Only expected paths disappeared.
    let after = fs.snapshot();
    let removed: Vec<_> = before.iter().filter(|p| !after.contains(p)).collect();
    for p in &removed {
        assert!(
            p.contains("/cache/")
                || p.contains("/code cache")
                || p.contains("/gpucache")
                || p.contains("/temp/"),
            "unexpected removal {p}"
        );
    }
    assert_eq!(report.measured_freed, Some(report.deleted_bytes as i64));
}

#[test]
fn unchecked_item_survives_cleaning() {
    let fs = seeded();
    let mut r = do_scan(&fs, &Exclusions::default());
    let n = find_node(&r, "chrome.cache", "Default/Cache/Cache_Data/f_000001");
    r.tree.set_selected(n, false);
    let parent = find_node(&r, "chrome.cache", "Default/Cache/Cache_Data");
    assert_eq!(r.tree.selection(parent), Selection::Partial);
    do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(fs.exists(chrome(&fs).join("Default/Cache/Cache_Data/f_000001")));
    assert!(!fs.exists(chrome(&fs).join("Default/Cache/Cache_Data/f_000002")));
}

#[test]
fn excluded_item_is_never_suggested_again() {
    let fs = seeded();
    let mut ex = Exclusions::default();
    ex.add(Exclusion::Path {
        rule_id: "chrome.cache".into(),
        rel_path: "Default/Code Cache".into(),
        is_dir: true,
    });
    let r = do_scan(&fs, &ex);
    assert_eq!(
        r.tree
            .node(cleaner_node(&r, "chrome.cache").unwrap())
            .file_count,
        3
    );
    do_clean(&fs, &r, &ex, false).unwrap();
    assert!(fs.exists(chrome(&fs).join("Default/Code Cache/js/index")));
}

#[test]
fn exclusion_added_after_plan_rejects_the_plan() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let mut ex = Exclusions::default();
    ex.add(Exclusion::Rule {
        rule_id: "chrome.cache".into(),
    });
    let err = do_clean(&fs, &r, &ex, false).unwrap_err();
    assert!(matches!(err, PlanError::ExcludedInPlan { .. }));
    assert!(
        fs.exists(temp(&fs).join("old.tmp")),
        "a rejected plan deletes nothing"
    );
}

#[test]
fn exclude_from_tree_updates_totals() {
    let fs = seeded();
    let mut r = do_scan(&fs, &Exclusions::default());
    let (total_before, count_before) = r.tree.selected_total();
    let n = find_node(&r, "chrome.cache", "Default/Code Cache");
    let e = r.tree.exclude(n, builtin()).unwrap();
    assert_eq!(
        e,
        Exclusion::Path {
            rule_id: "chrome.cache".into(),
            rel_path: "Default/Code Cache".into(),
            is_dir: true
        }
    );
    let (total_after, count_after) = r.tree.selected_total();
    assert_eq!(count_after, count_before - 1);
    assert!(total_after < total_before);
    // Re-checking the parent cannot bring the excluded item back.
    let chrome = cleaner_node(&r, "chrome.cache").unwrap();
    r.tree.set_selected(chrome, false);
    r.tree.set_selected(chrome, true);
    let plan = r.tree.build_plan(builtin());
    assert!(
        plan.candidates()
            .iter()
            .all(|c| !c.rel_path.as_str().starts_with("Default/Code Cache"))
    );
}

#[test]
fn junctions_and_symlinks_are_never_entered() {
    let fs = seeded();
    // A junction inside a cache folder, and a link where a directory should be.
    fs.add_link(chrome(&fs).join("Default/Cache/evil_junction"));
    fs.add_link(temp(&fs).join("link_to_documents"));
    let r = do_scan(&fs, &Exclusions::default());
    assert!(r.diagnostics.reparse_skipped >= 2);
    do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(fs.exists(chrome(&fs).join("Default/Cache/evil_junction")));
    assert!(fs.exists(temp(&fs).join("link_to_documents")));
}

#[test]
fn root_that_is_a_link_is_not_scanned() {
    let fs = MemFs::new();
    fs.add_link(chrome(&fs));
    let r = do_scan(&fs, &Exclusions::default());
    assert!(cleaner_node(&r, "chrome.cache").is_none());
    assert!(r.diagnostics.roots_unavailable >= 1);
}

#[test]
fn file_swapped_after_scan_is_not_deleted() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let p = chrome(&fs).join("Default/Cache/Cache_Data/f_000001");
    fs.replace_file(&p, 100_000, DAY);
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(fs.exists(&p), "new file with a different ID survives");
    assert_eq!(report.skipped[&SkipReason::Changed].count, 1);
}

#[test]
fn file_replaced_by_link_after_scan_is_not_deleted() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let dir = chrome(&fs).join("Default/Cache/Cache_Data");
    fs.remove(dir.join("f_000001"));
    fs.remove(dir.join("f_000002"));
    fs.remove(&dir);
    fs.add_link(&dir); // directory swapped for a junction mid-flight
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(fs.exists(&dir));
    assert_eq!(report.skipped[&SkipReason::LinkOrCloud].count, 2);
}

#[test]
fn read_only_hard_linked_locked_and_cloud_are_skipped() {
    let fs = seeded();
    let t = temp(&fs);
    fs.add_file(t.join("ro.tmp"), 1_000, 3 * DAY);
    fs.add_file(t.join("hl.tmp"), 1_000, 3 * DAY);
    fs.add_file(t.join("locked.tmp"), 1_000, 3 * DAY);
    fs.modify(t.join("ro.tmp"), |n| n.readonly = true);
    fs.modify(t.join("hl.tmp"), |n| n.links = 2);
    fs.modify(t.join("locked.tmp"), |n| n.locked = true);
    fs.add_file(t.join("cloud.tmp"), 1_000, 3 * DAY);
    fs.modify(t.join("cloud.tmp"), |n| n.cloud = true);
    let r = do_scan(&fs, &Exclusions::default());
    assert_eq!(
        r.diagnostics.cloud_skipped, 1,
        "cloud files are never candidates"
    );
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    for f in ["ro.tmp", "hl.tmp", "locked.tmp", "cloud.tmp"] {
        assert!(fs.exists(t.join(f)), "{f}");
    }
    assert_eq!(report.skipped[&SkipReason::ReadOnly].count, 1);
    assert_eq!(report.skipped[&SkipReason::HardLinked].count, 1);
    assert_eq!(report.skipped[&SkipReason::InUse].count, 1);
}

#[test]
fn file_that_became_fresh_is_not_deleted() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let p = temp(&fs).join("old.tmp");
    fs.modify(&p, |n| n.times.modified = purgekit_core::FileTime::now());
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(fs.exists(&p));
    assert_eq!(report.skipped[&SkipReason::Changed].count, 1);
}

#[test]
fn running_app_blocks_its_category_only() {
    let fs = seeded();
    fs.running.lock().unwrap().insert("chrome.exe".into());
    let mut r = do_scan(&fs, &Exclusions::default());
    let chrome_node = cleaner_node(&r, "chrome.cache").unwrap();
    let (idx, _) = builtin().find("chrome.cache").unwrap();
    assert_eq!(
        r.status(idx).unwrap().blocking,
        vec!["chrome.exe".to_string()]
    );
    assert_eq!(
        r.tree.selection(chrome_node),
        Selection::Unchecked,
        "blocked starts unchecked"
    );
    // Even if the user selects it, nothing in it is deleted while Chrome runs.
    r.tree.set_selected(chrome_node, true);
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(fs.exists(chrome(&fs).join("Default/Cache/Cache_Data/f_000001")));
    assert_eq!(report.skipped[&SkipReason::AppRunning].count, 4);
    assert!(
        !fs.exists(temp(&fs).join("old.tmp")),
        "other categories clean normally"
    );
}

#[test]
fn elevated_rules_go_to_the_helper_only() {
    let fs = seeded();
    let mut r = do_scan(&fs, &Exclusions::default());
    let wt = cleaner_node(&r, "windows.system_temp").unwrap();
    r.tree.set_selected(wt, true);
    let other = find_node(&r, "windows.system_temp", "other.log");
    r.tree.set_selected(other, false);
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert_eq!(
        report.elevated_pending,
        vec!["windows.system_temp".to_string()]
    );
    assert!(
        fs.exists(wintemp(&fs).join("setup.log")),
        "main app never deletes elevated items"
    );

    let plan = r.tree.build_plan(builtin());
    let req = build_request(&plan, builtin(), &Exclusions::default()).unwrap();
    assert_eq!(req.rule_ids, vec!["windows.system_temp".to_string()]);
    assert_eq!(req.allowed.len(), 1, "only the selected file's ID");
    // A junction planted in Windows Temp after the plan is never followed.
    fs.add_link(wintemp(&fs).join("planted_junction"));
    let resp = execute(&fs, builtin(), &req.rule_ids, &req, &CancelToken::new());
    let HelperResponse::Done(hr) = resp else {
        panic!("{resp:?}")
    };
    assert_eq!(hr.deleted_files, 1);
    assert!(!fs.exists(wintemp(&fs).join("setup.log")));
    assert!(
        fs.exists(wintemp(&fs).join("other.log")),
        "unchecked file survives the helper"
    );
    assert!(fs.exists(wintemp(&fs).join("planted_junction")));
}

#[test]
fn no_plan_means_no_helper_request() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let plan = r.tree.build_plan(builtin());
    assert!(
        build_request(&plan, builtin(), &Exclusions::default()).is_none(),
        "no UAC unless an elevated item is selected"
    );
}

#[test]
fn helper_refuses_bad_requests() {
    let fs = seeded();
    let mut r = do_scan(&fs, &Exclusions::default());
    let wt = cleaner_node(&r, "windows.system_temp").unwrap();
    r.tree.set_selected(wt, true);
    let plan = r.tree.build_plan(builtin());
    let req = build_request(&plan, builtin(), &Exclusions::default()).unwrap();

    let cancel = CancelToken::new();
    // Non-elevated rule on the command line.
    let bad = vec!["chrome.cache".to_string()];
    assert!(matches!(
        execute(&fs, builtin(), &bad, &req, &cancel),
        HelperResponse::Refused(_)
    ));
    // Unknown rule.
    let bad = vec!["windows.system32".to_string()];
    assert!(matches!(
        execute(&fs, builtin(), &bad, &req, &cancel),
        HelperResponse::Refused(_)
    ));
    // Version mismatch.
    let mut old = req.clone();
    old.app_version = "0.0.1".into();
    assert!(matches!(
        execute(&fs, builtin(), &req.rule_ids, &old, &cancel),
        HelperResponse::Refused(_)
    ));
    // Allowed IDs from elsewhere cannot widen: a random ID deletes nothing.
    let mut forged = req.clone();
    forged.allowed = vec![purgekit_core::CandidateId {
        volume: 1,
        file_id: purgekit_core::FileId128::from_u64(999_999),
    }];
    let HelperResponse::Done(rep) = execute(&fs, builtin(), &req.rule_ids, &forged, &cancel) else {
        panic!()
    };
    assert_eq!(rep.deleted_files, 0);
    assert!(fs.exists(wintemp(&fs).join("setup.log")));
}

#[test]
fn recycle_bin_is_review_and_opt_in() {
    let fs = seeded();
    *fs.recycle_bin.lock().unwrap() = (5_000_000, 3);
    let mut r = do_scan(&fs, &Exclusions::default());
    let rb = cleaner_node(&r, "windows.recycle_bin").unwrap();
    assert_eq!(r.tree.node(rb).kind, NodeKind::Cleaner);
    assert_eq!(r.tree.selection(rb), Selection::Unchecked);
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(!report.recycle_bin_emptied);
    assert_eq!(fs.recycle_bin_query(), Some((5_000_000, 3)));

    r.tree.set_selected(rb, true);
    let report = do_clean(&fs, &r, &Exclusions::default(), false).unwrap();
    assert!(report.recycle_bin_emptied);
    assert_eq!(fs.recycle_bin_query(), Some((0, 0)));
}

#[test]
fn cancelled_scan_is_partial() {
    let fs = seeded();
    let cancel = CancelToken::new();
    cancel.cancel();
    let r = scan(
        &fs,
        &ScanOptions {
            rules: builtin(),
            exclusions: &Exclusions::default(),
            only: None,
            threads: Some(1),
        },
        &cancel,
        &|_| {},
    );
    assert!(r.partial);
}

#[test]
fn cancelled_clean_leaves_remaining_untouched() {
    let fs = seeded();
    let r = do_scan(&fs, &Exclusions::default());
    let plan = r.tree.build_plan(builtin());
    let root_of = |i: RuleIdx| r.root_of(i);
    let cancel = CancelToken::new();
    let c2 = cancel.clone();
    let report = clean(
        &fs,
        &plan,
        &CleanOptions {
            rules: builtin(),
            exclusions: &Exclusions::default(),
            root_of: &root_of,
            include_elevated: false,
        },
        &cancel,
        &move |p| {
            if p.done_files == 1 {
                c2.cancel();
            }
        },
    )
    .unwrap();
    assert!(report.cancelled);
    assert_eq!(report.deleted_files, 1);
    assert_eq!(
        report.skipped[&SkipReason::Cancelled].count as usize,
        plan.file_count() - 1
    );
}
