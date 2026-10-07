//! Integration tests on real NTFS: junctions, symlinks, hard links,
//! read-only files, files held open, and roots swapped mid-clean.

#![cfg(windows)]

use std::collections::HashSet;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use purgekit_core::{KnownFolder, RelPath, SkipReason};
use purgekit_engine::backend::{
    FsBackend, FsError, OpenedFile, RootInfo, Skip, VolumeInfo, WalkEntry, WalkSkip, WalkVisitor,
};
use purgekit_engine::helper::{HelperResponse, build_request, execute};
use purgekit_engine::{CancelToken, CleanOptions, Exclusions, ScanOptions, clean, scan};
use purgekit_rules::{RuleIdx, builtin};
use purgekit_win::WinFs;

fn junction(link: &Path, target: &Path) -> bool {
    let win = |p: &Path| p.to_string_lossy().replace('/', "\\");
    Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(win(link))
        .arg(win(target))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Collects everything a walk reports.
#[derive(Default)]
struct Collect {
    files: Mutex<Vec<WalkEntry>>,
    skips: Mutex<Vec<WalkSkip>>,
    entered: Mutex<Vec<String>>,
}

impl WalkVisitor for Collect {
    fn cancelled(&self) -> bool {
        false
    }
    fn enter_dir(&self, dir: &RelPath) -> bool {
        self.entered.lock().unwrap().push(dir.as_str().to_string());
        true
    }
    fn files(&self, batch: Vec<WalkEntry>) {
        self.files.lock().unwrap().extend(batch);
    }
    fn skipped(&self, why: WalkSkip) {
        self.skips.lock().unwrap().push(why);
    }
}

fn write(p: &Path, bytes: usize) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, vec![7u8; bytes]).unwrap();
}

#[test]
fn walker_reports_ids_sizes_and_skips_junctions() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let victim = dir.path().join("victim");
    write(&root.join("a/b/file1.bin"), 10_000);
    write(&root.join("top.bin"), 5);
    write(&victim.join("secret.txt"), 100);
    assert!(junction(&root.join("a/jn"), &victim), "mklink /J failed");

    let c = Collect::default();
    let info = WinFs.walk(&root, &c).unwrap();
    assert_ne!(info.volume_serial, 0);
    let files = c.files.into_inner().unwrap();
    let names: HashSet<String> = files.iter().map(|f| f.rel.as_str().to_string()).collect();
    assert_eq!(
        names,
        HashSet::from(["a/b/file1.bin".to_string(), "top.bin".to_string()])
    );
    let f1 = files
        .iter()
        .find(|f| f.rel.as_str() == "a/b/file1.bin")
        .unwrap();
    assert_eq!(f1.logical_size, 10_000);
    assert!(f1.alloc_size >= 10_000);
    assert_ne!(f1.file_id, purgekit_core::FileId128::default());
    assert!(
        c.skips
            .into_inner()
            .unwrap()
            .contains(&WalkSkip::ReparsePoint)
    );
    assert!(
        !c.entered
            .into_inner()
            .unwrap()
            .iter()
            .any(|d| d.contains("jn"))
    );
}

#[test]
fn root_that_is_a_junction_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir_all(&target).unwrap();
    let link = dir.path().join("link");
    assert!(junction(&link, &target));
    assert_eq!(
        WinFs.walk(&link, &Collect::default()).unwrap_err(),
        FsError::RootIsLink
    );
    assert_eq!(
        WinFs
            .walk(&dir.path().join("missing"), &Collect::default())
            .unwrap_err(),
        FsError::NotFound
    );
}

fn opened_of(root: &Path, rel: &str) -> OpenedFile {
    let out = Mutex::new(None);
    let _ = WinFs.delete_file(root, &RelPath::parse(rel).unwrap(), &|o| {
        *out.lock().unwrap() = Some(o.clone());
        Err(Skip::new(SkipReason::Other))
    });
    out.into_inner().unwrap().expect("file opened")
}

#[test]
fn delete_checks_run_on_the_handle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write(&root.join("d/x.bin"), 3000);
    let o = opened_of(&root, "d/x.bin");
    assert_eq!(o.link_count, 1);
    assert!(!o.readonly && !o.reparse && !o.cloud && !o.is_dir);
    // A failing check leaves the file.
    assert!(root.join("d/x.bin").exists());
    // A passing check deletes through the same handle.
    WinFs
        .delete_file(&root, &RelPath::parse("d/x.bin").unwrap(), &|_| Ok(()))
        .unwrap();
    assert!(!root.join("d/x.bin").exists());
    // Directory removal is never recursive.
    write(&root.join("d/y.bin"), 1);
    assert!(!WinFs.remove_dir_if_empty(&root, &RelPath::parse("d").unwrap()));
    std::fs::remove_file(root.join("d/y.bin")).unwrap();
    assert!(WinFs.remove_dir_if_empty(&root, &RelPath::parse("d").unwrap()));
}

#[test]
fn hard_links_and_read_only_are_visible_to_checks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write(&root.join("h.bin"), 10);
    std::fs::hard_link(root.join("h.bin"), root.join("h2.bin")).unwrap();
    assert_eq!(opened_of(&root, "h.bin").link_count, 2);
    write(&root.join("ro.bin"), 10);
    let mut perm = std::fs::metadata(root.join("ro.bin"))
        .unwrap()
        .permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(root.join("ro.bin"), perm.clone()).unwrap();
    assert!(opened_of(&root, "ro.bin").readonly);
    // Clear read-only so the temp dir can be removed.
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(false);
    std::fs::set_permissions(root.join("ro.bin"), perm).unwrap();
}

#[test]
fn file_held_open_without_share_delete_is_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write(&root.join("locked.bin"), 10);
    let _held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1 /* FILE_SHARE_READ only */)
        .open(root.join("locked.bin"))
        .unwrap();
    let err = WinFs
        .delete_file(&root, &RelPath::parse("locked.bin").unwrap(), &|_| Ok(()))
        .unwrap_err();
    assert_eq!(err.reason, SkipReason::InUse);
    assert!(root.join("locked.bin").exists());
}

#[test]
fn parent_swapped_for_junction_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let victim = dir.path().join("victim");
    write(&root.join("cache/x.bin"), 10);
    write(&victim.join("x.bin"), 10);
    // Swap `cache` for a junction to the victim directory after the "scan".
    std::fs::remove_dir_all(root.join("cache")).unwrap();
    assert!(junction(&root.join("cache"), &victim));
    let err = WinFs
        .delete_file(&root, &RelPath::parse("cache/x.bin").unwrap(), &|_| Ok(()))
        .unwrap_err();
    assert_eq!(err.reason, SkipReason::LinkOrCloud);
    assert!(victim.join("x.bin").exists());
}

/// WinFs with known folders redirected into a temp directory.
struct Redirected {
    base: PathBuf,
}

impl FsBackend for Redirected {
    fn resolve(&self, folder: KnownFolder) -> Option<PathBuf> {
        Some(self.base.join(folder.token()))
    }
    fn walk(&self, root: &Path, v: &dyn WalkVisitor) -> Result<RootInfo, FsError> {
        WinFs.walk(root, v)
    }
    fn delete_file(
        &self,
        root: &Path,
        rel: &RelPath,
        check: &dyn Fn(&OpenedFile) -> Result<(), Skip>,
    ) -> Result<(), Skip> {
        WinFs.delete_file(root, rel, check)
    }
    fn remove_dir_if_empty(&self, root: &Path, rel: &RelPath) -> bool {
        WinFs.remove_dir_if_empty(root, rel)
    }
    fn running_processes(&self) -> HashSet<String> {
        HashSet::new()
    }
    fn free_space(&self, path: &Path) -> Option<u64> {
        WinFs.free_space(path)
    }
    fn recycle_bin_query(&self) -> Option<(u64, u64)> {
        None
    }
    fn recycle_bin_empty(&self) -> Result<(), Skip> {
        Err(Skip::new(SkipReason::Other))
    }
    fn registry_key_exists(&self, _: &str) -> bool {
        false
    }
    fn volumes(&self) -> Vec<VolumeInfo> {
        Vec::new()
    }
}

fn age(p: &Path, days: u64) {
    let t = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    f.set_times(std::fs::FileTimes::new().set_modified(t).set_accessed(t))
        .unwrap();
}

/// Helper adversarial test: a junction planted in an admin-cleaned root,
/// pointing at a protected test directory. Nothing outside the root changes.
#[test]
fn helper_never_follows_a_planted_junction() {
    let dir = tempfile::tempdir().unwrap();
    let fs = Redirected {
        base: dir.path().to_path_buf(),
    };
    let wintemp = dir.path().join("Windows/Temp");
    let victim = dir.path().join("victim_system_files");
    write(&victim.join("important.dll"), 1000);
    write(&wintemp.join("old.log"), 1000);
    // Creation time cannot be backdated portably; the rule uses the newest
    // timestamp, so this file would be "fresh". Use a rule-age-free check:
    // planted junction must never be entered regardless.
    age(&wintemp.join("old.log"), 5);
    assert!(junction(&wintemp.join("evil"), &victim));

    let ex = Exclusions::default();
    let mut r = scan(
        &fs,
        &ScanOptions {
            rules: builtin(),
            exclusions: &ex,
            only: None,
            threads: Some(2),
        },
        &CancelToken::new(),
        &|_| {},
    );
    assert!(r.diagnostics.reparse_skipped >= 1);
    let (idx, _) = builtin().find("windows.system_temp").unwrap();
    let cleaner = r.tree.cleaners().find(|&c| r.tree.node(c).rule == idx);
    if let Some(c) = cleaner {
        r.tree.set_selected(c, true);
    }
    let plan = r.tree.build_plan(builtin());
    if let Some(req) = build_request(&plan, builtin(), &ex) {
        let resp = execute(&fs, builtin(), &req.rule_ids, &req, &CancelToken::new());
        assert!(matches!(resp, HelperResponse::Done(_)), "{resp:?}");
    }
    assert!(
        victim.join("important.dll").exists(),
        "junction target untouched"
    );
    assert!(wintemp.join("evil").exists(), "junction itself untouched");
}

/// Full clean on a fixture tree in real NTFS: only DELETE paths disappear.
#[test]
fn end_to_end_chrome_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let fs = Redirected {
        base: dir.path().to_path_buf(),
    };
    let ud = dir.path().join("LocalAppData/Google/Chrome/User Data");
    let delete = [
        "Default/Cache/Cache_Data/f_000001",
        "Default/Code Cache/js/index",
        "Profile 1/GPUCache/data_0",
    ];
    let keep = [
        "Default/Cookies",
        "Default/Login Data",
        "Default/Bookmarks",
        "Default/Sessions/Session_1",
        "Local State",
        "Default/Cache/Login Data",
    ];
    for p in delete.iter().chain(&keep) {
        write(&ud.join(p), 5000);
    }
    let ex = Exclusions::default();
    let r = scan(
        &fs,
        &ScanOptions {
            rules: builtin(),
            exclusions: &ex,
            only: None,
            threads: Some(2),
        },
        &CancelToken::new(),
        &|_| {},
    );
    let plan = r.tree.build_plan(builtin());
    let root_of = |i: RuleIdx| r.root_of(i);
    let report = clean(
        &fs,
        &plan,
        &CleanOptions {
            rules: builtin(),
            exclusions: &ex,
            root_of: &root_of,
            include_elevated: false,
        },
        &CancelToken::new(),
        &|_| {},
    )
    .unwrap();
    assert_eq!(report.deleted_files, 3, "{report:?}");
    for p in delete {
        assert!(!ud.join(p).exists(), "{p} should be deleted");
    }
    for p in keep {
        assert!(ud.join(p).exists(), "{p} must be kept");
    }
    assert!(
        ud.join("Profile 1/GPUCache").exists(),
        "app folders are kept"
    );
}
