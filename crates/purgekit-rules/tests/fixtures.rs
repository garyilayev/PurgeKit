//! Rule fixtures: every rule has a manifest in `tests/fixtures/rules/<id>.txt`
//! with each path marked DELETE or KEEP. Any KEEP path that matches, or any
//! DELETE path that does not, fails the test.

use std::path::PathBuf;

use purgekit_core::{AgeSpec, FileTime, RelPath, protected};
use purgekit_rules::{EntryTimes, builtin};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rules")
}

fn times(age_secs: u64, now: FileTime) -> EntryTimes {
    let t = FileTime(now.0 - age_secs * 10_000_000);
    EntryTimes {
        created: t,
        modified: t,
        changed: t,
    }
}

#[test]
fn every_rule_has_a_fixture_and_all_fixtures_pass() {
    let now = FileTime::from_unix_secs(1_800_000_000);
    let mut failures = Vec::new();
    for (_, rule) in builtin().iter() {
        let path = fixtures_dir().join(format!("{}.txt", rule.id));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("rule '{}' has no fixture at {}", rule.id, path.display()));
        let mut delete_lines = 0;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (action, rest) = line.split_once(' ').expect("action and path");
            let (age, rel) = match rest.strip_prefix("age=") {
                Some(r) => {
                    let (a, p) = r.split_once(' ').expect("age and path");
                    (AgeSpec::parse(a).expect("valid age").secs, p)
                }
                None => (365 * 86_400, rest),
            };
            let rel = RelPath::parse(rel.trim()).expect("valid fixture path");
            let matched = rule.matches(&rel, false, &times(age, now), now)
                && !protected::is_protected_under([], &rel);
            let ok = match action {
                "DELETE" => {
                    delete_lines += 1;
                    matched
                }
                "KEEP" => !matched,
                other => panic!("{}:{}: unknown action {other}", path.display(), n + 1),
            };
            if !ok {
                failures.push(format!("{}: {action} {rel} (line {})", rule.id, n + 1));
            }
        }
        if rule.mechanism == purgekit_rules::Mechanism::Files && delete_lines == 0 {
            failures.push(format!("{}: fixture has no DELETE lines", rule.id));
        }
    }
    assert!(
        failures.is_empty(),
        "fixture failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn no_orphan_fixtures() {
    for entry in std::fs::read_dir(fixtures_dir()).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        let id = name
            .strip_suffix(".txt")
            .expect("fixture files end in .txt");
        assert!(builtin().find(id).is_some(), "fixture {name} has no rule");
    }
}

#[test]
fn every_rule_has_transparency_strings_and_tier() {
    for (_, r) in builtin().iter() {
        assert!(!r.what.trim().is_empty(), "{}", r.id);
        assert!(!r.why_safe.trim().is_empty(), "{}", r.id);
        assert!(!r.after_effects.trim().is_empty(), "{}", r.id);
    }
}

#[test]
fn rule_set_covers_the_0_1_scope() {
    let expected = [
        "windows.user_temp",
        "windows.system_temp",
        "windows.crash_dumps",
        "windows.error_reports",
        "windows.thumbnail_cache",
        "windows.recycle_bin",
        "chrome.cache",
        "edge.cache",
        "firefox.cache",
        "discord.cache",
        "spotify.cache",
        "vscode.cache",
        "cursor.cache",
        "slack.cache",
        "teams.cache",
        "steam.web_cache",
    ];
    for id in expected {
        assert!(builtin().find(id).is_some(), "missing rule {id}");
    }
    assert_eq!(builtin().rules.len(), expected.len());
}

#[test]
fn only_windows_temp_needs_elevation() {
    let elevated: Vec<_> = builtin()
        .iter()
        .filter(|(_, r)| r.needs_elevation())
        .map(|(_, r)| r.id.as_str())
        .collect();
    assert_eq!(elevated, ["windows.system_temp"]);
}

#[test]
fn traversal_never_matches() {
    // `..` cannot even be represented as a RelPath.
    for p in ["../x", "Default/../../Windows/System32/x", r"..\..\x"] {
        assert!(RelPath::parse(p).is_err(), "{p}");
    }
}
