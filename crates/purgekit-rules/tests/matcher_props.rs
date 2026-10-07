//! Property tests: a rule never authorizes a path outside its root, and odd
//! inputs (Unicode, very long, UNC-style, 8.3, relative, invalid) never
//! produce a match that bypasses normalization.

use proptest::prelude::*;
use purgekit_core::{FileTime, RelPath, protected};
use purgekit_rules::{EntryTimes, builtin};

fn old_times() -> (EntryTimes, FileTime) {
    let now = FileTime::from_unix_secs(1_800_000_000);
    let t = FileTime::from_unix_secs(1_000_000_000);
    (
        EntryTimes {
            created: t,
            modified: t,
            changed: t,
        },
        now,
    )
}

fn component() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("..".to_string()),
        Just(".".to_string()),
        Just("".to_string()),
        Just("Cache".to_string()),
        Just("Default".to_string()),
        Just("Login Data".to_string()),
        Just("LOGIND~1".to_string()),
        Just("C:".to_string()),
        Just("\\\\?\\C:".to_string()),
        Just("file.txt:stream".to_string()),
        "[a-zA-Z0-9 _.~-]{1,12}",
        "\\PC{1,8}",
        "[a-z]{200,260}",
    ]
}

fn raw_path() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(component(), 0..12),
        prop::bool::ANY,
        prop::bool::ANY,
    )
        .prop_map(|(c, back, lead)| {
            let sep = if back { "\\" } else { "/" };
            let p = c.join(sep);
            if lead { format!("{sep}{sep}{p}") } else { p }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn matched_paths_are_always_clean_relative(raw in raw_path()) {
        let (times, now) = old_times();
        if let Ok(rel) = RelPath::parse(&raw) {
            for (_, rule) in builtin().iter() {
                if rule.matches(&rel, false, &times, now) {
                    // Matched implies: no traversal, not absolute, no short names, not protected by name.
                    prop_assert!(!rel.is_root());
                    prop_assert!(!rel.has_short_name());
                    prop_assert!(rel.components().all(|c| c != ".." && c != "." && !c.contains(':')));
                    prop_assert!(!protected::is_protected_under([], &rel), "rule {} matched protected {}", rule.id, rel);
                }
            }
        } else {
            // Unparseable paths can never be candidates; nothing to check.
        }
    }

    #[test]
    fn parse_is_idempotent(raw in raw_path()) {
        if let Ok(rel) = RelPath::parse(&raw) {
            let again = RelPath::parse(rel.as_str()).unwrap();
            prop_assert_eq!(rel, again);
        }
    }

    #[test]
    fn descend_is_consistent_with_match(raw in raw_path()) {
        // If a file matches, the walker must have been allowed to enter every ancestor.
        let (times, now) = old_times();
        if let Ok(rel) = RelPath::parse(&raw) {
            for (_, rule) in builtin().iter() {
                if rule.matches(&rel, false, &times, now) {
                    let mut dir = rel.parent();
                    while let Some(d) = dir {
                        prop_assert!(rule.should_descend(&d), "rule {} would not enter {} for {}", rule.id, d, rel);
                        dir = d.parent();
                    }
                }
            }
        }
    }
}
