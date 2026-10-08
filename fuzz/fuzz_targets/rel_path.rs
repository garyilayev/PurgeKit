//! Path normalization + every built-in rule on arbitrary input.
//!
//! Invariant (spec, "Matcher fuzzing"): a rule never authorizes a path outside
//! its root. Arbitrary bytes are decoded three ways (strict UTF-8, lossy
//! UTF-8, lossy UTF-16LE as Windows names are) so invalid encodings, Unicode,
//! very long, UNC-style (`\\?\`, `\\server`), 8.3 and relative inputs all
//! reach `RelPath::parse` and `Rule::matches_path`. Any panic is a failure.

#![no_main]

use libfuzzer_sys::fuzz_target;
use purgekit_core::path::validate_component;
use purgekit_core::{RelPath, protected};
use purgekit_rules::builtin;

/// Resolves `rel` against a root the way Win32 would treat the joined string
/// (`.` skipped, `..` pops, a drive/stream colon or an empty component
/// escapes) and reports whether the result is still strictly inside the root.
fn stays_inside(rel: &str) -> bool {
    let root = ["c:", "users", "u", "appdata", "local", "rule-root"];
    let mut stack: Vec<&str> = root.to_vec();
    for comp in rel.split(['/', '\\']) {
        match comp {
            "" => return false, // leading or doubled separator: absolute / UNC form
            "." => {}
            ".." => {
                stack.pop();
            }
            c if c.contains(':') => return false,
            c => stack.push(c),
        }
    }
    stack.len() > root.len() && stack[..root.len()] == root
}

fn check(input: &str) {
    let Ok(rel) = RelPath::parse(input) else {
        return; // Unparseable paths can never be candidates.
    };

    // Normalization is idempotent and only yields valid components.
    let again = RelPath::parse(rel.as_str()).expect("normalized path re-parses");
    assert_eq!(rel, again, "parse is not idempotent for {input:?}");
    for c in rel.components() {
        assert!(
            validate_component(c).is_ok(),
            "invalid component {c:?} kept from {input:?}"
        );
    }

    for (_, rule) in builtin().iter() {
        // Must never panic, whatever the outcome.
        let _ = rule.should_descend(&rel);
        let _ = rule.dir_in_cleaned_area(&rel);

        for is_dir in [false, true] {
            if !rule.matches_path(&rel, is_dir) {
                continue;
            }
            let id = &rule.id;
            assert!(!rel.is_root(), "rule {id} authorized its own root");
            assert!(
                stays_inside(rel.as_str()),
                "rule {id} authorized {rel} outside its root"
            );
            assert!(!rel.has_short_name(), "rule {id} authorized 8.3 name {rel}");
            assert!(
                !protected::is_protected_under([], &rel),
                "rule {id} authorized protected {rel}"
            );
            assert!(
                rule.matches_path_raw(&rel, is_dir),
                "rule {id}: deny-list widened a match for {rel}"
            );
            // The walker must have been allowed into every ancestor.
            let mut dir = rel.parent();
            while let Some(d) = dir {
                assert!(
                    rule.should_descend(&d),
                    "rule {id} would not enter {d} for {rel}"
                );
                dir = d.parent();
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        check(s);
    } else {
        check(&String::from_utf8_lossy(data));
    }
    let (pairs, _) = data.as_chunks::<2>();
    let wide: Vec<u16> = pairs.iter().map(|b| u16::from_le_bytes(*b)).collect();
    check(&String::from_utf16_lossy(&wide));
});
