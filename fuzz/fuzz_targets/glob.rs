//! Glob parser and DP matcher on arbitrary patterns and paths.
//!
//! Input: `<pattern> NUL <path>`. Checks that nothing panics, that matching
//! stays consistent with the walker's pruning (`could_match_below`,
//! `matches_everything_below`) and that a parsed pattern re-parses to itself.
//! libFuzzer's per-input timeout also catches super-linear matching.

#![no_main]

use libfuzzer_sys::fuzz_target;
use purgekit_core::RelPath;
use purgekit_rules::Glob;

fuzz_target!(|data: &[u8]| {
    let (pat, path) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let pat = String::from_utf8_lossy(pat);
    let Ok(glob) = Glob::parse(&pat) else {
        return;
    };
    assert!(
        Glob::parse(glob.as_str()).is_ok_and(|g| g == glob),
        "pattern {pat:?} does not re-parse to itself"
    );

    let path = String::from_utf8_lossy(path);
    let Ok(rel) = RelPath::parse(&path) else {
        return;
    };
    let comps: Vec<&str> = rel.folded_components().collect();

    if glob.matches(&comps) {
        // Every strict ancestor must look enterable, or the walker would
        // never reach a file the pattern matches.
        for k in 0..comps.len() {
            assert!(
                glob.could_match_below(&comps[..k]),
                "{pat:?} matches {rel} but prunes at depth {k}"
            );
        }
    }
    for k in 0..=comps.len() {
        let dir = &comps[..k];
        if glob.matches_everything_below(dir) {
            let mut child = dir.to_vec();
            child.push("x");
            assert!(
                glob.matches(&child),
                "{pat:?} claims all of {dir:?} but not a child"
            );
        }
    }
});
