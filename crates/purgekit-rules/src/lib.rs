//! PurgeKit rule database: TOML rules compiled into the binary.
//!
//! Rules are data and the engine is code. `build.rs` validates every file in
//! `rules/` with the same compiler used here, so loading cannot fail at run
//! time for a binary that built.

#![forbid(unsafe_code)]

pub mod compile;
pub mod glob;
pub mod rule;

use std::sync::OnceLock;

pub use glob::Glob;
pub use rule::{Detect, EntryTimes, Mechanism, RootSpec, Rule};

include!(concat!(env!("OUT_DIR"), "/rules_gen.rs"));

/// Index into [`RuleSet::rules`]. `u16` keeps tree nodes small.
pub type RuleIdx = u16;

#[derive(Debug)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// App version plus a short content hash of all rule sources.
    pub version: String,
}

impl RuleSet {
    pub fn get(&self, idx: RuleIdx) -> &Rule {
        &self.rules[idx as usize]
    }

    pub fn find(&self, id: &str) -> Option<(RuleIdx, &Rule)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, r)| r.id == id)
            .map(|(i, r)| (i as RuleIdx, r))
    }

    pub fn iter(&self) -> impl Iterator<Item = (RuleIdx, &Rule)> {
        self.rules
            .iter()
            .enumerate()
            .map(|(i, r)| (i as RuleIdx, r))
    }
}

/// The embedded rule set.
pub fn builtin() -> &'static RuleSet {
    static SET: OnceLock<RuleSet> = OnceLock::new();
    SET.get_or_init(|| {
        let rules = compile::compile_sources(RULE_SOURCES)
            .unwrap_or_else(|e| unreachable!("rules were validated at build time: {e:?}"));
        assert!(rules.len() <= RuleIdx::MAX as usize);
        RuleSet {
            rules,
            version: format!("{}+{:08x}", env!("CARGO_PKG_VERSION"), sources_hash()),
        }
    })
}

/// FNV-1a over file names and contents; identifies the rule set in plans and the About page.
fn sources_hash() -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for (name, text) in RULE_SOURCES {
        for b in name.bytes().chain(text.bytes()) {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
    }
    h
}
