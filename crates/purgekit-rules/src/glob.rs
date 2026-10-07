//! Root-relative glob patterns.
//!
//! Semantics: case-insensitive; `/` separates components; `*` and `?` match
//! within one component; `**` (a whole component) crosses zero or more levels.
//! Patterns may not contain `.`, `..`, empty components, `\`, `:` or a leading `/`.
//! Matching uses a DP table, so no pattern can cause exponential backtracking.

use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct Glob {
    source: String,
    segs: Vec<Seg>,
}

#[derive(Clone, PartialEq, Eq)]
enum Seg {
    AnyDepth,
    Name(Vec<Tok>),
}

#[derive(Clone, PartialEq, Eq)]
enum Tok {
    Lit(char),
    Star,
    One,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobError(pub String);

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Glob {
    pub fn parse(pattern: &str) -> Result<Self, GlobError> {
        let err = |m: &str| Err(GlobError(format!("pattern {pattern:?}: {m}")));
        if pattern.is_empty() {
            return err("empty pattern");
        }
        if pattern.starts_with('/') {
            return err("must be relative to the rule root");
        }
        if pattern.contains('\\') {
            return err("use '/' as the separator");
        }
        if pattern.contains(':') {
            return err("':' is not allowed");
        }
        let mut segs = Vec::new();
        for comp in pattern.split('/') {
            match comp {
                "" => return err("empty component"),
                "." | ".." => return err("'.' and '..' are not allowed"),
                "**" => {
                    // Collapse consecutive `**`.
                    if segs.last() != Some(&Seg::AnyDepth) {
                        segs.push(Seg::AnyDepth);
                    }
                }
                c if c.contains("**") => return err("'**' must be a whole component"),
                c => {
                    let mut toks = Vec::new();
                    for ch in c.chars() {
                        match ch {
                            '*' => {
                                if toks.last() != Some(&Tok::Star) {
                                    toks.push(Tok::Star)
                                }
                            }
                            '?' => toks.push(Tok::One),
                            c if (c as u32) < 0x20 || matches!(c, '<' | '>' | '"' | '|') => {
                                return err("forbidden character");
                            }
                            c => toks.extend(c.to_lowercase().map(Tok::Lit)),
                        }
                    }
                    segs.push(Seg::Name(toks));
                }
            }
        }
        Ok(Glob {
            source: pattern.to_string(),
            segs,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    fn trailing_any_depth(&self) -> bool {
        self.segs.last() == Some(&Seg::AnyDepth)
    }

    /// Full match of case-folded path components.
    ///
    /// A trailing `**` matches one or more levels (`Cache/**` matches what is
    /// inside `Cache`, not `Cache` itself). Elsewhere `**` matches zero or more.
    pub fn matches(&self, folded: &[&str]) -> bool {
        let n = self.segs.len();
        if self.trailing_any_depth() {
            // Some strict prefix must match the pattern without its trailing `**`.
            (0..folded.len()).any(|k| self.reachable(&folded[..k])[n - 1])
        } else {
            self.reachable(folded)[n]
        }
    }

    /// True if some path strictly below `folded_dir` could match.
    pub fn could_match_below(&self, folded_dir: &[&str]) -> bool {
        let reach = self.reachable(folded_dir);
        // Any reachable state with pattern left can be completed by deeper components.
        (0..self.segs.len()).any(|i| reach[i])
    }

    /// True if every path strictly below `folded_dir` matches (the pattern
    /// ends in `**` and `folded_dir` matches the part before it). Used to
    /// prune excluded directories without entering them.
    pub fn matches_everything_below(&self, folded_dir: &[&str]) -> bool {
        self.trailing_any_depth() && self.reachable(folded_dir)[self.segs.len() - 1]
    }

    /// `reach[i]` = the first `i` segments can consume all of `path`.
    fn reachable(&self, path: &[&str]) -> Vec<bool> {
        let n = self.segs.len();
        // state[i]: first i segments consumed the components seen so far.
        let mut state = vec![false; n + 1];
        state[0] = true;
        close_any_depth(&self.segs, &mut state);
        for comp in path {
            let mut next = vec![false; n + 1];
            for i in 0..n {
                if !state[i] {
                    continue;
                }
                match &self.segs[i] {
                    // `**` consumes this component and stays, or (via closure) moves on.
                    Seg::AnyDepth => next[i] = true,
                    Seg::Name(toks) => {
                        if name_matches(toks, comp) {
                            next[i + 1] = true;
                        }
                    }
                }
            }
            close_any_depth(&self.segs, &mut next);
            state = next;
            if !state.iter().any(|b| *b) {
                break;
            }
        }
        state
    }
}

/// `**` may match zero components: a state before `**` also reaches after it.
fn close_any_depth(segs: &[Seg], state: &mut [bool]) {
    for i in 0..segs.len() {
        if state[i] && segs[i] == Seg::AnyDepth {
            state[i + 1] = true;
        }
    }
}

/// Wildcard match of one component (already case-folded) with a DP over chars.
fn name_matches(toks: &[Tok], name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    let mut dp = vec![false; chars.len() + 1];
    dp[0] = true;
    for tok in toks {
        let mut next = vec![false; chars.len() + 1];
        match tok {
            Tok::Star => {
                let mut seen = false;
                for j in 0..=chars.len() {
                    seen |= dp[j];
                    next[j] = seen;
                }
            }
            Tok::One => next[1..].copy_from_slice(&dp[..chars.len()]),
            Tok::Lit(c) => {
                for j in 0..chars.len() {
                    next[j + 1] = dp[j] && chars[j] == *c;
                }
            }
        }
        dp = next;
    }
    dp[chars.len()]
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Glob({:?})", self.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, path: &str) -> bool {
        let comps: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| c.to_lowercase())
            .collect();
        let refs: Vec<&str> = comps.iter().map(|s| s.as_str()).collect();
        Glob::parse(p).unwrap().matches(&refs)
    }

    fn below(p: &str, path: &str) -> bool {
        let comps: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| c.to_lowercase())
            .collect();
        let refs: Vec<&str> = comps.iter().map(|s| s.as_str()).collect();
        Glob::parse(p).unwrap().could_match_below(&refs)
    }

    #[test]
    fn single_star_stays_in_one_level() {
        assert!(m("*/Cache/**", "Default/Cache/x"));
        assert!(m("*/Cache/**", "Profile 1/Cache/a/b/c"));
        assert!(!m("*/Cache/**", "a/b/Cache/x"));
        assert!(m("*.dmp", "app.exe.123.dmp"));
        assert!(!m("*.dmp", "sub/app.dmp"));
    }

    #[test]
    fn double_star_crosses_levels_and_matches_zero() {
        assert!(m("**", "a"));
        assert!(m("**", "a/b/c"));
        assert!(m("**/Login Data*", "Login Data"));
        assert!(m("**/Login Data*", "x/y/Login Data-journal"));
        assert!(!m("Cache/**", "Cache"));
        assert!(m("Cache/**", "Cache/x"));
        assert!(!m("**", ""));
        assert!(m("a/**/b", "a/b"));
        assert!(m("a/**/b", "a/x/y/b"));
        assert!(!m("a/**/b", "a/x/y/c"));
    }

    #[test]
    fn case_insensitive() {
        assert!(m("Thumbcache_*.db", "THUMBCACHE_1024.DB"));
        assert!(m("ÄBC", "äbc"));
    }

    #[test]
    fn question_mark() {
        assert!(m("data_?", "data_0"));
        assert!(!m("data_?", "data_10"));
    }

    #[test]
    fn prefix_pruning() {
        assert!(below("*/Cache/**", "Default"));
        assert!(below("*/Cache/**", "Default/Cache"));
        assert!(below("*/Cache/**", "Default/Cache/sub"));
        assert!(!below("*/Cache/**", "Default/Sessions"));
        assert!(!below("*.dmp", "sub"));
        assert!(below("**", "anything/at/all"));
        assert!(!below("a/b", "a/b"));
    }

    #[test]
    fn rejects_bad_patterns() {
        for p in [
            "", "/abs", "a/../b", "./a", "a//b", r"a\b", "C:/x", "a**/b", "x/..",
        ] {
            assert!(Glob::parse(p).is_err(), "{p}");
        }
    }

    #[test]
    fn many_double_stars_are_fast() {
        let p = "**/".repeat(50) + "x";
        let path = "a/".repeat(200) + "y";
        assert!(!m(&p, &path));
    }
}
