//! Root-relative path normalization.
//!
//! Every rule decision is made on a [`RelPath`]: `/` separators, no empty,
//! `.` or `..` components, nothing absolute, no characters Windows forbids in
//! names, and a case-folded form for matching. Anything that cannot be
//! represented unambiguously is rejected (fail closed).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("path is absolute or has a drive/UNC prefix")]
    Absolute,
    #[error("path contains a '..' component")]
    ParentRef,
    #[error("path contains a forbidden character")]
    InvalidChar,
    #[error("path component ends with a dot or space")]
    TrailingDotOrSpace,
}

/// A normalized, root-relative path. Empty means the root itself.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelPath {
    original: String,
    folded: String,
    has_short_name: bool,
}

impl RelPath {
    pub fn root() -> Self {
        RelPath {
            original: String::new(),
            folded: String::new(),
            has_short_name: false,
        }
    }

    pub fn parse(input: &str) -> Result<Self, PathError> {
        if input.starts_with('/') || input.starts_with('\\') {
            return Err(PathError::Absolute);
        }
        let mut out = RelPath::root();
        for comp in input.split(['/', '\\']) {
            if comp.is_empty() || comp == "." {
                continue;
            }
            out = out.join(comp)?;
        }
        Ok(out)
    }

    /// Appends one name component (as returned by directory enumeration).
    pub fn join(&self, name: &str) -> Result<Self, PathError> {
        validate_component(name)?;
        let mut original = String::with_capacity(self.original.len() + name.len() + 1);
        original.push_str(&self.original);
        let mut folded = String::with_capacity(self.folded.len() + name.len() + 1);
        folded.push_str(&self.folded);
        if !original.is_empty() {
            original.push('/');
            folded.push('/');
        }
        original.push_str(name);
        folded.push_str(&fold(name));
        Ok(RelPath {
            original,
            folded,
            has_short_name: self.has_short_name || looks_like_short_name(name),
        })
    }

    pub fn is_root(&self) -> bool {
        self.original.is_empty()
    }

    /// Original-case form with `/` separators.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Case-folded form used for all matching.
    pub fn folded(&self) -> &str {
        &self.folded
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.original.split('/').filter(|c| !c.is_empty())
    }

    pub fn folded_components(&self) -> impl Iterator<Item = &str> {
        self.folded.split('/').filter(|c| !c.is_empty())
    }

    pub fn depth(&self) -> usize {
        self.components().count()
    }

    /// Last component, original case.
    pub fn file_name(&self) -> Option<&str> {
        self.original.rsplit('/').next().filter(|s| !s.is_empty())
    }

    pub fn parent(&self) -> Option<RelPath> {
        if self.is_root() {
            return None;
        }
        let orig = self.original.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        Some(RelPath::parse(orig).expect("prefix of a valid path is valid"))
    }

    /// True if any component looks like an unexpanded 8.3 short name.
    /// The matcher refuses such paths and the protected check treats them as
    /// protected, because `LOGIND~1` could be `Login Data`.
    pub fn has_short_name(&self) -> bool {
        self.has_short_name
    }

    /// Windows form with backslashes, for display and opening.
    pub fn to_windows(&self) -> String {
        self.original.replace('/', "\\")
    }
}

impl fmt::Debug for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelPath({:?})", self.original)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

/// Case folding used for matching. NTFS compares with its upcase table;
/// Unicode lowercase is a close, conservative approximation.
pub fn fold(s: &str) -> String {
    s.to_lowercase()
}

pub fn validate_component(name: &str) -> Result<(), PathError> {
    if name.is_empty() || name == "." {
        return Err(PathError::InvalidChar);
    }
    if name == ".." {
        return Err(PathError::ParentRef);
    }
    if name.contains(':') {
        // Drive letters and alternate data streams.
        return Err(PathError::Absolute);
    }
    for c in name.chars() {
        if (c as u32) < 0x20
            || matches!(
                c,
                '<' | '>' | '"' | '|' | '?' | '*' | '/' | '\\' | '\u{FFFD}'
            )
        {
            return Err(PathError::InvalidChar);
        }
    }
    if name.ends_with('.') || name.ends_with(' ') {
        // Win32 silently strips these, so the name would be ambiguous.
        return Err(PathError::TrailingDotOrSpace);
    }
    Ok(())
}

/// Detects generated 8.3 names such as `LOGIND~1` or `PROGRA~2.TXT`.
/// Real short names are upper case ASCII, so lower-case names like
/// `word~1.tmp` (common in temp folders) are not flagged.
pub fn looks_like_short_name(name: &str) -> bool {
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) => (b, Some(e)),
        None => (name, None),
    };
    let Some((stem, digits)) = base.rsplit_once('~') else {
        return false;
    };
    let valid =
        |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || "_$%'-@{}!#()&^".contains(c);
    !stem.is_empty()
        && stem.len() <= 7
        && stem.chars().all(valid)
        && !digits.is_empty()
        && digits.len() <= 6
        && digits.chars().all(|c| c.is_ascii_digit())
        && base.len() <= 8
        && ext.is_none_or(|e| e.len() <= 3 && e.chars().all(valid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_separators_and_dots() {
        let p = RelPath::parse(r"Default\.\Cache//Cache_Data\f_000001").unwrap();
        assert_eq!(p.as_str(), "Default/Cache/Cache_Data/f_000001");
        assert_eq!(p.folded(), "default/cache/cache_data/f_000001");
        assert_eq!(p.depth(), 4);
        assert_eq!(p.file_name(), Some("f_000001"));
        assert_eq!(p.parent().unwrap().as_str(), "Default/Cache/Cache_Data");
    }

    #[test]
    fn rejects_traversal_and_absolute() {
        assert_eq!(RelPath::parse("a/../b"), Err(PathError::ParentRef));
        assert_eq!(RelPath::parse(".."), Err(PathError::ParentRef));
        assert_eq!(RelPath::parse("/a"), Err(PathError::Absolute));
        assert_eq!(RelPath::parse(r"\\?\C:\a"), Err(PathError::Absolute));
        assert_eq!(RelPath::parse(r"\\server\share"), Err(PathError::Absolute));
        assert_eq!(RelPath::parse("C:/Windows"), Err(PathError::Absolute));
        assert_eq!(RelPath::parse("file.txt:stream"), Err(PathError::Absolute));
    }

    #[test]
    fn rejects_bad_chars() {
        assert!(RelPath::parse("a*b").is_err());
        assert!(RelPath::parse("a\u{0}b").is_err());
        assert!(RelPath::parse("bad\u{FFFD}name").is_err());
        assert!(RelPath::parse("trailing.").is_err());
        assert!(RelPath::parse("trailing ").is_err());
        assert!(RelPath::root().join("..").is_err());
        assert!(RelPath::root().join("a/b").is_err());
    }

    #[test]
    fn short_names() {
        assert!(looks_like_short_name("LOGIND~1"));
        assert!(looks_like_short_name("PROGRA~2.TXT"));
        assert!(looks_like_short_name("A~123456"));
        assert!(!looks_like_short_name("word~1.tmp"));
        assert!(!looks_like_short_name("~DF1234.TMP"));
        assert!(!looks_like_short_name("Login Data"));
        assert!(!looks_like_short_name("ABCDEFGH~1"));
        assert!(RelPath::parse("Default/LOGIND~1").unwrap().has_short_name());
        assert!(
            !RelPath::parse("Default/Login Data")
                .unwrap()
                .has_short_name()
        );
    }

    #[test]
    fn unicode_folding() {
        let p = RelPath::parse("Ünïcode/ÄBC").unwrap();
        assert_eq!(p.folded(), "ünïcode/äbc");
    }
}
