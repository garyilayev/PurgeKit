//! Compiled rule and its matching semantics.

use purgekit_core::{
    AgeSpec, Category, DeleteMethod, Elevation, FileTime, KnownFolder, RelPath, Target, Tier,
    protected,
};

use crate::glob::Glob;

/// How a rule finds and removes its items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// Files under `root` matched by include/exclude globs.
    Files,
    /// The Recycle Bin, through `SHQueryRecycleBin` / `SHEmptyRecycleBin`.
    RecycleBin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detect {
    /// The rule applies when its root directory exists.
    RootExists,
    /// The rule applies when this registry key exists (read-only check).
    RegistryKey(String),
    /// Always present (system mechanisms like the Recycle Bin).
    Always,
}

/// Rule root: a known folder plus a relative path below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSpec {
    pub folder: KnownFolder,
    pub rel: RelPath,
}

impl RootSpec {
    /// Log-safe form, e.g. `%LOCALAPPDATA%\Google\Chrome\User Data`.
    pub fn log_form(&self) -> String {
        if self.rel.is_root() {
            self.folder.log_form().to_string()
        } else {
            format!("{}\\{}", self.folder.log_form(), self.rel.to_windows())
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub display_name: String,
    pub category: Category,
    pub what: String,
    pub why_safe: String,
    pub after_effects: String,
    pub detect: Detect,
    pub mechanism: Mechanism,
    /// `None` only for non-file mechanisms.
    pub root: Option<RootSpec>,
    pub include: Vec<Glob>,
    pub exclude: Vec<Glob>,
    pub min_age: Option<AgeSpec>,
    pub max_age: Option<AgeSpec>,
    pub target: Target,
    pub tier: Tier,
    pub delete_method: DeleteMethod,
    pub elevation: Elevation,
    /// Lower-cased executable names, e.g. `chrome.exe`.
    pub process_deps: Vec<String>,
    pub regenerates: bool,
}

/// Timestamps used for age checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntryTimes {
    pub created: FileTime,
    pub modified: FileTime,
    pub changed: FileTime,
}

impl EntryTimes {
    /// The newest timestamp. Age rules use it so a file counts as old only if
    /// it was neither created, written nor changed recently.
    pub fn newest(&self) -> FileTime {
        self.created.max(self.modified).max(self.changed)
    }
}

impl Rule {
    /// Path-only match (no age check), with the protected-data deny-list
    /// applied last. This is what the scanner and the cleaner use.
    pub fn matches_path(&self, rel: &RelPath, is_dir: bool) -> bool {
        self.matches_path_raw(rel, is_dir) && !protected::is_protected_under([], rel)
    }

    /// Rule-only match without the deny-list. Only the build-time protected
    /// fixture check uses this: it proves the rule itself avoids protected data.
    /// Exclusions apply to the path and to every ancestor, so an excluded
    /// directory excludes its whole subtree.
    pub fn matches_path_raw(&self, rel: &RelPath, is_dir: bool) -> bool {
        if self.mechanism != Mechanism::Files || rel.is_root() || rel.has_short_name() {
            return false;
        }
        let kind_ok = match self.target {
            Target::Files => !is_dir,
            Target::Dirs => is_dir,
            Target::Both => true,
        };
        if !kind_ok {
            return false;
        }
        let comps: Vec<&str> = rel.folded_components().collect();
        if self.is_excluded_comps(&comps) {
            return false;
        }
        self.include.iter().any(|g| g.matches(&comps))
    }

    /// Full match including the age window.
    pub fn matches(&self, rel: &RelPath, is_dir: bool, times: &EntryTimes, now: FileTime) -> bool {
        self.matches_path(rel, is_dir) && self.age_ok(times, now)
    }

    pub fn age_ok(&self, times: &EntryTimes, now: FileTime) -> bool {
        let age = times.newest().age_secs(now);
        self.min_age.is_none_or(|a| age >= a.secs) && self.max_age.is_none_or(|a| age <= a.secs)
    }

    /// Whether the walker should enter `dir`: it is not excluded and some
    /// include pattern could match below it. Callers only ask for children of
    /// directories that already passed, so ancestors need no re-check here.
    pub fn should_descend(&self, dir: &RelPath) -> bool {
        if self.mechanism != Mechanism::Files || dir.has_short_name() {
            return false;
        }
        let comps: Vec<&str> = dir.folded_components().collect();
        if !comps.is_empty()
            && self
                .exclude
                .iter()
                .any(|g| g.matches(&comps) || g.matches_everything_below(&comps))
        {
            return false;
        }
        self.include.iter().any(|g| g.could_match_below(&comps))
    }

    fn is_excluded_comps(&self, comps: &[&str]) -> bool {
        (1..=comps.len()).any(|n| self.exclude.iter().any(|g| g.matches(&comps[..n])))
    }

    /// True if `dir` lies inside the area the rule cleans (an include pattern
    /// matches it as a path, and it is not excluded). Only such directories
    /// may be removed when emptied, so app folders like `Profile 1` or the
    /// `Cache` folder itself are always kept.
    pub fn dir_in_cleaned_area(&self, dir: &RelPath) -> bool {
        if self.mechanism != Mechanism::Files || dir.is_root() || dir.has_short_name() {
            return false;
        }
        let comps: Vec<&str> = dir.folded_components().collect();
        !self.is_excluded_comps(&comps) && self.include.iter().any(|g| g.matches(&comps))
    }

    pub fn needs_elevation(&self) -> bool {
        self.elevation == Elevation::Required
    }
}
