//! Local data in `%LOCALAPPDATA%\PurgeKit`: settings, exclusions, history.
//!
//! Every file carries a `schema_version`. Writes are atomic (temp file +
//! rename). A corrupt file is backed up, reset to defaults, and the user is told.

use std::path::{Path, PathBuf};

use purgekit_engine::{Exclusion, Exclusions};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const HISTORY_CAP: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub schema_version: u32,
    /// Opt-in, off by default.
    pub scan_on_launch: bool,
    pub show_advanced: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            schema_version: SCHEMA_VERSION,
            scan_on_launch: false,
            show_advanced: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExclusionsFile {
    schema_version: u32,
    items: Vec<Exclusion>,
}

impl Default for ExclusionsFile {
    fn default() -> Self {
        ExclusionsFile {
            schema_version: SCHEMA_VERSION,
            items: Vec::new(),
        }
    }
}

/// One clean. No file names, ever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unix seconds.
    pub timestamp: u64,
    pub categories: Vec<String>,
    pub estimated_bytes: u64,
    pub measured_bytes: Option<i64>,
    pub files_deleted: u64,
    pub files_skipped: u64,
    pub error_categories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HistoryFile {
    schema_version: u32,
    entries: Vec<HistoryEntry>,
}

impl Default for HistoryFile {
    fn default() -> Self {
        HistoryFile {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }
}

trait Versioned {
    fn version(&self) -> u32;
}
impl Versioned for Settings {
    fn version(&self) -> u32 {
        self.schema_version
    }
}
impl Versioned for ExclusionsFile {
    fn version(&self) -> u32 {
        self.schema_version
    }
}
impl Versioned for HistoryFile {
    fn version(&self) -> u32 {
        self.schema_version
    }
}

pub struct Store {
    dir: PathBuf,
}

/// Writes `bytes` to `path` atomically.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Store { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn load<T: DeserializeOwned + Serialize + Default + Versioned>(
        &self,
        name: &str,
        notices: &mut Vec<String>,
    ) -> T {
        let path = self.dir.join(name);
        let Ok(text) = std::fs::read(&path) else {
            return T::default();
        };
        match serde_json::from_slice::<T>(&text) {
            Ok(v) if v.version() == SCHEMA_VERSION => v,
            _ => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let backup = self.dir.join(format!("{name}.corrupt-{ts}"));
                let _ = std::fs::rename(&path, &backup);
                let def = T::default();
                let _ = self.save(name, &def);
                tracing::warn!(file = name, "unreadable file backed up and reset");
                notices.push(format!(
                    "{name} could not be read. PurgeKit saved a copy and reset it to defaults."
                ));
                def
            }
        }
    }

    fn save<T: Serialize>(&self, name: &str, v: &T) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(v).map_err(std::io::Error::other)?;
        write_atomic(&self.dir.join(name), &bytes)
    }

    pub fn load_settings(&self, notices: &mut Vec<String>) -> Settings {
        self.load("settings.json", notices)
    }

    pub fn save_settings(&self, s: &Settings) {
        if let Err(e) = self.save("settings.json", s) {
            tracing::error!(error = %e, "saving settings failed");
        }
    }

    pub fn load_exclusions(&self, notices: &mut Vec<String>) -> Exclusions {
        let f: ExclusionsFile = self.load("exclusions.json", notices);
        Exclusions { items: f.items }
    }

    pub fn save_exclusions(&self, e: &Exclusions) {
        let f = ExclusionsFile {
            schema_version: SCHEMA_VERSION,
            items: e.items.clone(),
        };
        if let Err(e) = self.save("exclusions.json", &f) {
            tracing::error!(error = %e, "saving exclusions failed");
        }
    }

    pub fn load_history(&self, notices: &mut Vec<String>) -> Vec<HistoryEntry> {
        let f: HistoryFile = self.load("history.json", notices);
        f.entries
    }

    pub fn save_history(&self, entries: &[HistoryEntry]) {
        let start = entries.len().saturating_sub(HISTORY_CAP);
        let f = HistoryFile {
            schema_version: SCHEMA_VERSION,
            entries: entries[start..].to_vec(),
        };
        if let Err(e) = self.save("history.json", &f) {
            tracing::error!(error = %e, "saving history failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "purgekit-store-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn roundtrip_and_defaults() {
        let s = Store::new(tmp());
        let mut n = Vec::new();
        assert_eq!(s.load_settings(&mut n), Settings::default());
        assert!(
            !Settings::default().scan_on_launch,
            "scan on launch is opt-in"
        );
        let set = Settings {
            show_advanced: true,
            ..Settings::default()
        };
        s.save_settings(&set);
        assert_eq!(s.load_settings(&mut n), set);
        assert!(n.is_empty());
    }

    #[test]
    fn corrupt_file_is_backed_up_and_reset() {
        let s = Store::new(tmp());
        std::fs::write(s.dir().join("settings.json"), b"{not json").unwrap();
        let mut n = Vec::new();
        assert_eq!(s.load_settings(&mut n), Settings::default());
        assert_eq!(n.len(), 1);
        let backups = std::fs::read_dir(s.dir())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("corrupt")
            })
            .count();
        assert_eq!(backups, 1);
    }

    #[test]
    fn history_is_capped() {
        let s = Store::new(tmp());
        let e = HistoryEntry {
            timestamp: 1,
            categories: vec![],
            estimated_bytes: 0,
            measured_bytes: None,
            files_deleted: 0,
            files_skipped: 0,
            error_categories: vec![],
        };
        s.save_history(&vec![e; 600]);
        assert_eq!(s.load_history(&mut Vec::new()).len(), HISTORY_CAP);
    }
}
