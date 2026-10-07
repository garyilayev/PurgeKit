use std::fmt;

use serde::{Deserialize, Serialize};

/// Risk tier of a rule. Ordered from least to most cautious, so `max` of two
/// tiers is the more conservative one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Selected by default, permanent delete.
    Safe,
    /// Not selected by default, sent to the Recycle Bin.
    Review,
    /// Hidden behind "Show advanced", not selected, often elevated.
    Advanced,
}

impl Tier {
    /// The deletion method a tier implies when the rule does not override it.
    pub fn default_delete_method(self) -> DeleteMethod {
        match self {
            Tier::Safe | Tier::Advanced => DeleteMethod::Permanent,
            Tier::Review => DeleteMethod::RecycleBin,
        }
    }

    /// Whether candidates of this tier start out selected.
    pub fn selected_by_default(self) -> bool {
        matches!(self, Tier::Safe)
    }

    pub fn label(self) -> &'static str {
        match self {
            Tier::Safe => "Safe",
            Tier::Review => "Review",
            Tier::Advanced => "Advanced",
        }
    }
}

/// How a candidate is removed. Ordered from least to most recoverable, so
/// `max` of two methods is the safer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteMethod {
    Permanent,
    RecycleBin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Elevation {
    None,
    Required,
}

/// What kind of filesystem entries a rule may select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Files,
    Dirs,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Windows,
    Browsers,
    Apps,
    Developer,
}

impl Category {
    pub const ALL: [Category; 4] = [
        Category::Windows,
        Category::Browsers,
        Category::Apps,
        Category::Developer,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Windows => "Windows",
            Category::Browsers => "Browsers",
            Category::Apps => "Apps",
            Category::Developer => "Developer",
        }
    }
}

/// Known-folder tokens a rule root may start with. Resolved by the platform
/// layer (`SHGetKnownFolderPath`, `GetTempPath2W`); never hardcoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KnownFolder {
    LocalAppData,
    RoamingAppData,
    LocalAppDataLow,
    ProgramData,
    Windows,
    Temp,
}

impl KnownFolder {
    pub const ALL: [KnownFolder; 6] = [
        KnownFolder::LocalAppData,
        KnownFolder::RoamingAppData,
        KnownFolder::LocalAppDataLow,
        KnownFolder::ProgramData,
        KnownFolder::Windows,
        KnownFolder::Temp,
    ];

    pub fn token(self) -> &'static str {
        match self {
            KnownFolder::LocalAppData => "LocalAppData",
            KnownFolder::RoamingAppData => "RoamingAppData",
            KnownFolder::LocalAppDataLow => "LocalAppDataLow",
            KnownFolder::ProgramData => "ProgramData",
            KnownFolder::Windows => "Windows",
            KnownFolder::Temp => "Temp",
        }
    }

    pub fn from_token(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.token() == s)
    }

    /// Environment-variable style form used in logs so usernames never appear.
    pub fn log_form(self) -> &'static str {
        match self {
            KnownFolder::LocalAppData => "%LOCALAPPDATA%",
            KnownFolder::RoamingAppData => "%APPDATA%",
            KnownFolder::LocalAppDataLow => "%USERPROFILE%\\AppData\\LocalLow",
            KnownFolder::ProgramData => "%PROGRAMDATA%",
            KnownFolder::Windows => "%WINDIR%",
            KnownFolder::Temp => "%TEMP%",
        }
    }
}

/// NTFS 128-bit file ID (`FILE_ID_128`). 64-bit IDs are zero-extended.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct FileId128(pub [u8; 16]);

impl FileId128 {
    pub fn from_u64(id: u64) -> Self {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&id.to_le_bytes());
        FileId128(b)
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 32 || !s.is_ascii() {
            return None;
        }
        let mut b = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).ok()?;
            b[i] = u8::from_str_radix(hex, 16).ok()?;
        }
        Some(FileId128(b))
    }
}

impl fmt::Debug for FileId128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId128({})", self.to_hex())
    }
}

/// Stable identity of a scanned entry: volume serial plus file ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CandidateId {
    pub volume: u64,
    pub file_id: FileId128,
}

/// Tri-state checkbox value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Selection {
    Checked,
    Unchecked,
    Partial,
}

/// Plain-language reasons a candidate was skipped. Shown to the user grouped
/// by reason; technical detail goes to logs and an expander.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Another program holds the file open (sharing violation / lock).
    InUse,
    /// The owning app is running (`process_deps`).
    AppRunning,
    AccessDenied,
    ReadOnly,
    /// More than one hard link: deleting one name frees nothing.
    HardLinked,
    /// Reparse point, cloud placeholder or offline file.
    LinkOrCloud,
    /// File changed identity, vanished, or no longer matches its rule.
    Changed,
    /// Matched the protected-data list. Should never happen past the scan.
    Protected,
    /// User cancelled before this item was reached.
    Cancelled,
    /// The Recycle Bin cannot hold the item and the user declined permanent deletion.
    TooLargeForRecycleBin,
    /// Path could not be represented safely (unexpanded short name, invalid chars).
    UnsafePath,
    Other,
}

impl SkipReason {
    pub fn describe(self) -> &'static str {
        match self {
            SkipReason::InUse => "Another program is using them",
            SkipReason::AppRunning => "The app that owns them is running",
            SkipReason::AccessDenied => "Windows did not allow access",
            SkipReason::ReadOnly => "They are marked read-only",
            SkipReason::HardLinked => "They are shared with another location (hard link)",
            SkipReason::LinkOrCloud => "They are links or cloud files",
            SkipReason::Changed => "They changed since the scan",
            SkipReason::Protected => "They are protected data",
            SkipReason::Cancelled => "Cleaning was cancelled",
            SkipReason::TooLargeForRecycleBin => "Too large for the Recycle Bin",
            SkipReason::UnsafePath => "Their names could not be checked safely",
            SkipReason::Other => "Something unexpected happened",
        }
    }
}
