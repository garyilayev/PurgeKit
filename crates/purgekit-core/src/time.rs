use serde::{Deserialize, Serialize};

/// Windows FILETIME: 100 ns ticks since 1601-01-01 UTC.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct FileTime(pub u64);

const TICKS_PER_SEC: u64 = 10_000_000;
/// Seconds between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

impl FileTime {
    pub fn from_unix_secs(secs: u64) -> Self {
        FileTime((secs + EPOCH_DIFF_SECS) * TICKS_PER_SEC)
    }

    pub fn to_unix_secs(self) -> u64 {
        (self.0 / TICKS_PER_SEC).saturating_sub(EPOCH_DIFF_SECS)
    }

    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::from_unix_secs(secs)
    }

    /// Age in seconds relative to `now`. Timestamps in the future count as age 0,
    /// which keeps age-gated rules from matching them.
    pub fn age_secs(self, now: FileTime) -> u64 {
        now.0.saturating_sub(self.0) / TICKS_PER_SEC
    }
}

/// Age bound parsed from rule strings like `"24h"`, `"7d"`, `"30m"`, `"90d"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgeSpec {
    pub secs: u64,
}

impl AgeSpec {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
        let n: u64 = num.parse().ok()?;
        let mult = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            "w" => 7 * 86_400,
            _ => return None,
        };
        Some(AgeSpec {
            secs: n.checked_mul(mult)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ages() {
        assert_eq!(AgeSpec::parse("24h").unwrap().secs, 86_400);
        assert_eq!(AgeSpec::parse("7d").unwrap().secs, 604_800);
        assert_eq!(AgeSpec::parse("30m").unwrap().secs, 1800);
        assert!(AgeSpec::parse("24").is_none());
        assert!(AgeSpec::parse("h").is_none());
        assert!(AgeSpec::parse("1y").is_none());
        assert!(AgeSpec::parse("-1h").is_none());
    }

    #[test]
    fn future_times_have_zero_age() {
        let now = FileTime::from_unix_secs(1_000_000);
        let later = FileTime::from_unix_secs(2_000_000);
        assert_eq!(later.age_secs(now), 0);
        assert_eq!(now.age_secs(later), 1_000_000);
    }

    #[test]
    fn unix_roundtrip() {
        assert_eq!(
            FileTime::from_unix_secs(1_700_000_000).to_unix_secs(),
            1_700_000_000
        );
    }
}
