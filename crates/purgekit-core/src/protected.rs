//! Protected-data deny-list: passwords, bookmarks and credentials are never
//! deleted, by any path.
//!
//! This is compiled code, not a rule file. It overrides every rule, exclusion
//! and tier, and is enforced at four independent points: build (rule fixtures),
//! scan (entries dropped), plan validation (plan rejected) and deletion
//! (re-checked on the open handle).
//!
//! Matching is deliberately broader than the spec's per-owner table (names are
//! matched at any depth, under any root): over-protecting costs a few bytes,
//! under-protecting costs a user's passwords.

use crate::path::{RelPath, fold, looks_like_short_name};

/// File-name prefixes (case-folded). The trailing `*` in the spec also covers
/// SQLite `-journal` / `-wal` siblings and `.bak` copies.
const NAME_PREFIXES: &[&str] = &[
    // Chromium: passwords, bookmarks, autofill, and the key that decrypts passwords.
    "login data",
    "bookmarks",
    "web data",
    "local state",
    // Firefox: passwords, their key, bookmarks.
    "logins.json",
    "logins-backup.json",
    "key4.db",
    "key3.db",
    "signons.sqlite",
    "places.sqlite",
];

/// Substrings of a file name that mark a password database (`*.kdbx`, `*.kdb`).
const NAME_CONTAINS: &[&str] = &[".kdbx", ".kdb"];

/// Any directory with one of these names protects everything beneath it.
const DIR_NAMES: &[&str] = &[
    "bookmarkbackups",
    "bitwarden",
    "1password",
    "keepassxc",
    "keepass",
];

/// Consecutive directory pairs that protect everything beneath them
/// (Credential Manager and DPAPI master keys, in Local and Roaming AppData).
const DIR_PAIRS: &[(&str, &str)] = &[
    ("microsoft", "protect"),
    ("microsoft", "credentials"),
    ("microsoft", "vault"),
];

/// Returns true if the path is protected. `components` are the components of
/// the full path (root components followed by the relative path), in any case.
pub fn is_protected<'a>(components: impl IntoIterator<Item = &'a str>) -> bool {
    let mut prev: Option<String> = None;
    for comp in components {
        if comp.is_empty() {
            continue;
        }
        // Fail closed: an unexpanded short name could hide a protected name.
        if looks_like_short_name(comp) {
            return true;
        }
        let c = fold(comp);
        if is_protected_name(&c) || DIR_NAMES.contains(&c.as_str()) {
            return true;
        }
        if let Some(p) = &prev
            && DIR_PAIRS.iter().any(|(a, b)| p == a && c == *b)
        {
            return true;
        }
        prev = Some(c);
    }
    false
}

/// Convenience: root components plus a relative path.
pub fn is_protected_under<'a>(
    root_components: impl IntoIterator<Item = &'a str>,
    rel: &'a RelPath,
) -> bool {
    rel.has_short_name() || is_protected(root_components.into_iter().chain(rel.components()))
}

fn is_protected_name(folded_name: &str) -> bool {
    NAME_PREFIXES.iter().any(|p| folded_name.starts_with(p))
        || NAME_CONTAINS.iter().any(|s| folded_name.contains(s))
}

/// Protected fixture paths planted under every rule root by the build-time
/// check. A rule that matches any of them fails the build.
pub fn fixture_paths() -> Vec<String> {
    const NAMES: &[&str] = &[
        "Login Data",
        "Login Data-journal",
        "Login Data For Account",
        "Login Data For Account-wal",
        "Bookmarks",
        "Bookmarks.bak",
        "Web Data",
        "Web Data-journal",
        "Local State",
        "logins.json",
        "logins-backup.json",
        "key4.db",
        "key3.db",
        "signons.sqlite",
        "places.sqlite",
        "places.sqlite-wal",
        "bookmarkbackups/bookmarks-2026-01-01.jsonlz4",
        "Vault.kdbx",
        "old.kdb",
        "Microsoft/Protect/S-1-5-21-1/masterkey",
        "Microsoft/Credentials/ABCDEF",
        "Microsoft/Vault/4BF4C442/policy.vpol",
        "Bitwarden/data.json",
        "1Password/data/1password.sqlite",
        "KeePassXC/keepassxc.ini",
    ];
    const PREFIXES: &[&str] = &[
        "",
        "Default/",
        "Profile 1/",
        "Guest Profile/",
        "abcd1234.default-release/",
    ];
    PREFIXES
        .iter()
        .flat_map(|p| NAMES.iter().map(move |n| format!("{p}{n}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prot(p: &str) -> bool {
        is_protected(p.split('/'))
    }

    #[test]
    fn chromium_files() {
        assert!(prot(
            "Users/x/AppData/Local/Google/Chrome/User Data/Default/Login Data"
        ));
        assert!(prot(
            "Chrome/User Data/Profile 3/Login Data For Account-journal"
        ));
        assert!(prot("Edge/User Data/Default/Bookmarks.bak"));
        assert!(prot("Brave/User Data/Default/Web Data-wal"));
        assert!(prot("Chrome/User Data/Local State"));
        assert!(prot("Chrome/User Data/Default/LOGIN DATA"));
    }

    #[test]
    fn firefox_files() {
        assert!(prot("Mozilla/Firefox/Profiles/x.default/logins.json"));
        assert!(prot("Mozilla/Firefox/Profiles/x.default/key4.db"));
        assert!(prot("Mozilla/Firefox/Profiles/x.default/places.sqlite-wal"));
        assert!(prot(
            "Mozilla/Firefox/Profiles/x.default/bookmarkbackups/b.jsonlz4"
        ));
        assert!(prot("Mozilla/Firefox/Profiles/x.default/signons.sqlite"));
    }

    #[test]
    fn windows_credentials() {
        assert!(prot("AppData/Roaming/Microsoft/Protect/S-1-5-21/abc"));
        assert!(prot("AppData/Local/Microsoft/Credentials/ABC"));
        assert!(prot("AppData/Local/Microsoft/Vault/x/y"));
        assert!(!prot("AppData/Local/Microsoft/Windows/INetCache/x"));
        // "protect" alone, not under Microsoft, is fine.
        assert!(!prot("AppData/Local/Temp/protect/x"));
    }

    #[test]
    fn password_managers() {
        assert!(prot("Documents/Passwords.kdbx"));
        assert!(prot("Temp/old.KDB"));
        assert!(prot("AppData/Roaming/Bitwarden/data.json"));
        assert!(prot("AppData/Local/1Password/x"));
        assert!(prot("AppData/Roaming/KeePassXC/x"));
    }

    #[test]
    fn short_names_fail_closed() {
        assert!(prot("Chrome/User Data/Default/LOGIND~1"));
        let rel = RelPath::parse("Default/LOGIND~1").unwrap();
        assert!(is_protected_under(["Chrome"], &rel));
    }

    #[test]
    fn ordinary_cache_files_are_not_protected() {
        assert!(!prot("Chrome/User Data/Default/Cache/Cache_Data/f_000001"));
        assert!(!prot("Chrome/User Data/Default/Code Cache/js/index"));
        assert!(!prot("Temp/~DF1234.tmp"));
        assert!(!prot("CrashDumps/app.exe.1234.dmp"));
    }

    #[test]
    fn every_fixture_is_protected() {
        for f in fixture_paths() {
            assert!(prot(&f), "fixture not protected: {f}");
        }
    }
}
