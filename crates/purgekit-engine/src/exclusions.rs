//! User exclusions: "never suggest again". They can only narrow what rules
//! match; there is no way to express a widening.

use purgekit_core::{Category, RelPath};
use purgekit_rules::Rule;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Exclusion {
    Category {
        category: Category,
    },
    Rule {
        rule_id: String,
    },
    /// A file or folder below a rule's root, root-relative with `/` separators.
    Path {
        rule_id: String,
        rel_path: String,
        is_dir: bool,
    },
}

impl Exclusion {
    pub fn describe(&self) -> String {
        match self {
            Exclusion::Category { category } => format!("All {} items", category.label()),
            Exclusion::Rule { rule_id } => {
                let name = purgekit_rules::builtin()
                    .find(rule_id)
                    .map(|(_, r)| r.display_name.as_str())
                    .unwrap_or(rule_id);
                format!("{name} (all items)")
            }
            Exclusion::Path {
                rule_id,
                rel_path,
                is_dir,
            } => {
                let name = purgekit_rules::builtin()
                    .find(rule_id)
                    .map(|(_, r)| r.display_name.as_str())
                    .unwrap_or(rule_id);
                let kind = if *is_dir { "folder" } else { "file" };
                format!("{name}: {kind} {}", rel_path.replace('/', "\\"))
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusions {
    pub items: Vec<Exclusion>,
}

impl Exclusions {
    pub fn add(&mut self, e: Exclusion) {
        if !self.items.contains(&e) {
            self.items.push(e);
        }
    }

    pub fn remove(&mut self, e: &Exclusion) {
        self.items.retain(|x| x != e);
    }

    /// Whole rule excluded (by rule or category).
    pub fn excludes_rule(&self, rule: &Rule) -> bool {
        self.items.iter().any(|e| match e {
            Exclusion::Category { category } => *category == rule.category,
            Exclusion::Rule { rule_id } => *rule_id == rule.id,
            Exclusion::Path { .. } => false,
        })
    }

    /// True if `rel` (file or directory) is excluded, either itself or
    /// because an ancestor folder is excluded.
    pub fn excludes(&self, rule: &Rule, rel: &RelPath) -> bool {
        if self.excludes_rule(rule) {
            return true;
        }
        let folded = rel.folded();
        self.items.iter().any(|e| match e {
            Exclusion::Path {
                rule_id,
                rel_path,
                is_dir,
            } if *rule_id == rule.id => {
                let Ok(p) = RelPath::parse(rel_path) else {
                    return false;
                };
                let p = p.folded();
                folded == p
                    || (*is_dir
                        && folded.len() > p.len()
                        && folded.starts_with(p)
                        && folded.as_bytes()[p.len()] == b'/')
            }
            _ => false,
        })
    }

    /// Exclusions that apply to one rule (sent to the elevated helper).
    pub fn for_rule(&self, rule: &Rule) -> Vec<Exclusion> {
        self.items
            .iter()
            .filter(|e| match e {
                Exclusion::Category { category } => *category == rule.category,
                Exclusion::Rule { rule_id } | Exclusion::Path { rule_id, .. } => {
                    *rule_id == rule.id
                }
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome() -> &'static Rule {
        purgekit_rules::builtin().find("chrome.cache").unwrap().1
    }

    #[test]
    fn folder_exclusion_covers_children_only_on_boundaries() {
        let mut ex = Exclusions::default();
        ex.add(Exclusion::Path {
            rule_id: "chrome.cache".into(),
            rel_path: "Default/Cache".into(),
            is_dir: true,
        });
        let r = chrome();
        assert!(ex.excludes(r, &RelPath::parse("Default/Cache").unwrap()));
        assert!(ex.excludes(r, &RelPath::parse("default/CACHE/Cache_Data/f_1").unwrap()));
        assert!(!ex.excludes(r, &RelPath::parse("Default/Cache2/x").unwrap()));
        assert!(!ex.excludes(r, &RelPath::parse("Default/Code Cache/x").unwrap()));
    }

    #[test]
    fn file_exclusion_is_exact() {
        let mut ex = Exclusions::default();
        ex.add(Exclusion::Path {
            rule_id: "chrome.cache".into(),
            rel_path: "Default/Cache/a".into(),
            is_dir: false,
        });
        assert!(ex.excludes(chrome(), &RelPath::parse("Default/Cache/a").unwrap()));
        assert!(!ex.excludes(chrome(), &RelPath::parse("Default/Cache/a/b").unwrap()));
    }

    #[test]
    fn other_rules_unaffected() {
        let mut ex = Exclusions::default();
        ex.add(Exclusion::Rule {
            rule_id: "edge.cache".into(),
        });
        assert!(!ex.excludes_rule(chrome()));
        ex.add(Exclusion::Category {
            category: Category::Browsers,
        });
        assert!(ex.excludes_rule(chrome()));
    }
}
