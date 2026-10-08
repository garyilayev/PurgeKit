//! View model: turns the result tree into rows for Home and the Cleanup
//! Explorer. Pure logic (no Slint types) so it is testable.
//!
//! Only expanded paths are flattened, so the row count stays small no matter
//! how many files a scan finds. Folders with more than 1,000 children show the
//! 200 largest plus one aggregate row.

use std::collections::HashSet;

use purgekit_core::format::{format_bytes, format_count};
use purgekit_core::{Selection, Tier};
use purgekit_engine::ScanResult;
use purgekit_engine::tree::{NodeKind, ResultTree};
use purgekit_rules::RuleSet;

pub const AGGREGATE_ABOVE: usize = 1000;
pub const AGGREGATE_SHOW: usize = 200;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    /// Largest first (default).
    #[default]
    Size,
    Name,
    /// Newest first.
    Modified,
}

impl SortBy {
    pub fn from_index(i: i32) -> Self {
        match i {
            1 => SortBy::Name,
            2 => SortBy::Modified,
            _ => SortBy::Size,
        }
    }
}

#[derive(Debug, Default)]
pub struct Explorer {
    pub expanded: HashSet<u32>,
    pub query: String,
    pub current: Option<u32>,
    pub sort: SortBy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    Node { id: u32, depth: u32 },
    Aggregate { depth: u32, count: u64, bytes: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowData {
    pub node: i32,
    pub depth: i32,
    pub name: String,
    pub size: String,
    pub modified: String,
    /// Short label shown only when an item needs attention: its app is open,
    /// or its tier is not SAFE. Empty otherwise.
    pub badge: String,
    /// 0 neutral, 1 caution (REVIEW), 2 critical (ADVANCED).
    pub badge_tone: i32,
    pub check: i32,
    pub expandable: bool,
    pub expanded: bool,
    pub aggregate: bool,
    pub blocked: bool,
}

pub struct Ctx<'a> {
    pub result: &'a ScanResult,
    pub rules: &'a RuleSet,
    pub show_advanced: bool,
}

impl Ctx<'_> {
    fn tree(&self) -> &ResultTree {
        &self.result.tree
    }

    pub fn is_blocked(&self, i: u32) -> bool {
        let t = self.tree();
        t.cleaner_of(i)
            .and_then(|c| self.result.status(t.node(c).rule))
            .is_some_and(|s| !s.blocking.is_empty())
    }

    /// ADVANCED items are hidden unless "Show advanced items" is on.
    pub fn visible(&self, i: u32) -> bool {
        let n = self.tree().node(i);
        match n.kind {
            NodeKind::Root => true,
            NodeKind::Category => self.tree().children(i).any(|c| self.visible(c)),
            _ => self.show_advanced || n.tier != Tier::Advanced,
        }
    }

    fn visible_children(&self, i: u32) -> Vec<u32> {
        self.tree()
            .children(i)
            .filter(|&c| self.visible(c))
            .collect()
    }

    /// Cleaners a category checkbox controls: visible and not blocked.
    pub fn category_cleaners(&self, cat: u32) -> Vec<u32> {
        self.visible_children(cat)
            .into_iter()
            .filter(|&c| !self.is_blocked(c))
            .collect()
    }

    pub fn check_of(&self, i: u32) -> Selection {
        let t = self.tree();
        match t.node(i).kind {
            NodeKind::Category | NodeKind::Root => {
                let cl = self.category_cleaners(i);
                let states: Vec<Selection> = cl.iter().map(|&c| t.selection(c)).collect();
                if states.is_empty() || states.iter().all(|s| *s == Selection::Unchecked) {
                    Selection::Unchecked
                } else if states.iter().all(|s| *s == Selection::Checked) {
                    Selection::Checked
                } else {
                    Selection::Partial
                }
            }
            _ => t.selection(i),
        }
    }

    /// Recoverable bytes in a category, counting only what its checkbox controls.
    pub fn category_bytes(&self, cat: u32) -> u64 {
        self.category_cleaners(cat)
            .iter()
            .map(|&c| self.tree().node(c).total_alloc)
            .sum()
    }
}

/// Toggles a node. Category checkboxes act only on visible, unblocked
/// cleaners, so hidden ADVANCED items are never selected by accident.
pub fn toggle(result: &mut ScanResult, rules: &RuleSet, show_advanced: bool, i: u32) {
    let kind = result.tree.node(i).kind;
    if matches!(kind, NodeKind::Category | NodeKind::Root) {
        let (targets, check) = {
            let ctx = Ctx {
                result,
                rules,
                show_advanced,
            };
            (
                ctx.category_cleaners(i),
                ctx.check_of(i) != Selection::Checked,
            )
        };
        for c in targets {
            result.tree.set_selected(c, check);
        }
    } else {
        result.tree.toggle(i);
    }
}

fn check_code(s: Selection) -> i32 {
    match s {
        Selection::Unchecked => 0,
        Selection::Checked => 1,
        Selection::Partial => 2,
    }
}

/// Flattens the explorer rows.
pub fn flatten(ctx: &Ctx<'_>, ex: &Explorer) -> Vec<Row> {
    let t = ctx.tree();
    let q = ex.query.trim().to_lowercase();
    let mut rows = Vec::new();
    if q.is_empty() {
        push_children(ctx, ex, None, 0, 0, &mut rows);
        return rows;
    }
    // Search: mark matches and their ancestors. Never changes selection.
    let mut matched = vec![false; t.len()];
    let mut ancestor = vec![false; t.len()];
    for i in 1..t.len() as u32 {
        let n = t.node(i);
        if n.excluded || !ctx.visible(i) || !n.name.to_lowercase().contains(&q) {
            continue;
        }
        matched[i as usize] = true;
        let mut p = n.parent;
        while p != u32::MAX && !ancestor[p as usize] {
            ancestor[p as usize] = true;
            p = t.node(p).parent;
        }
    }
    push_children(ctx, ex, Some((&matched, &ancestor)), 0, 0, &mut rows);
    rows
}

type Marks<'a> = Option<(&'a [bool], &'a [bool])>;

fn push_children(
    ctx: &Ctx<'_>,
    ex: &Explorer,
    marks: Marks<'_>,
    parent: u32,
    depth: u32,
    rows: &mut Vec<Row>,
) {
    let t = ctx.tree();
    let parent_matched = marks.is_some_and(|(m, _)| m[parent as usize]);
    let kids: Vec<u32> = ctx
        .visible_children(parent)
        .into_iter()
        .filter(|&k| match marks {
            Some((m, a)) if !parent_matched => m[k as usize] || a[k as usize],
            _ => true,
        })
        .collect();
    // Children are stored largest first, so the aggregate keeps the 200 largest.
    let (shown, rest) = if kids.len() > AGGREGATE_ABOVE {
        kids.split_at(AGGREGATE_SHOW)
    } else {
        (&kids[..], &[][..])
    };
    let mut shown = shown.to_vec();
    match ex.sort {
        SortBy::Size => {}
        SortBy::Name => shown.sort_by_cached_key(|&k| t.node(k).name.to_lowercase()),
        SortBy::Modified => shown.sort_by_key(|&k| std::cmp::Reverse(t.node(k).modified)),
    }
    for k in shown {
        rows.push(Row::Node { id: k, depth });
        let auto = marks.is_some_and(|(_, a)| a[k as usize]);
        if auto || ex.expanded.contains(&k) {
            let child_marks = if parent_matched || marks.is_some_and(|(m, _)| m[k as usize]) {
                None
            } else {
                marks
            };
            push_children(ctx, ex, child_marks, k, depth + 1, rows);
        }
    }
    if !rest.is_empty() {
        let count = rest.iter().map(|&k| t.node(k).file_count as u64).sum();
        let bytes = rest.iter().map(|&k| t.node(k).total_logical).sum();
        rows.push(Row::Aggregate {
            depth,
            count,
            bytes,
        });
    }
}

pub fn row_data(
    ctx: &Ctx<'_>,
    ex: &Explorer,
    row: &Row,
    fmt_date: &dyn Fn(purgekit_core::FileTime) -> String,
) -> RowData {
    match row {
        Row::Aggregate {
            depth,
            count,
            bytes,
        } => RowData {
            node: -1,
            depth: *depth as i32,
            name: format!(
                "{} more files · {}",
                format_count(*count),
                format_bytes(*bytes)
            ),
            size: String::new(),
            modified: String::new(),
            badge: String::new(),
            badge_tone: 0,
            check: 0,
            expandable: false,
            expanded: false,
            aggregate: true,
            blocked: false,
        },
        Row::Node { id, depth } => {
            let t = ctx.tree();
            let n = t.node(*id);
            let expandable = !ctx.visible_children(*id).is_empty();
            let searching = !ex.query.trim().is_empty();
            let (badge, badge_tone) = if n.kind == NodeKind::Category {
                (String::new(), 0)
            } else if n.kind == NodeKind::Cleaner && ctx.is_blocked(*id) {
                ("App open".to_string(), 0)
            } else {
                match n.tier {
                    Tier::Safe => (String::new(), 0),
                    Tier::Review => (n.tier.label().to_string(), 1),
                    Tier::Advanced => (n.tier.label().to_string(), 2),
                }
            };
            RowData {
                node: *id as i32,
                depth: *depth as i32,
                name: n.name.to_string(),
                size: format_bytes(n.total_logical),
                modified: if n.modified.0 > 0 && n.kind != NodeKind::Category {
                    fmt_date(n.modified)
                } else {
                    String::new()
                },
                badge,
                badge_tone,
                check: check_code(ctx.check_of(*id)),
                expandable,
                expanded: expandable && (ex.expanded.contains(id) || searching),
                aggregate: false,
                blocked: ctx.is_blocked(*id),
            }
        }
    }
}

pub struct CategoryData {
    pub node: i32,
    pub name: String,
    /// What the category holds: "Chrome cache, Edge cache · 1,204 files".
    pub detail: String,
    pub size: String,
    pub check: i32,
    /// Why the checkbox is partial: "Not selected: Recycle Bin." Empty unless
    /// the category is partly selected.
    pub note: String,
}

/// A cleaner whose owning app is running, so nothing in it is selected.
pub struct BlockedData {
    pub app: String,
    pub size: String,
}

pub struct HomeData {
    pub headline: String,
    pub clean_label: String,
    pub can_clean: bool,
    pub selection_summary: String,
    pub categories: Vec<CategoryData>,
    pub blocked: Vec<BlockedData>,
    /// One line above the blocked list; empty when no app is open.
    pub blocked_summary: String,
    pub advanced_hint: String,
}

/// "Chrome cache" → "Chrome"; "Steam web cache" → "Steam".
pub fn app_name(display_name: &str) -> &str {
    display_name
        .strip_suffix(" web cache")
        .or_else(|| display_name.strip_suffix(" cache"))
        .unwrap_or(display_name)
}

/// Names the cleaners that keep a category checkbox partial. REVIEW and
/// ADVANCED items start unchecked, so this explains the partial state
/// right after a scan.
fn partial_note(ctx: &Ctx<'_>, cleaners: &[u32]) -> String {
    let t = ctx.tree();
    let names_with = |want: Selection| -> Vec<&str> {
        cleaners
            .iter()
            .filter(|&&c| t.selection(c) == want)
            .map(|&c| ctx.rules.get(t.node(c).rule).display_name.as_str())
            .collect()
    };
    let mut parts = Vec::new();
    let unchecked = names_with(Selection::Unchecked);
    if !unchecked.is_empty() {
        parts.push(format!("Not selected: {}.", unchecked.join(", ")));
    }
    let partial = names_with(Selection::Partial);
    if !partial.is_empty() {
        parts.push(format!("Partly selected: {}.", partial.join(", ")));
    }
    parts.join(" ")
}

pub fn home(ctx: &Ctx<'_>) -> HomeData {
    let t = ctx.tree();
    let (sel_bytes, sel_count) = t.selected_total();
    let mut categories = Vec::new();
    let mut blocked = Vec::new();
    let mut blocked_bytes = 0u64;
    let mut advanced_bytes = 0u64;
    for cat in t.children(0) {
        for c in t.children(cat) {
            let n = t.node(c);
            if n.tier == Tier::Advanced && !ctx.show_advanced {
                advanced_bytes += n.total_alloc;
            } else if ctx.is_blocked(c) {
                blocked_bytes += n.total_alloc;
                blocked.push(BlockedData {
                    app: app_name(&ctx.rules.get(n.rule).display_name).to_string(),
                    size: format_bytes(n.total_alloc),
                });
            }
        }
        let cleaners = ctx.category_cleaners(cat);
        if !ctx.visible(cat) || cleaners.is_empty() {
            continue;
        }
        let names: Vec<&str> = cleaners
            .iter()
            .map(|&c| ctx.rules.get(t.node(c).rule).display_name.as_str())
            .collect();
        let files: u64 = cleaners.iter().map(|&c| t.node(c).file_count as u64).sum();
        let check = ctx.check_of(cat);
        categories.push(CategoryData {
            node: cat as i32,
            name: t.node(cat).name.to_string(),
            detail: format!("{} · {} files", names.join(", "), format_count(files)),
            size: format_bytes(ctx.category_bytes(cat)),
            check: check_code(check),
            note: if check == Selection::Partial {
                partial_note(ctx, &cleaners)
            } else {
                String::new()
            },
        });
    }
    let blocked_summary = match blocked.len() {
        0 => String::new(),
        1 => format!(
            "{} is open. Close it to clean {} more.",
            blocked[0].app,
            format_bytes(blocked_bytes)
        ),
        n => format!(
            "{n} apps are open. Close them to clean {} more.",
            format_bytes(blocked_bytes)
        ),
    };
    let headline = if t.is_empty() {
        "No cleanable files found.".to_string()
    } else if sel_count == 0 {
        "Nothing is selected.".to_string()
    } else {
        format!("{} can be safely cleaned", format_bytes(sel_bytes))
    };
    let advanced_hint = if advanced_bytes > 0 {
        format!(
            "{} of advanced items are hidden. Turn on \"Show advanced items\" in Settings to review them.",
            format_bytes(advanced_bytes)
        )
    } else {
        String::new()
    };
    HomeData {
        headline,
        clean_label: format!("Clean {}", format_bytes(sel_bytes)),
        can_clean: sel_count > 0,
        selection_summary: format!(
            "{} · {} files selected",
            format_bytes(sel_bytes),
            format_count(sel_count as u64)
        ),
        categories,
        blocked,
        blocked_summary,
        advanced_hint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purgekit_core::{FileId128, FileTime, RelPath};
    use purgekit_engine::scan::{RuleStatus, ScanDiagnostics};
    use purgekit_engine::tree::{CleanerInput, FoundFile};
    use purgekit_rules::builtin;

    fn result(files: usize, blocked_chrome: bool) -> ScanResult {
        let rules = builtin();
        let (chrome, _) = rules.find("chrome.cache").unwrap();
        let (wt, _) = rules.find("windows.system_temp").unwrap();
        let mk = |rule, i: usize, p: String| FoundFile {
            rule,
            volume: 1,
            file_id: FileId128::from_u64(i as u64 + 1),
            rel: RelPath::parse(&p).unwrap(),
            logical: 1000 + i as u64,
            alloc: 4096,
            modified: FileTime(1),
        };
        let chrome_files = (0..files)
            .map(|i| mk(chrome, i, format!("Default/Cache/Cache_Data/f_{i:06}")))
            .collect();
        let wt_files = vec![mk(wt, 999_999, "old.log".into())];
        let tree = ResultTree::build(
            rules,
            vec![
                CleanerInput {
                    rule: chrome,
                    files: chrome_files,
                    virtual_size: None,
                    selected: !blocked_chrome,
                },
                CleanerInput {
                    rule: wt,
                    files: wt_files,
                    virtual_size: None,
                    selected: false,
                },
            ],
        );
        ScanResult {
            tree,
            rules_version: rules.version.clone(),
            started: FileTime(0),
            duration: Default::default(),
            partial: false,
            statuses: vec![RuleStatus {
                rule: chrome,
                root: None,
                present: true,
                blocking: if blocked_chrome {
                    vec!["chrome.exe".into()]
                } else {
                    vec![]
                },
            }],
            diagnostics: ScanDiagnostics::default(),
        }
    }

    #[test]
    fn large_folders_aggregate() {
        let r = result(1500, false);
        let ctx = Ctx {
            result: &r,
            rules: builtin(),
            show_advanced: false,
        };
        let mut ex = Explorer::default();
        // Expand everything down to Cache_Data.
        for i in 0..r.tree.len() as u32 {
            if r.tree.node(i).kind != NodeKind::File {
                ex.expanded.insert(i);
            }
        }
        let rows = flatten(&ctx, &ex);
        let files = rows
            .iter()
            .filter(|r| matches!(r, Row::Node { id, .. } if r_kind(&ctx, *id) == NodeKind::File))
            .count();
        assert_eq!(files, AGGREGATE_SHOW);
        assert!(
            rows.iter()
                .any(|r| matches!(r, Row::Aggregate { count: 1300, .. }))
        );
    }

    fn r_kind(ctx: &Ctx<'_>, id: u32) -> NodeKind {
        ctx.result.tree.node(id).kind
    }

    #[test]
    fn advanced_hidden_and_never_toggled_by_category() {
        let mut r = result(3, false);
        let rules = builtin();
        {
            let ctx = Ctx {
                result: &r,
                rules,
                show_advanced: false,
            };
            let rows = flatten(&ctx, &Explorer::default());
            // Windows category only has an ADVANCED cleaner: hidden entirely.
            assert!(rows.iter().all(|row| match row {
                Row::Node { id, .. } => r.tree.node(*id).name.as_ref() != "Windows",
                _ => true,
            }));
        }
        // Toggling the root-level categories never selects ADVANCED items.
        let cats: Vec<u32> = r.tree.children(0).collect();
        for c in cats {
            toggle(&mut r, rules, false, c);
            toggle(&mut r, rules, false, c);
        }
        let plan = r.tree.build_plan(rules);
        assert!(plan.elevated_rules(rules).is_empty());
    }

    #[test]
    fn search_filters_without_changing_selection() {
        let r = result(20, false);
        let ctx = Ctx {
            result: &r,
            rules: builtin(),
            show_advanced: false,
        };
        let before = r.tree.selected_total();
        let ex = Explorer {
            query: "f_000007".into(),
            ..Default::default()
        };
        let rows = flatten(&ctx, &ex);
        let names: Vec<String> = rows
            .iter()
            .filter_map(|row| match row {
                Row::Node { id, .. } => Some(r.tree.node(*id).name.to_string()),
                _ => None,
            })
            .collect();
        assert!(names.contains(&"f_000007".to_string()));
        assert!(!names.contains(&"f_000008".to_string()));
        assert_eq!(r.tree.selected_total(), before);
    }

    #[test]
    fn partial_category_names_what_is_not_selected() {
        let r = result(3, false);
        let rules = builtin();
        let home_with = |show_advanced| {
            home(&Ctx {
                result: &r,
                rules,
                show_advanced,
            })
        };
        // Chrome is fully selected: no note.
        let h = home_with(true);
        let browsers = h.categories.iter().find(|c| c.check == 1).unwrap();
        assert!(browsers.note.is_empty());
        // Windows has only the unchecked ADVANCED cleaner: unchecked, no note.
        let windows = h.categories.iter().find(|c| c.name == "Windows").unwrap();
        assert_eq!(windows.check, 0);
        assert!(windows.note.is_empty());

        // A partly selected cleaner and an unchecked one in the same category.
        let mut r = result(3, false);
        let (wt, _) = rules.find("windows.system_temp").unwrap();
        let (ut, _) = rules.find("windows.user_temp").unwrap();
        let mk = |rule, i: u64, p: &str| FoundFile {
            rule,
            volume: 1,
            file_id: FileId128::from_u64(5_000 + i),
            rel: RelPath::parse(p).unwrap(),
            logical: 10,
            alloc: 4096,
            modified: FileTime(1),
        };
        r.tree = ResultTree::build(
            rules,
            vec![
                CleanerInput {
                    rule: ut,
                    files: vec![mk(ut, 1, "a.tmp"), mk(ut, 2, "b.tmp")],
                    virtual_size: None,
                    selected: true,
                },
                CleanerInput {
                    rule: wt,
                    files: vec![mk(wt, 3, "old.log")],
                    virtual_size: None,
                    selected: false,
                },
            ],
        );
        let a_tmp = (0..r.tree.len() as u32)
            .find(|&i| r.tree.node(i).name.as_ref() == "a.tmp")
            .unwrap();
        r.tree.toggle(a_tmp);
        let h = home(&Ctx {
            result: &r,
            rules,
            show_advanced: true,
        });
        let windows = h.categories.iter().find(|c| c.name == "Windows").unwrap();
        assert_eq!(windows.check, 2);
        assert_eq!(
            windows.note,
            "Not selected: Windows temporary files. Partly selected: Temporary files."
        );
    }

    #[test]
    fn blocked_app_message() {
        let r = result(5, true);
        let ctx = Ctx {
            result: &r,
            rules: builtin(),
            show_advanced: false,
        };
        let h = home(&ctx);
        assert_eq!(h.blocked.len(), 1);
        assert_eq!(h.blocked[0].app, "Chrome");
        assert!(
            h.blocked_summary
                .starts_with("Chrome is open. Close it to clean")
        );
        assert!(!h.can_clean);
    }
}
