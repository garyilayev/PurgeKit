//! Arena tree of cleanup results with tri-state selection.
//!
//! Layout: Root → Category → Cleaner (one per rule) → Directory → File.
//! Children of a node are contiguous in the arena and sorted by size, largest
//! first. Names are stored per node; paths are rebuilt on demand.
//!
//! Selection toggles are O(tree depth), never O(files): a toggle records an
//! explicit state with an epoch on the toggled node and pushes the size and
//! count delta up its ancestors. Descendants are resolved lazily — a node's
//! stored aggregate is valid unless an ancestor was set explicitly after it
//! was last updated, in which case the node is all-or-nothing.

use std::collections::HashMap;
use std::ops::Range;

use purgekit_core::{CandidateId, Category, FileId128, FileTime, RelPath, Selection, Tier};
use purgekit_rules::{RuleIdx, RuleSet};

use crate::exclusions::Exclusion;
use crate::plan::{CleanupPlan, PlanCandidate};

pub const NO_PARENT: u32 = u32::MAX;
pub const NO_RULE: RuleIdx = RuleIdx::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Root,
    Category,
    Cleaner,
    Directory,
    File,
}

#[derive(Debug, Clone)]
pub struct CleanupNode {
    pub parent: u32,
    pub children: Range<u32>,
    pub name: Box<str>,
    pub kind: NodeKind,
    pub rule: RuleIdx,
    pub category: Category,
    pub tier: Tier,
    pub total_logical: u64,
    pub total_alloc: u64,
    pub file_count: u32,
    pub modified: FileTime,
    pub file_id: Option<FileId128>,
    pub volume: u64,
    pub excluded: bool,
    sel_alloc: u64,
    sel_count: u32,
    explicit_epoch: u32,
    explicit_state: bool,
    agg_epoch: u32,
}

/// A scanned file before it is placed in the tree.
#[derive(Debug, Clone)]
pub struct FoundFile {
    pub rule: RuleIdx,
    pub volume: u64,
    pub file_id: FileId128,
    pub rel: RelPath,
    pub logical: u64,
    pub alloc: u64,
    pub modified: FileTime,
}

/// Input for one cleaner node.
#[derive(Debug, Clone)]
pub struct CleanerInput {
    pub rule: RuleIdx,
    pub files: Vec<FoundFile>,
    /// For non-file mechanisms (Recycle Bin): size and item count.
    pub virtual_size: Option<(u64, u64)>,
    /// Initially selected (tier default, and not blocked by a running app).
    pub selected: bool,
}

#[derive(Debug, Clone)]
pub struct ResultTree {
    nodes: Vec<CleanupNode>,
    epoch: u32,
}

struct Tmp {
    name: Box<str>,
    kind: NodeKind,
    rule: RuleIdx,
    category: Category,
    tier: Tier,
    children: Vec<usize>,
    index: HashMap<String, usize>,
    logical: u64,
    alloc: u64,
    count: u32,
    modified: FileTime,
    file_id: Option<FileId128>,
    volume: u64,
    explicit: Option<bool>,
}

impl Tmp {
    fn new(name: &str, kind: NodeKind, rule: RuleIdx, category: Category, tier: Tier) -> Self {
        Tmp {
            name: name.into(),
            kind,
            rule,
            category,
            tier,
            children: Vec::new(),
            index: HashMap::new(),
            logical: 0,
            alloc: 0,
            count: 0,
            modified: FileTime(0),
            file_id: None,
            volume: 0,
            explicit: None,
        }
    }
}

impl ResultTree {
    pub fn build(rules: &RuleSet, cleaners: Vec<CleanerInput>) -> Self {
        let mut tmp: Vec<Tmp> = vec![Tmp::new(
            "",
            NodeKind::Root,
            NO_RULE,
            Category::Windows,
            Tier::Safe,
        )];
        let mut cat_nodes: HashMap<Category, usize> = HashMap::new();
        let mut cleaners = cleaners;
        cleaners.sort_by_key(|c| (rules.get(c.rule).category, c.rule));

        for c in cleaners {
            if c.files.is_empty() && c.virtual_size.is_none_or(|(s, n)| s == 0 && n == 0) {
                continue;
            }
            let rule = rules.get(c.rule);
            let cat = *cat_nodes.entry(rule.category).or_insert_with(|| {
                tmp.push(Tmp::new(
                    rule.category.label(),
                    NodeKind::Category,
                    NO_RULE,
                    rule.category,
                    Tier::Safe,
                ));
                let i = tmp.len() - 1;
                tmp[0].children.push(i);
                i
            });
            tmp.push(Tmp::new(
                &rule.display_name,
                NodeKind::Cleaner,
                c.rule,
                rule.category,
                rule.tier,
            ));
            let cl = tmp.len() - 1;
            tmp[cat].children.push(cl);
            tmp[cl].explicit = Some(c.selected);
            if let Some((size, n)) = c.virtual_size {
                tmp[cl].logical = size;
                tmp[cl].alloc = size;
                tmp[cl].count = n.min(u32::MAX as u64) as u32;
            }
            for f in c.files {
                let mut cur = cl;
                let comps: Vec<&str> = f.rel.components().collect();
                let folded: Vec<&str> = f.rel.folded_components().collect();
                for (i, (name, key)) in comps.iter().zip(&folded).enumerate() {
                    let is_last = i + 1 == comps.len();
                    if let Some(&next) = tmp[cur].index.get(*key) {
                        cur = next;
                        continue;
                    }
                    let kind = if is_last {
                        NodeKind::File
                    } else {
                        NodeKind::Directory
                    };
                    tmp.push(Tmp::new(name, kind, c.rule, rule.category, rule.tier));
                    let n = tmp.len() - 1;
                    tmp[cur].children.push(n);
                    tmp[cur].index.insert((*key).to_string(), n);
                    cur = n;
                }
                let leaf = &mut tmp[cur];
                if leaf.kind == NodeKind::File && leaf.file_id.is_none() {
                    leaf.logical = f.logical;
                    leaf.alloc = f.alloc;
                    leaf.count = 1;
                    leaf.modified = f.modified;
                    leaf.file_id = Some(f.file_id);
                    leaf.volume = f.volume;
                }
            }
        }

        // Aggregate bottom-up (children always have larger indices than parents).
        for i in (0..tmp.len()).rev() {
            if tmp[i].children.is_empty() {
                continue;
            }
            let (mut l, mut a, mut n, mut m) = (0u64, 0u64, 0u32, FileTime(0));
            for &c in &tmp[i].children {
                l += tmp[c].logical;
                a += tmp[c].alloc;
                n = n.saturating_add(tmp[c].count);
                m = m.max(tmp[c].modified);
            }
            let t = &mut tmp[i];
            t.logical += l;
            t.alloc += a;
            t.count = t.count.saturating_add(n);
            t.modified = m;
        }

        // Sort children by size, largest first, then name.
        for i in 0..tmp.len() {
            let mut ch = std::mem::take(&mut tmp[i].children);
            if tmp[i].kind != NodeKind::Root {
                ch.sort_by(|&x, &y| {
                    tmp[y]
                        .logical
                        .cmp(&tmp[x].logical)
                        .then_with(|| tmp[x].name.cmp(&tmp[y].name))
                });
            }
            tmp[i].children = ch;
        }

        // Breadth-first layout so each node's children are contiguous.
        let mut order: Vec<usize> = vec![0];
        let mut new_index = vec![0u32; tmp.len()];
        let mut head = 0;
        while head < order.len() {
            let t = order[head];
            new_index[t] = head as u32;
            order.extend(tmp[t].children.iter().copied());
            head += 1;
        }
        let mut nodes: Vec<CleanupNode> = Vec::with_capacity(order.len());
        let mut parent_of = vec![NO_PARENT; tmp.len()];
        for &t in &order {
            for &c in &tmp[t].children {
                parent_of[c] = new_index[t];
            }
        }
        for &t in &order {
            let x = &tmp[t];
            let children = match (x.children.first(), x.children.last()) {
                (Some(&f), Some(&l)) => new_index[f]..new_index[l] + 1,
                _ => 0..0,
            };
            nodes.push(CleanupNode {
                parent: parent_of[t],
                children,
                name: x.name.clone(),
                kind: x.kind,
                rule: x.rule,
                category: x.category,
                tier: x.tier,
                total_logical: x.logical,
                total_alloc: x.alloc,
                file_count: x.count,
                modified: x.modified,
                file_id: x.file_id,
                volume: x.volume,
                excluded: false,
                sel_alloc: 0,
                sel_count: 0,
                explicit_epoch: if x.explicit.is_some() { 1 } else { 0 },
                explicit_state: x.explicit.unwrap_or(false),
                agg_epoch: 1,
            });
        }

        // Initial selection aggregates: cleaners carry the explicit default.
        for i in (0..nodes.len()).rev() {
            let n = &nodes[i];
            if n.kind == NodeKind::Cleaner {
                let s = n.explicit_state;
                let (a, c) = (n.total_alloc, n.file_count);
                set_all_below(&mut nodes, i, s);
                nodes[i].sel_alloc = if s { a } else { 0 };
                nodes[i].sel_count = if s { c } else { 0 };
            } else if matches!(n.kind, NodeKind::Root | NodeKind::Category) {
                let (mut a, mut c) = (0, 0u32);
                for ch in n.children.clone() {
                    a += nodes[ch as usize].sel_alloc;
                    c = c.saturating_add(nodes[ch as usize].sel_count);
                }
                nodes[i].sel_alloc = a;
                nodes[i].sel_count = c;
            }
        }

        ResultTree { nodes, epoch: 1 }
    }

    pub fn root(&self) -> u32 {
        0
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    pub fn node(&self, i: u32) -> &CleanupNode {
        &self.nodes[i as usize]
    }

    /// Visible children (excluded subtrees are hidden).
    pub fn children(&self, i: u32) -> impl Iterator<Item = u32> + '_ {
        self.nodes[i as usize]
            .children
            .clone()
            .filter(|&c| !self.nodes[c as usize].excluded)
    }

    /// Ancestors from the root down to (excluding) `i`.
    fn path_to(&self, i: u32) -> Vec<u32> {
        let mut path = Vec::new();
        let mut p = self.nodes[i as usize].parent;
        while p != NO_PARENT {
            path.push(p);
            p = self.nodes[p as usize].parent;
        }
        path.reverse();
        path
    }

    /// Latest explicit (epoch, state) among strict ancestors.
    fn inherited(&self, i: u32) -> Option<(u32, bool)> {
        let mut best: Option<(u32, bool)> = None;
        let mut p = self.nodes[i as usize].parent;
        while p != NO_PARENT {
            let n = &self.nodes[p as usize];
            if n.explicit_epoch > 0 && best.is_none_or(|(e, _)| n.explicit_epoch > e) {
                best = Some((n.explicit_epoch, n.explicit_state));
            }
            p = n.parent;
        }
        best
    }

    /// Selected (allocated bytes, file count) under `i`.
    pub fn selected(&self, i: u32) -> (u64, u32) {
        let n = &self.nodes[i as usize];
        if n.excluded {
            return (0, 0);
        }
        match self.inherited(i) {
            Some((e, s)) if e > n.agg_epoch => {
                if s {
                    (n.total_alloc, n.file_count)
                } else {
                    (0, 0)
                }
            }
            _ => (n.sel_alloc, n.sel_count),
        }
    }

    pub fn selection(&self, i: u32) -> Selection {
        let n = &self.nodes[i as usize];
        let (_, count) = self.selected(i);
        if count == 0 || n.file_count == 0 {
            Selection::Unchecked
        } else if count >= n.file_count {
            Selection::Checked
        } else {
            Selection::Partial
        }
    }

    /// Total selection: what "Clean X GB" means.
    pub fn selected_total(&self) -> (u64, u32) {
        self.selected(0)
    }

    /// Check or uncheck a node and everything below it. O(depth).
    pub fn set_selected(&mut self, i: u32, state: bool) {
        if self.nodes[i as usize].excluded || i == 0 && self.nodes.len() == 1 {
            return;
        }
        self.epoch += 1;
        let epoch = self.epoch;
        let path = self.path_to(i);
        // Materialize ancestors top-down so their stored aggregates are current.
        let mut inh: Option<(u32, bool)> = None;
        for &p in path.iter().chain(std::iter::once(&i)) {
            let n = &self.nodes[p as usize];
            if let Some((e, s)) = inh
                && e > n.agg_epoch
            {
                let (a, c) = if s {
                    (n.total_alloc, n.file_count)
                } else {
                    (0, 0)
                };
                let n = &mut self.nodes[p as usize];
                n.sel_alloc = a;
                n.sel_count = c;
            }
            let n = &mut self.nodes[p as usize];
            n.agg_epoch = epoch;
            if n.explicit_epoch > 0 && inh.is_none_or(|(e, _)| n.explicit_epoch > e) {
                inh = Some((n.explicit_epoch, n.explicit_state));
            }
        }
        let n = &mut self.nodes[i as usize];
        let (old_a, old_c) = (n.sel_alloc, n.sel_count);
        let (new_a, new_c) = if state {
            (n.total_alloc, n.file_count)
        } else {
            (0, 0)
        };
        n.sel_alloc = new_a;
        n.sel_count = new_c;
        n.explicit_epoch = epoch;
        n.explicit_state = state;
        for &p in &path {
            let a = &mut self.nodes[p as usize];
            a.sel_alloc = a.sel_alloc - old_a + new_a;
            a.sel_count = a.sel_count - old_c + new_c;
        }
    }

    /// Checked → unchecked; unchecked or partial → checked.
    pub fn toggle(&mut self, i: u32) {
        let checked = self.selection(i) == Selection::Checked;
        self.set_selected(i, !checked);
    }

    /// Hide a node and remove it from every total. Returns the exclusion to
    /// persist, or `None` for nodes that cannot be excluded.
    pub fn exclude(&mut self, i: u32, rules: &RuleSet) -> Option<Exclusion> {
        let n = &self.nodes[i as usize];
        if n.excluded {
            return None;
        }
        let excl = match n.kind {
            NodeKind::Root => return None,
            NodeKind::Category => Exclusion::Category {
                category: n.category,
            },
            NodeKind::Cleaner => Exclusion::Rule {
                rule_id: rules.get(n.rule).id.clone(),
            },
            NodeKind::Directory | NodeKind::File => Exclusion::Path {
                rule_id: rules.get(n.rule).id.clone(),
                rel_path: self.rel_path(i)?.as_str().to_string(),
                is_dir: n.kind == NodeKind::Directory,
            },
        };
        let (l, a, c) = (n.total_logical, n.total_alloc, n.file_count);
        self.set_selected(i, false);
        for p in self.path_to(i) {
            let x = &mut self.nodes[p as usize];
            x.total_logical -= l;
            x.total_alloc -= a;
            x.file_count -= c;
        }
        self.nodes[i as usize].excluded = true;
        Some(excl)
    }

    /// Root-relative path of a directory or file node (relative to its rule root).
    pub fn rel_path(&self, i: u32) -> Option<RelPath> {
        let mut names = Vec::new();
        let mut cur = i;
        loop {
            let n = &self.nodes[cur as usize];
            match n.kind {
                NodeKind::Directory | NodeKind::File => names.push(&*n.name),
                NodeKind::Cleaner => break,
                _ => return None,
            }
            cur = n.parent;
        }
        names.reverse();
        let mut p = RelPath::root();
        for name in names {
            p = p.join(name).ok()?;
        }
        Some(p)
    }

    /// Cleaner node index for any node at or below a cleaner.
    pub fn cleaner_of(&self, i: u32) -> Option<u32> {
        let mut cur = i;
        while cur != NO_PARENT {
            let n = &self.nodes[cur as usize];
            if n.kind == NodeKind::Cleaner {
                return Some(cur);
            }
            cur = n.parent;
        }
        None
    }

    /// Cleaner nodes in tree order.
    pub fn cleaners(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.nodes.len() as u32).filter(|&i| {
            self.nodes[i as usize].kind == NodeKind::Cleaner && !self.nodes[i as usize].excluded
        })
    }

    /// Freeze the current selection into an immutable plan.
    pub fn build_plan(&self, rules: &RuleSet) -> CleanupPlan {
        let mut candidates = Vec::new();
        let mut empty_recycle_bin = false;
        // Iterative DFS carrying the latest explicit (epoch, state).
        let mut stack: Vec<(u32, (u32, bool))> = vec![(0, (0, false))];
        while let Some((i, inh)) = stack.pop() {
            let n = &self.nodes[i as usize];
            if n.excluded {
                continue;
            }
            let inh = if n.explicit_epoch > inh.0 {
                (n.explicit_epoch, n.explicit_state)
            } else {
                inh
            };
            match n.kind {
                NodeKind::File => {
                    if inh.1
                        && let (Some(file_id), Some(rel)) = (n.file_id, self.rel_path(i))
                    {
                        let rule = rules.get(n.rule);
                        candidates.push(PlanCandidate {
                            id: CandidateId {
                                volume: n.volume,
                                file_id,
                            },
                            rel_path: rel,
                            rule: n.rule,
                            tier: rule.tier,
                            method: rule.delete_method,
                            alloc_size: n.total_alloc,
                        });
                    }
                }
                NodeKind::Cleaner if n.children.is_empty() => {
                    if inh.1
                        && rules.get(n.rule).mechanism == purgekit_rules::Mechanism::RecycleBin
                        && n.file_count > 0
                    {
                        empty_recycle_bin = true;
                    }
                }
                _ => {
                    for c in n.children.clone() {
                        stack.push((c, inh));
                    }
                }
            }
        }
        let recycle_bytes = if empty_recycle_bin {
            self.cleaners()
                .filter(|&c| {
                    rules.get(self.nodes[c as usize].rule).mechanism
                        == purgekit_rules::Mechanism::RecycleBin
                })
                .map(|c| self.nodes[c as usize].total_alloc)
                .sum()
        } else {
            0
        };
        CleanupPlan::new(
            rules.version.clone(),
            candidates,
            empty_recycle_bin,
            recycle_bytes,
        )
    }
}

impl ResultTree {
    /// Plan containing exactly the files whose IDs are in `allowed` (used by
    /// the elevated helper: file IDs can only narrow its own scan).
    pub fn plan_for_ids(
        &self,
        rules: &RuleSet,
        allowed: &std::collections::HashSet<CandidateId>,
    ) -> CleanupPlan {
        let mut candidates = Vec::new();
        for (i, n) in self.nodes.iter().enumerate() {
            if n.kind != NodeKind::File || n.excluded {
                continue;
            }
            let Some(file_id) = n.file_id else { continue };
            let id = CandidateId {
                volume: n.volume,
                file_id,
            };
            if !allowed.contains(&id) {
                continue;
            }
            if let Some(rel) = self.rel_path(i as u32) {
                let rule = rules.get(n.rule);
                candidates.push(PlanCandidate {
                    id,
                    rel_path: rel,
                    rule: n.rule,
                    tier: rule.tier,
                    method: rule.delete_method,
                    alloc_size: n.total_alloc,
                });
            }
        }
        CleanupPlan::new(rules.version.clone(), candidates, false, 0)
    }
}

fn set_all_below(nodes: &mut [CleanupNode], i: usize, state: bool) {
    let mut stack = vec![i];
    while let Some(x) = stack.pop() {
        for c in nodes[x].children.clone() {
            let n = &mut nodes[c as usize];
            n.sel_alloc = if state { n.total_alloc } else { 0 };
            n.sel_count = if state { n.file_count } else { 0 };
            stack.push(c as usize);
        }
    }
}
