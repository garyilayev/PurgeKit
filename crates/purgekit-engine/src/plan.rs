//! `CleanupPlan`: a frozen snapshot of the final selection. The cleaner only
//! consumes plans, and every plan is validated before use.

use std::path::{Path, PathBuf};

use purgekit_core::{CandidateId, DeleteMethod, FileTime, RelPath, Tier, protected};
use purgekit_rules::{Mechanism, RuleIdx, RuleSet};

use crate::exclusions::Exclusions;

#[derive(Debug, Clone)]
pub struct PlanCandidate {
    pub id: CandidateId,
    pub rel_path: RelPath,
    pub rule: RuleIdx,
    pub tier: Tier,
    pub method: DeleteMethod,
    pub alloc_size: u64,
}

/// Immutable: fields are private and there are no mutating methods.
#[derive(Debug, Clone)]
pub struct CleanupPlan {
    plan_id: u64,
    created_at: FileTime,
    rules_version: String,
    candidates: Vec<PlanCandidate>,
    empty_recycle_bin: bool,
    recycle_bin_bytes: u64,
    total_alloc: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("plan was built with rules {plan}, but this build has rules {current}")]
    RulesVersion { plan: String, current: String },
    #[error("engine bug: protected file in plan (rule {rule_id})")]
    ProtectedInPlan { rule_id: String },
    #[error("engine bug: candidate outside its rule (rule {rule_id})")]
    OutsideRule { rule_id: String },
    #[error("engine bug: excluded candidate in plan (rule {rule_id})")]
    ExcludedInPlan { rule_id: String },
    #[error("engine bug: unknown rule index {0}")]
    UnknownRule(RuleIdx),
    #[error("engine bug: duplicate candidate in plan")]
    Duplicate,
}

impl CleanupPlan {
    pub(crate) fn new(
        rules_version: String,
        candidates: Vec<PlanCandidate>,
        empty_recycle_bin: bool,
        recycle_bin_bytes: u64,
    ) -> Self {
        let total_alloc = candidates.iter().map(|c| c.alloc_size).sum::<u64>() + recycle_bin_bytes;
        let created_at = FileTime::now();
        CleanupPlan {
            plan_id: created_at.0 ^ (candidates.len() as u64).rotate_left(32),
            created_at,
            rules_version,
            candidates,
            empty_recycle_bin,
            recycle_bin_bytes,
            total_alloc,
        }
    }

    pub fn plan_id(&self) -> u64 {
        self.plan_id
    }
    pub fn created_at(&self) -> FileTime {
        self.created_at
    }
    pub fn rules_version(&self) -> &str {
        &self.rules_version
    }
    pub fn candidates(&self) -> &[PlanCandidate] {
        &self.candidates
    }
    pub fn empty_recycle_bin(&self) -> bool {
        self.empty_recycle_bin
    }
    pub fn recycle_bin_bytes(&self) -> u64 {
        self.recycle_bin_bytes
    }
    /// Estimated recoverable bytes (allocated size).
    pub fn total_alloc(&self) -> u64 {
        self.total_alloc
    }
    pub fn file_count(&self) -> usize {
        self.candidates.len()
    }
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty() && !self.empty_recycle_bin
    }

    /// Rules in the plan that need the elevated helper.
    pub fn elevated_rules(&self, rules: &RuleSet) -> Vec<RuleIdx> {
        let mut v: Vec<RuleIdx> = self
            .candidates
            .iter()
            .map(|c| c.rule)
            .filter(|&r| rules.get(r).needs_elevation())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Enforcement point 3. Any protected, excluded or out-of-rule candidate
    /// rejects the whole plan: it can only get here through an engine bug.
    /// `roots` maps rule index to its resolved root path.
    pub fn validate(
        &self,
        rules: &RuleSet,
        exclusions: &Exclusions,
        root_of: &dyn Fn(RuleIdx) -> Option<PathBuf>,
    ) -> Result<(), PlanError> {
        if self.rules_version != rules.version {
            return Err(PlanError::RulesVersion {
                plan: self.rules_version.clone(),
                current: rules.version.clone(),
            });
        }
        let mut seen = std::collections::HashSet::with_capacity(self.candidates.len());
        for c in &self.candidates {
            if c.rule as usize >= rules.rules.len() {
                return Err(PlanError::UnknownRule(c.rule));
            }
            let rule = rules.get(c.rule);
            let rule_id = rule.id.clone();
            if !seen.insert(c.id) {
                return Err(PlanError::Duplicate);
            }
            let root = root_of(c.rule);
            let root_comps = root.as_deref().map(path_components).unwrap_or_default();
            if protected::is_protected_under(root_comps.iter().map(String::as_str), &c.rel_path) {
                return Err(PlanError::ProtectedInPlan { rule_id });
            }
            if rule.mechanism != Mechanism::Files
                || root.is_none()
                || !rule.matches_path(&c.rel_path, false)
            {
                return Err(PlanError::OutsideRule { rule_id });
            }
            if exclusions.excludes(rule, &c.rel_path) {
                return Err(PlanError::ExcludedInPlan { rule_id });
            }
        }
        Ok(())
    }
}

/// Normal components of an absolute path, for the protected check.
pub fn path_components(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}
