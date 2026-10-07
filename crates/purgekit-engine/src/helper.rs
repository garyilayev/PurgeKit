//! Protocol between the main app and the elevated helper.
//!
//! The helper receives rule IDs (command line) and narrowing-only data —
//! exclusions and the file IDs the user selected — over a pipe. It never
//! receives a path: it resolves and scans its rules' roots itself, keeps only
//! files whose IDs were selected, and deletes with the same handle-based
//! procedure as the main app.

use std::collections::HashSet;

use purgekit_core::CandidateId;
use purgekit_rules::{RuleIdx, RuleSet};
use serde::{Deserialize, Serialize};

use crate::backend::FsBackend;
use crate::cancel::CancelToken;
use crate::clean::{CleanOptions, CleanReport, clean};
use crate::exclusions::{Exclusion, Exclusions};
use crate::plan::CleanupPlan;
use crate::scan::{ScanOptions, scan};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperRequest {
    pub app_version: String,
    pub rules_version: String,
    pub rule_ids: Vec<String>,
    pub exclusions: Vec<Exclusion>,
    /// Selected file IDs. Only narrows: a file must also match a rule in the
    /// helper's own scan.
    pub allowed: Vec<CandidateId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelperResponse {
    Done(CleanReport),
    Refused(String),
}

/// Builds the request for the elevated part of a plan, or `None` if the plan
/// needs no elevation.
pub fn build_request(
    plan: &CleanupPlan,
    rules: &RuleSet,
    exclusions: &Exclusions,
) -> Option<HelperRequest> {
    let elevated = plan.elevated_rules(rules);
    if elevated.is_empty() {
        return None;
    }
    let mut ex = Vec::new();
    for &r in &elevated {
        ex.extend(exclusions.for_rule(rules.get(r)));
    }
    Some(HelperRequest {
        app_version: APP_VERSION.to_string(),
        rules_version: rules.version.clone(),
        rule_ids: elevated.iter().map(|&r| rules.get(r).id.clone()).collect(),
        exclusions: ex,
        allowed: plan
            .candidates()
            .iter()
            .filter(|c| elevated.contains(&c.rule))
            .map(|c| c.id)
            .collect(),
    })
}

/// Validates rule IDs from the command line. Only rules that need elevation
/// are accepted; anything unknown refuses the whole request.
pub fn parse_rule_ids(rules: &RuleSet, ids: &[String]) -> Result<Vec<RuleIdx>, String> {
    let mut out = Vec::new();
    for id in ids {
        let (idx, rule) = rules
            .find(id)
            .ok_or_else(|| format!("unknown rule id '{id}'"))?;
        if !rule.needs_elevation() {
            return Err(format!("rule '{id}' does not need elevation"));
        }
        out.push(idx);
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err("no rules".into());
    }
    Ok(out)
}

/// Runs a request inside the helper. `cmdline_rules` are the rule IDs from the
/// helper's command line; the pipe request must name the same rules.
pub fn execute(
    backend: &dyn FsBackend,
    rules: &RuleSet,
    cmdline_rules: &[String],
    req: &HelperRequest,
    cancel: &CancelToken,
) -> HelperResponse {
    if req.app_version != APP_VERSION {
        return HelperResponse::Refused(format!(
            "version mismatch: app {} helper {}",
            req.app_version, APP_VERSION
        ));
    }
    if req.rules_version != rules.version {
        return HelperResponse::Refused("rules version mismatch".into());
    }
    let idxs = match parse_rule_ids(rules, cmdline_rules) {
        Ok(i) => i,
        Err(e) => return HelperResponse::Refused(e),
    };
    let mut req_ids = req.rule_ids.clone();
    req_ids.sort();
    let mut cmd_ids: Vec<String> = idxs.iter().map(|&i| rules.get(i).id.clone()).collect();
    cmd_ids.sort();
    if req_ids != cmd_ids {
        return HelperResponse::Refused("request rules differ from command line".into());
    }

    // Keep only exclusions that concern these rules (they can only narrow anyway).
    let mut exclusions = Exclusions::default();
    for e in &req.exclusions {
        let relevant = idxs.iter().any(|&i| {
            let r = rules.get(i);
            match e {
                Exclusion::Category { category } => *category == r.category,
                Exclusion::Rule { rule_id } | Exclusion::Path { rule_id, .. } => *rule_id == r.id,
            }
        });
        if relevant {
            exclusions.add(e.clone());
        }
    }

    let result = scan(
        backend,
        &ScanOptions {
            rules,
            exclusions: &exclusions,
            only: Some(&idxs),
            threads: None,
        },
        cancel,
        &|_| {},
    );
    let allowed: HashSet<CandidateId> = req.allowed.iter().copied().collect();
    let plan = result.tree.plan_for_ids(rules, &allowed);
    let root_of = |r: RuleIdx| result.root_of(r);
    match clean(
        backend,
        &plan,
        &CleanOptions {
            rules,
            exclusions: &exclusions,
            root_of: &root_of,
            include_elevated: true,
        },
        cancel,
        &|_| {},
    ) {
        Ok(report) => HelperResponse::Done(report),
        Err(e) => HelperResponse::Refused(e.to_string()),
    }
}
