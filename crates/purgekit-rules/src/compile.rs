//! TOML schema and compilation into [`Rule`]s.
//!
//! This file is shared with `build.rs` (via `#[path]`), so every rule is
//! validated at build time and an invalid rule fails the build.

use std::collections::{BTreeMap, HashSet};

use purgekit_core::{
    AgeSpec, Category, DeleteMethod, Elevation, KnownFolder, RelPath, Target, Tier, protected,
};
use serde::Deserialize;

use crate::glob::Glob;
use crate::rule::{Detect, Mechanism, RootSpec, Rule};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default)]
    pub template: BTreeMap<String, TemplateDef>,
    pub rule: Option<RuleDef>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateDef {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    pub regenerates: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum DetectDef {
    Simple(String),
    Registry { registry_key: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub display_name: String,
    pub category: Category,
    pub what: String,
    pub why_safe: String,
    pub after_effects: String,
    pub detect: DetectDef,
    pub root: Option<String>,
    #[serde(default)]
    pub mechanism: Option<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    pub min_age: Option<String>,
    pub max_age: Option<String>,
    pub target: Target,
    pub tier: Tier,
    pub delete_method: Option<DeleteMethod>,
    pub elevation: Elevation,
    #[serde(default)]
    pub process_deps: Vec<String>,
    pub regenerates: Option<bool>,
    pub template: Option<String>,
    pub profile: Option<String>,
}

/// Compiles every source file. Returns all errors at once.
pub fn compile_sources(sources: &[(&str, &str)]) -> Result<Vec<Rule>, Vec<String>> {
    let mut errors = Vec::new();
    let mut templates: BTreeMap<String, TemplateDef> = BTreeMap::new();
    let mut defs: Vec<(String, RuleDef)> = Vec::new();

    for (name, text) in sources {
        match toml::from_str::<RuleFile>(text) {
            Ok(file) => {
                for (tname, t) in file.template {
                    if templates.insert(tname.clone(), t).is_some() {
                        errors.push(format!("{name}: template '{tname}' defined twice"));
                    }
                }
                if let Some(r) = file.rule {
                    defs.push((name.to_string(), r));
                }
            }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }

    let mut ids = HashSet::new();
    let mut rules = Vec::new();
    for (file, def) in defs {
        if !ids.insert(def.id.clone()) {
            errors.push(format!("{file}: duplicate rule id '{}'", def.id));
        }
        match compile_rule(&def, &templates) {
            Ok(rule) => {
                let mut errs = check_protected_fixtures(&rule);
                if errs.is_empty() {
                    rules.push(rule);
                } else {
                    errors.extend(errs.drain(..).map(|e| format!("{file}: {e}")));
                }
            }
            Err(errs) => errors.extend(errs.into_iter().map(|e| format!("{file}: {e}"))),
        }
    }

    if errors.is_empty() {
        rules.sort_by(|a, b| (a.category, &a.id).cmp(&(b.category, &b.id)));
        Ok(rules)
    } else {
        Err(errors)
    }
}

fn compile_rule(
    def: &RuleDef,
    templates: &BTreeMap<String, TemplateDef>,
) -> Result<Rule, Vec<String>> {
    let mut errors = Vec::new();
    let id = def.id.as_str();
    let mut err = |m: String| errors.push(format!("rule '{id}': {m}"));

    if !valid_id(id) {
        err(
            "id must look like 'app.part' (lowercase letters, digits, '_', '-', at least one '.')"
                .into(),
        );
    }
    for (field, value) in [
        ("display_name", &def.display_name),
        ("what", &def.what),
        ("why_safe", &def.why_safe),
        ("after_effects", &def.after_effects),
    ] {
        if value.trim().is_empty() {
            err(format!("'{field}' is required and must not be empty"));
        }
    }

    let template = match &def.template {
        Some(t) => match templates.get(t) {
            Some(t) => Some(t.clone()),
            None => {
                err(format!("unknown template '{t}'"));
                None
            }
        },
        None => None,
    };

    let mechanism = match def.mechanism.as_deref() {
        None | Some("files") => Mechanism::Files,
        Some("recycle_bin") => Mechanism::RecycleBin,
        Some(other) => {
            err(format!("unknown mechanism '{other}'"));
            Mechanism::Files
        }
    };

    let detect = match &def.detect {
        DetectDef::Simple(s) if s == "root_exists" => Detect::RootExists,
        DetectDef::Simple(s) if s == "always" => Detect::Always,
        DetectDef::Simple(s) => {
            err(format!(
                "unknown detect '{s}' (use \"root_exists\", \"always\" or {{ registry_key = ... }})"
            ));
            Detect::RootExists
        }
        DetectDef::Registry { registry_key } => Detect::RegistryKey(registry_key.clone()),
    };

    let root = match (&def.root, mechanism) {
        (Some(r), Mechanism::Files) => match parse_root(r) {
            Ok(root) => Some(root),
            Err(e) => {
                err(e);
                None
            }
        },
        (None, Mechanism::Files) => {
            err("'root' is required".into());
            None
        }
        (Some(_), _) => {
            err("'root' is not allowed for this mechanism".into());
            None
        }
        (None, _) => None,
    };

    // Merge template and rule globs, then expand {profile}.
    let mut include_src: Vec<String> = template.iter().flat_map(|t| t.include.clone()).collect();
    include_src.extend(def.include.iter().cloned());
    let mut exclude_src: Vec<String> = template.iter().flat_map(|t| t.exclude.clone()).collect();
    exclude_src.extend(def.exclude.iter().cloned());

    let compile_globs = |src: &[String], err: &mut dyn FnMut(String)| -> Vec<Glob> {
        src.iter()
            .filter_map(|p| match expand_profile(p, def.profile.as_deref()) {
                Ok(p) => match Glob::parse(&p) {
                    Ok(g) => Some(g),
                    Err(e) => {
                        err(e.to_string());
                        None
                    }
                },
                Err(e) => {
                    err(e);
                    None
                }
            })
            .collect()
    };
    let include = compile_globs(&include_src, &mut err);
    let exclude = compile_globs(&exclude_src, &mut err);

    match mechanism {
        Mechanism::Files if include.is_empty() && include_src.is_empty() => {
            err("'include' must list at least one pattern".into())
        }
        Mechanism::RecycleBin if !include_src.is_empty() || !exclude_src.is_empty() => {
            err("include/exclude are not allowed for the recycle_bin mechanism".into())
        }
        _ => {}
    }

    if def.target != Target::Files {
        err(
            "only target = \"files\" is supported; directories are only removed when emptied"
                .into(),
        );
    }

    let parse_age = |s: &Option<String>, field: &str, err: &mut dyn FnMut(String)| {
        s.as_ref().and_then(|v| {
            let a = AgeSpec::parse(v);
            if a.is_none() {
                err(format!(
                    "'{field}' must look like \"24h\", \"7d\" or \"30m\""
                ));
            }
            a
        })
    };
    let min_age = parse_age(&def.min_age, "min_age", &mut err);
    let max_age = parse_age(&def.max_age, "max_age", &mut err);
    if let (Some(lo), Some(hi)) = (min_age, max_age)
        && lo.secs > hi.secs
    {
        err("min_age is greater than max_age".into());
    }

    let derived = def.tier.default_delete_method();
    let delete_method = match def.delete_method {
        // Overrides may only move toward safer.
        Some(m) if m < derived => {
            err(format!(
                "delete_method may only be overridden toward safer ({derived:?} -> RecycleBin)"
            ));
            derived
        }
        Some(m) => m,
        None => derived,
    };

    if mechanism == Mechanism::Files && delete_method == DeleteMethod::RecycleBin {
        // The cleaner deletes through handles; per-file recycling (with the
        // Recycle Bin overflow check) arrives with REVIEW file rules in 0.2.
        err("recycle-bin deletion of individual files is not supported yet (0.2); file rules must delete permanently".into());
    }

    if def.elevation == Elevation::Required && def.tier != Tier::Advanced {
        err("rules that need elevation must be tier \"advanced\"".into());
    }

    let regenerates = def
        .regenerates
        .or(template.as_ref().and_then(|t| t.regenerates));
    if regenerates.is_none() {
        err("'regenerates' is required (in the rule or its template)".into());
    }

    let mut process_deps = Vec::new();
    for p in &def.process_deps {
        let p = p.to_lowercase();
        if !p.ends_with(".exe") || p.contains(['/', '\\']) {
            err(format!(
                "process_deps entry '{p}' must be a bare executable name"
            ));
        }
        process_deps.push(p);
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Rule {
        id: def.id.clone(),
        display_name: def.display_name.clone(),
        category: def.category,
        what: def.what.clone(),
        why_safe: def.why_safe.clone(),
        after_effects: def.after_effects.clone(),
        detect,
        mechanism,
        root,
        include,
        exclude,
        min_age,
        max_age,
        target: def.target,
        tier: def.tier,
        delete_method,
        elevation: def.elevation,
        process_deps,
        regenerates: regenerates.unwrap_or(false),
    })
}

fn valid_id(id: &str) -> bool {
    let ok_part = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    };
    id.contains('.') && id.split('.').all(ok_part)
}

/// `{Token}/rest/of/path` with a known-folder token.
pub fn parse_root(root: &str) -> Result<RootSpec, String> {
    let Some(rest) = root.strip_prefix('{') else {
        return Err(format!(
            "root '{root}' must start with a known-folder token like {{LocalAppData}}"
        ));
    };
    let Some((token, tail)) = rest.split_once('}') else {
        return Err(format!("root '{root}': unterminated token"));
    };
    let folder = KnownFolder::from_token(token)
        .ok_or_else(|| format!("root '{root}': unknown token '{{{token}}}'"))?;
    let tail = tail.strip_prefix('/').unwrap_or(tail);
    if tail.contains('\\') {
        return Err(format!("root '{root}': use '/' as the separator"));
    }
    if tail.contains(['*', '?', '{', '}']) {
        return Err(format!("root '{root}': wildcards are not allowed in roots"));
    }
    let rel = RelPath::parse(tail).map_err(|e| format!("root '{root}': {e}"))?;
    Ok(RootSpec { folder, rel })
}

/// Expands `{profile}`: `"*"` = any one profile directory, `"."` = the root
/// itself (Electron apps), anything else is a literal directory name.
fn expand_profile(pattern: &str, profile: Option<&str>) -> Result<String, String> {
    if !pattern.contains("{profile}") {
        return Ok(pattern.to_string());
    }
    match profile {
        None => Err(format!(
            "pattern '{pattern}' uses {{profile}} but the rule sets no 'profile'"
        )),
        Some(".") => Ok(pattern.replace("{profile}/", "").replace("{profile}", "")),
        Some(p) if p.contains(['/', '\\']) || p == ".." => {
            Err(format!("profile '{p}' must be a single component"))
        }
        Some(p) => Ok(pattern.replace("{profile}", p)),
    }
}

/// Build-time enforcement point 1: a rule may not match any protected fixture
/// planted under its root (age ignored, so age gates cannot hide a match).
fn check_protected_fixtures(rule: &Rule) -> Vec<String> {
    let mut errors = Vec::new();
    for f in protected::fixture_paths() {
        let rel = RelPath::parse(&f).expect("fixtures are valid paths");
        if rule.matches_path_raw(&rel, false) {
            errors.push(format!(
                "rule '{}' matches protected fixture '{f}'",
                rule.id
            ));
        }
    }
    errors
}
