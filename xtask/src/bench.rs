//! Benchmark regression gate: `cargo run -p xtask -- bench-check`.
//!
//! Reads the Criterion results of the last `cargo bench` run
//! (`target/criterion/**/new/{benchmark,estimates}.json`) and compares each
//! benchmark's **median** with a stored baseline summary from `main`.
//!
//! A benchmark regresses when both hold:
//! 1. its median is more than `threshold` percent (default 10) slower than
//!    the baseline median, and
//! 2. the 95% confidence intervals of the two medians do not overlap
//!    (current lower bound above the baseline upper bound).
//!
//! Rule 2 keeps run-to-run noise on shared CI runners from failing a build
//! when the measurement itself cannot tell the two runs apart. The median is
//! used because it is robust to the occasional descheduled sample.
//!
//! Benchmarks listed in [`REFERENCE_ONLY`] (third-party baselines such as
//! jwalk) are reported but never gate. Absolute limits from the spec
//! ([`ABSOLUTE_LIMITS_NS`]) always apply, with or without a baseline.
//!
//! No baseline file (first run, expired cache) is not an error: the check
//! passes and, with `--save`, writes the current results as the new baseline.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

pub const DEFAULT_THRESHOLD_PCT: f64 = 10.0;
const SUMMARY_SCHEMA: u64 = 1;

/// Benchmarks that are reported but never fail the gate.
const REFERENCE_ONLY: &[&str] = &["jwalk_baseline"];

/// Spec "Performance targets": checkbox toggle to updated total < 16 ms
/// (one frame) on a 100k-node tree.
const ABSOLUTE_LIMITS_NS: &[(&str, f64)] = &[
    ("toggle_leaf_100k", 16_000_000.0),
    ("toggle_cleaner_100k", 16_000_000.0),
];

/// Median of one benchmark with its 95% confidence interval, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Median {
    pub point: f64,
    pub lower: f64,
    pub upper: f64,
}

pub type Results = BTreeMap<String, Median>;

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok,
    Improved,
    Regressed,
    /// Slower by more than the threshold, but the intervals overlap.
    Noisy,
    New,
    ReferenceOnly,
}

#[derive(Debug)]
pub struct Line {
    pub id: String,
    pub base: Option<Median>,
    pub cur: Median,
    pub verdict: Verdict,
}

fn is_reference(id: &str) -> bool {
    REFERENCE_ONLY
        .iter()
        .any(|r| id.rsplit('/').next() == Some(*r))
}

pub fn compare(base: Option<&Results>, cur: &Results, threshold_pct: f64) -> Vec<Line> {
    let factor = 1.0 + threshold_pct / 100.0;
    cur.iter()
        .map(|(id, &c)| {
            let b = base.and_then(|b| b.get(id)).copied();
            let verdict = match b {
                _ if is_reference(id) => Verdict::ReferenceOnly,
                None => Verdict::New,
                Some(b) if c.point > b.point * factor => {
                    if c.lower > b.upper {
                        Verdict::Regressed
                    } else {
                        Verdict::Noisy
                    }
                }
                Some(b) if c.point * factor < b.point && c.upper < b.lower => Verdict::Improved,
                Some(_) => Verdict::Ok,
            };
            Line {
                id: id.clone(),
                base: b,
                cur: c,
                verdict,
            }
        })
        .collect()
}

/// Absolute-limit failures as human-readable messages.
pub fn absolute_failures(cur: &Results) -> Vec<String> {
    ABSOLUTE_LIMITS_NS
        .iter()
        .filter_map(|(id, limit)| {
            let m = cur.get(*id)?;
            (m.point >= *limit).then(|| {
                format!(
                    "{id}: median {} is over the absolute limit {}",
                    fmt_ns(m.point),
                    fmt_ns(*limit)
                )
            })
        })
        .collect()
}

fn median_of(estimates: &Value) -> Option<Median> {
    let m = estimates.get("median")?;
    let ci = m.get("confidence_interval")?;
    Some(Median {
        point: m.get("point_estimate")?.as_f64()?,
        lower: ci.get("lower_bound")?.as_f64()?,
        upper: ci.get("upper_bound")?.as_f64()?,
    })
}

/// Collects `<dir>/**/new/` results produced by the last `cargo bench`.
pub fn collect_criterion(dir: &Path) -> Result<Results, String> {
    fn walk(dir: &Path, out: &mut Results) -> Result<(), String> {
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if path.file_name().is_some_and(|n| n == "new") {
                let read = |name: &str| -> Result<Value, String> {
                    let p = path.join(name);
                    let text = std::fs::read_to_string(&p)
                        .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
                    serde_json::from_str(&text)
                        .map_err(|e| format!("cannot parse {}: {e}", p.display()))
                };
                let bench = read("benchmark.json")?;
                let id = bench
                    .get("full_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{}: no full_id", path.display()))?
                    .to_string();
                let m = median_of(&read("estimates.json")?)
                    .ok_or_else(|| format!("{}: no median estimate", path.display()))?;
                out.insert(id, m);
            } else if path.file_name().is_some_and(|n| n != "report") {
                walk(&path, out)?;
            }
        }
        Ok(())
    }
    let mut out = Results::new();
    walk(dir, &mut out)?;
    Ok(out)
}

pub fn to_summary(r: &Results) -> Value {
    let benches: serde_json::Map<String, Value> = r
        .iter()
        .map(|(id, m)| {
            (
                id.clone(),
                json!({ "median_ns": m.point, "lower_ns": m.lower, "upper_ns": m.upper }),
            )
        })
        .collect();
    json!({ "schema_version": SUMMARY_SCHEMA, "benches": benches })
}

pub fn from_summary(v: &Value) -> Result<Results, String> {
    if v.get("schema_version").and_then(Value::as_u64) != Some(SUMMARY_SCHEMA) {
        return Err("unsupported baseline schema_version".into());
    }
    let benches = v
        .get("benches")
        .and_then(Value::as_object)
        .ok_or("baseline has no benches")?;
    benches
        .iter()
        .map(|(id, b)| {
            let f = |k: &str| {
                b.get(k)
                    .and_then(Value::as_f64)
                    .ok_or_else(|| format!("baseline {id}: missing {k}"))
            };
            Ok((
                id.clone(),
                Median {
                    point: f("median_ns")?,
                    lower: f("lower_ns")?,
                    upper: f("upper_ns")?,
                },
            ))
        })
        .collect()
}

fn fmt_ns(ns: f64) -> String {
    if ns >= 1e9 {
        format!("{:.3} s", ns / 1e9)
    } else if ns >= 1e6 {
        format!("{:.3} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.3} us", ns / 1e3)
    } else {
        format!("{ns:.1} ns")
    }
}

pub fn report(lines: &[Line]) -> String {
    let mut s = String::new();
    for l in lines {
        let change = l
            .base
            .map(|b| format!("{:+.1}%", (l.cur.point / b.point - 1.0) * 100.0))
            .unwrap_or_else(|| "-".into());
        let base = l
            .base
            .map(|b| fmt_ns(b.point))
            .unwrap_or_else(|| "-".into());
        let tag = match l.verdict {
            Verdict::Ok => "ok",
            Verdict::Improved => "improved",
            Verdict::Regressed => "REGRESSED",
            Verdict::Noisy => "noisy (CIs overlap, not gated)",
            Verdict::New => "new (no baseline)",
            Verdict::ReferenceOnly => "reference only",
        };
        let _ = writeln!(
            s,
            "{:<34} base {:>12}  now {:>12}  {:>8}  {tag}",
            l.id,
            base,
            fmt_ns(l.cur.point),
            change
        );
    }
    s
}

pub struct Args {
    pub criterion_dir: PathBuf,
    pub baseline: Option<PathBuf>,
    pub save: Option<PathBuf>,
    pub threshold_pct: f64,
}

pub fn parse_args(args: &[String], workspace: &Path) -> Result<Args, String> {
    let mut a = Args {
        criterion_dir: workspace.join("target").join("criterion"),
        baseline: None,
        save: None,
        threshold_pct: DEFAULT_THRESHOLD_PCT,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--criterion-dir" => a.criterion_dir = val()?.into(),
            "--baseline" => a.baseline = Some(val()?.into()),
            "--save" => a.save = Some(val()?.into()),
            "--threshold" => {
                a.threshold_pct = val()?.parse().map_err(|e| format!("--threshold: {e}"))?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(a)
}

/// Runs the gate. Returns `Ok(true)` when it passes.
pub fn run(a: &Args) -> Result<bool, String> {
    let cur = collect_criterion(&a.criterion_dir)?;
    if cur.is_empty() {
        return Err(format!(
            "no Criterion results under {}; run `cargo bench` first",
            a.criterion_dir.display()
        ));
    }
    let base = match &a.baseline {
        Some(p) if p.exists() => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("cannot parse {}: {e}", p.display()))?;
            Some(from_summary(&v)?)
        }
        Some(p) => {
            println!(
                "No baseline at {}: nothing to compare (first run). This run passes.",
                p.display()
            );
            None
        }
        None => None,
    };

    let lines = compare(base.as_ref(), &cur, a.threshold_pct);
    println!(
        "Benchmark medians (gate: > {}% slower and 95% CIs disjoint):",
        a.threshold_pct
    );
    print!("{}", report(&lines));

    let mut failures: Vec<String> = lines
        .iter()
        .filter(|l| l.verdict == Verdict::Regressed)
        .map(|l| format!("{}: regressed beyond {}%", l.id, a.threshold_pct))
        .collect();
    failures.extend(absolute_failures(&cur));
    for f in &failures {
        eprintln!("FAIL {f}");
    }
    let passed = failures.is_empty();

    if let Some(p) = a.save.as_ref().filter(|_| passed) {
        if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let text = serde_json::to_string_pretty(&to_summary(&cur)).expect("serializable");
        std::fs::write(p, text).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
        println!("Saved current results to {}", p.display());
    }
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(point: f64, spread: f64) -> Median {
        Median {
            point,
            lower: point - spread,
            upper: point + spread,
        }
    }

    fn results(items: &[(&str, Median)]) -> Results {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn no_baseline_is_new_and_passes() {
        let cur = results(&[("a", m(100.0, 1.0))]);
        let lines = compare(None, &cur, 10.0);
        assert_eq!(lines[0].verdict, Verdict::New);
    }

    #[test]
    fn small_change_is_ok() {
        let base = results(&[("a", m(100.0, 1.0))]);
        let cur = results(&[("a", m(109.0, 1.0))]);
        assert_eq!(compare(Some(&base), &cur, 10.0)[0].verdict, Verdict::Ok);
    }

    #[test]
    fn clear_regression_fails() {
        let base = results(&[("a", m(100.0, 1.0))]);
        let cur = results(&[("a", m(120.0, 1.0))]);
        assert_eq!(
            compare(Some(&base), &cur, 10.0)[0].verdict,
            Verdict::Regressed
        );
    }

    #[test]
    fn overlapping_intervals_are_noise() {
        let base = results(&[("a", m(100.0, 15.0))]);
        let cur = results(&[("a", m(120.0, 15.0))]);
        assert_eq!(compare(Some(&base), &cur, 10.0)[0].verdict, Verdict::Noisy);
    }

    #[test]
    fn reference_benchmarks_never_gate() {
        let base = results(&[("walk_200000/jwalk_baseline", m(100.0, 1.0))]);
        let cur = results(&[("walk_200000/jwalk_baseline", m(300.0, 1.0))]);
        assert_eq!(
            compare(Some(&base), &cur, 10.0)[0].verdict,
            Verdict::ReferenceOnly
        );
    }

    #[test]
    fn improvement_is_reported() {
        let base = results(&[("a", m(100.0, 1.0))]);
        let cur = results(&[("a", m(50.0, 1.0))]);
        assert_eq!(
            compare(Some(&base), &cur, 10.0)[0].verdict,
            Verdict::Improved
        );
    }

    #[test]
    fn absolute_limit_applies_without_baseline() {
        let cur = results(&[("toggle_leaf_100k", m(20_000_000.0, 1.0))]);
        assert_eq!(absolute_failures(&cur).len(), 1);
        let cur = results(&[("toggle_leaf_100k", m(2_000.0, 1.0))]);
        assert!(absolute_failures(&cur).is_empty());
    }

    #[test]
    fn summary_round_trips() {
        let cur = results(&[("a", m(100.0, 1.0)), ("g/b", m(5.0, 0.5))]);
        assert_eq!(from_summary(&to_summary(&cur)).unwrap(), cur);
    }

    #[test]
    fn collects_criterion_layout() {
        let dir = std::env::temp_dir().join(format!("xtask-bench-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let new = dir.join("walk_10").join("purgekit_walker").join("new");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(dir.join("report")).unwrap();
        std::fs::write(
            new.join("benchmark.json"),
            r#"{"full_id":"walk_10/purgekit_walker"}"#,
        )
        .unwrap();
        std::fs::write(
            new.join("estimates.json"),
            r#"{"median":{"confidence_interval":{"confidence_level":0.95,"lower_bound":9.0,"upper_bound":11.0},"point_estimate":10.0,"standard_error":0.1}}"#,
        )
        .unwrap();
        let r = collect_criterion(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r.len(), 1);
        assert_eq!(r["walk_10/purgekit_walker"], m(10.0, 1.0));
    }
}
