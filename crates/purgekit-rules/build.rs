//! Validates every rule in `rules/` and embeds it in the binary.
//! An invalid rule, or a rule that matches a protected fixture, fails the build.

#[allow(dead_code)]
#[path = "src/compile.rs"]
mod compile;
#[allow(dead_code)]
#[path = "src/glob.rs"]
mod glob;
#[allow(dead_code)]
#[path = "src/rule.rs"]
mod rule;

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let rules_dir = manifest
        .join("../../rules")
        .canonicalize()
        .expect("rules/ directory exists");
    println!("cargo:rerun-if-changed={}", rules_dir.display());
    println!("cargo:rerun-if-changed=src/glob.rs");
    println!("cargo:rerun-if-changed=src/rule.rs");
    println!("cargo:rerun-if-changed=src/compile.rs");

    let mut files: Vec<PathBuf> = std::fs::read_dir(&rules_dir)
        .expect("read rules/")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();

    let mut owned = Vec::new();
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        owned.push((name, std::fs::read_to_string(f).expect("read rule file")));
    }
    let sources: Vec<(&str, &str)> = owned
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();

    if let Err(errors) = compile::compile_sources(&sources) {
        for e in &errors {
            println!("cargo:warning=rule error: {e}");
        }
        panic!("{} rule error(s):\n{}", errors.len(), errors.join("\n"));
    }

    let mut out = String::from("pub(crate) static RULE_SOURCES: &[(&str, &str)] = &[\n");
    for f in &files {
        let name = f.file_name().unwrap().to_string_lossy();
        out.push_str(&format!(
            "    ({name:?}, include_str!({:?})),\n",
            f.display().to_string()
        ));
    }
    out.push_str("];\n");
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("rules_gen.rs");
    std::fs::write(out_path, out).expect("write rules_gen.rs");
}
