//! The compiler rejects invalid rules (the same code runs in build.rs).

use purgekit_rules::compile::compile_sources;

const VALID: &str = r#"
[rule]
id = "test.rule"
display_name = "Test"
category = "apps"
root = "{LocalAppData}/Test"
include = ["Cache/**"]
detect = "root_exists"
target = "files"
tier = "safe"
elevation = "none"
regenerates = true
what = "w"
why_safe = "y"
after_effects = "a"
"#;

fn errs(src: &str) -> Vec<String> {
    compile_sources(&[("t.toml", src)])
        .err()
        .unwrap_or_default()
}

fn assert_rejected(src: &str, needle: &str) {
    let e = errs(src);
    assert!(
        e.iter().any(|m| m.contains(needle)),
        "expected error containing {needle:?}, got {e:?}"
    );
}

#[test]
fn valid_rule_compiles() {
    assert!(errs(VALID).is_empty());
}

#[test]
fn missing_transparency_string() {
    assert_rejected(
        &VALID.replace("why_safe = \"y\"", "why_safe = \"  \""),
        "why_safe",
    );
    assert_rejected(
        &VALID.replace("after_effects = \"a\"\n", ""),
        "after_effects",
    );
}

#[test]
fn unknown_field_is_rejected() {
    assert_rejected(
        &VALID.replace("[rule]", "[rule]\nestimated_recoverability = 1"),
        "unknown field",
    );
}

#[test]
fn root_must_use_known_folder() {
    assert_rejected(
        &VALID.replace("{LocalAppData}/Test", "C:/Users/x/Test"),
        "known-folder",
    );
    assert_rejected(
        &VALID.replace("{LocalAppData}/Test", "{Home}/Test"),
        "unknown token",
    );
    assert_rejected(
        &VALID.replace("{LocalAppData}/Test", "{LocalAppData}/../Test"),
        "..",
    );
    assert_rejected(
        &VALID.replace("{LocalAppData}/Test", "{LocalAppData}/*/Test"),
        "wildcards",
    );
}

#[test]
fn bad_globs() {
    assert_rejected(&VALID.replace("Cache/**", "../Cache/**"), "'..'");
    assert_rejected(&VALID.replace("Cache/**", "/Cache/**"), "relative");
    assert_rejected(
        &VALID.replace("include = [\"Cache/**\"]", "include = []"),
        "include",
    );
}

#[test]
fn delete_method_only_toward_safer() {
    let review = VALID.replace("tier = \"safe\"", "tier = \"review\"");
    assert_rejected(
        &review.replace("[rule]", "[rule]\ndelete_method = \"permanent\""),
        "safer",
    );
    // Safer override is allowed by the schema, but per-file recycling is not in 0.1.
    let safer = VALID.replace("[rule]", "[rule]\ndelete_method = \"recycle_bin\"");
    assert_rejected(&safer, "0.2");
}

#[test]
fn elevation_requires_advanced() {
    assert_rejected(
        &VALID.replace("elevation = \"none\"", "elevation = \"required\""),
        "advanced",
    );
}

#[test]
fn rule_matching_protected_data_fails() {
    assert_rejected(&VALID.replace("Cache/**", "**"), "protected fixture");
    assert_rejected(
        &VALID.replace("Cache/**", "*/Login Data"),
        "protected fixture",
    );
}

#[test]
fn duplicate_ids() {
    let e = compile_sources(&[("a.toml", VALID), ("b.toml", VALID)]).unwrap_err();
    assert!(e.iter().any(|m| m.contains("duplicate rule id")));
}

#[test]
fn bad_id() {
    assert_rejected(&VALID.replace("test.rule", "TestRule"), "id must");
}

#[test]
fn profile_token_requires_profile() {
    assert_rejected(&VALID.replace("Cache/**", "{profile}/Cache/**"), "profile");
}
