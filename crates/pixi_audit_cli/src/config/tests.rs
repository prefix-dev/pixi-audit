use super::*;
use pixi_audit::IgnoreScope;

fn write(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn rule(id: Option<&str>, scope: IgnoreScope, until_fixed: bool) -> IgnoreRule {
    IgnoreRule::new(id.map(str::to_string), scope, until_fixed).unwrap()
}

fn in_package(package: &str) -> IgnoreScope {
    IgnoreScope {
        package: Some(package.to_string()),
        ..IgnoreScope::default()
    }
}

#[test]
fn parses_full_table_from_pixi_toml() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        r#"
[workspace]
name = "demo"

[tool.pixi-audit]
ignore = ["CVE-1"]
ignore-until-fixed = ["CVE-2"]
fail-on = "high"
"#,
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(
        config.rules,
        [
            IgnoreRule::from_id("CVE-1".into(), false),
            IgnoreRule::from_id("CVE-2".into(), true),
        ]
    );
    assert_eq!(config.fail_on, Some(SeverityRating::High));
}

#[test]
fn accepts_toml_1_1_multiline_inline_tables() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        r#"
[workspace]
name = "demo"

[tasks]
insta-review = {
    cmd = "cargo insta review",
    depends-on = ["test"],
}

[tool.pixi-audit]
fail-on = "high"
"#,
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(config.fail_on, Some(SeverityRating::High));
}

#[test]
fn ignore_entries_accept_tables_with_reason_and_expired_at() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        r#"
[tool.pixi-audit]
ignore = [
    "CVE-1",
    { id = "CVE-2", reason = "test only", expired-at = 2999-01-01 },
    { id = "CVE-3", expired-at = "2999-06-01" },
]
ignore-until-fixed = [{ id = "CVE-4" }]
"#,
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(
        config.rules,
        [
            IgnoreRule::from_id("CVE-1".into(), false),
            IgnoreRule::from_id("CVE-2".into(), false),
            IgnoreRule::from_id("CVE-3".into(), false),
            IgnoreRule::from_id("CVE-4".into(), true),
        ]
    );
}

#[test]
fn id_and_package_entries_share_one_rule_list() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        r#"
[tool.pixi-audit]
ignore = [
    "CVE-1",
    { package = "vendored-thing", reason = "never runs" },
    { id = "CVE-2", package = "requests" },
]
ignore-until-fixed = [{ package = "libfoo", expired-at = 2999-01-01 }]
"#,
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(
        config.rules,
        vec![
            IgnoreRule::from_id("CVE-1".into(), false),
            rule(None, in_package("vendored-thing"), false),
            rule(Some("CVE-2"), in_package("requests"), false),
            rule(None, in_package("libfoo"), true),
        ]
    );
}

#[test]
fn scoped_id_entries_retain_ecosystem_and_version_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nignore = [{ id = \"CVE-1\", ecosystem = \"conda-forge\", version = \"1.13.1\", up-to-version = \"1.13.2\" }]\n",
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(
        config.rules,
        [rule(
            Some("CVE-1"),
            IgnoreScope {
                ecosystem: Some("conda-forge".to_string()),
                version: Some("1.13.1".to_string()),
                up_to_version: Some("1.13.2".to_string()),
                ..IgnoreScope::default()
            },
            false,
        )]
    );
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nignore = [{ id = \"CVE-1\", ecosystem = \"npm\" }]\n",
    );
    assert!(load_config(&manifest).is_err());
}

#[test]
fn ignore_unfixed_is_read_as_a_flag() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nignore-unfixed = true\n",
    );
    assert!(load_config(&manifest).unwrap().ignore_unfixed);
    let manifest = write(dir.path(), "pixi.toml", "[tool.pixi-audit]\n");
    assert!(!load_config(&manifest).unwrap().ignore_unfixed);
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nignore-unfixed = \"yes\"\n",
    );
    assert!(load_config(&manifest).is_err());
}

#[test]
fn expired_ignore_rules_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nignore = [{ id = \"CVE-1\", expired-at = 2000-01-01 }, \"CVE-2\"]\n",
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(config.rules, [IgnoreRule::from_id("CVE-2".into(), false)]);
}

#[test]
fn malformed_ignore_rules_are_errors() {
    let cases = [
        "ignore = [{ id = \"CVE-1\", expired-at = \"soon\" }]",
        "ignore = [{ id = \"CVE-1\", expired-at = 20260901 }]",
        "ignore = [{ id = \"CVE-1\", reasn = \"typo\" }]",
        "ignore = [{ id = \"CVE-1\", ecosystem = \"PyPI\", version = \"1.0\", up-to-version = \"2.0\", reasn = \"typo\" }]",
        "ignore = [{ id = \"CVE-1\", scope = { package = \"requests\" } }]",
        "ignore = [{ reason = \"neither id nor package\" }]",
    ];
    for table in cases {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write(
            dir.path(),
            "pixi.toml",
            &format!("[tool.pixi-audit]\n{table}\n"),
        );
        assert!(load_config(&manifest).is_err(), "{table}");
    }
}

#[test]
fn missing_table_yields_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(dir.path(), "pixi.toml", "[workspace]\nname = \"demo\"\n");
    let config = load_config(&manifest).unwrap();
    assert!(config.rules.is_empty());
    assert_eq!(config.fail_on, None);
}

#[test]
fn invalid_fail_on_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nfail-on = \"severe\"\n",
    );
    assert!(load_config(&manifest).is_err());
}

#[test]
fn wrong_type_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nignore = \"CVE-1\"\n",
    );
    assert!(load_config(&manifest).is_err());
}

#[test]
fn non_table_value_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(dir.path(), "pixi.toml", "[tool]\npixi-audit = 5\n");
    assert!(load_config(&manifest).is_err());
}

#[test]
fn unknown_keys_are_tolerated() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nignore = [\"CVE-1\"]\nfuture-option = true\n",
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(config.rules, [IgnoreRule::from_id("CVE-1".into(), false)]);
}

#[test]
fn unparsable_toml_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(dir.path(), "pixi.toml", "not toml [");
    assert!(load_config(&manifest).is_err());
}

#[test]
fn parse_rating_accepts_the_four_ratings_only() {
    assert_eq!(parse_rating("low").unwrap(), SeverityRating::Low);
    assert_eq!(parse_rating("medium").unwrap(), SeverityRating::Medium);
    assert_eq!(parse_rating("high").unwrap(), SeverityRating::High);
    assert_eq!(parse_rating("critical").unwrap(), SeverityRating::Critical);
    assert!(parse_rating("unknown").is_err());
    assert!(parse_rating("HIGH").is_err());
}
