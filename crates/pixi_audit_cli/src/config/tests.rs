use super::*;

fn write(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
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
severity = "high"
"#,
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(config.ignore, vec!["CVE-1"]);
    assert_eq!(config.ignore_until_fixed, vec!["CVE-2"]);
    assert_eq!(config.severity, Some(SeverityBand::High));
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
severity = "high"
"#,
    );
    let config = load_config(&manifest).unwrap();
    assert_eq!(config.severity, Some(SeverityBand::High));
}

#[test]
fn missing_table_yields_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(dir.path(), "pixi.toml", "[workspace]\nname = \"demo\"\n");
    let config = load_config(&manifest).unwrap();
    assert!(config.ignore.is_empty());
    assert!(config.ignore_until_fixed.is_empty());
    assert_eq!(config.severity, None);
}

#[test]
fn invalid_severity_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(
        dir.path(),
        "pixi.toml",
        "[tool.pixi-audit]\nseverity = \"severe\"\n",
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
fn unparsable_toml_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write(dir.path(), "pixi.toml", "not toml [");
    assert!(load_config(&manifest).is_err());
}

#[test]
fn pyproject_with_tool_pixi_is_a_manifest() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "pyproject.toml",
        "[tool.pixi]\n[tool.pixi-audit]\nignore = [\"CVE-9\"]\n",
    );
    let manifest = find_manifest_in(dir.path()).unwrap().unwrap();
    assert!(manifest.ends_with("pyproject.toml"));
    assert_eq!(load_config(&manifest).unwrap().ignore, vec!["CVE-9"]);
}

#[test]
fn pyproject_without_tool_pixi_is_not_a_manifest() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "pyproject.toml", "[project]\nname = \"x\"\n");
    assert_eq!(find_manifest_in(dir.path()).unwrap(), None);
}

#[test]
fn unparsable_pyproject_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "pyproject.toml", "not toml [");
    assert!(find_manifest_in(dir.path()).is_err());
}

#[test]
fn pixi_toml_takes_precedence_over_pyproject() {
    for pyproject in ["[tool.pixi]\n", "not toml ["] {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pixi.toml", "[workspace]\n");
        write(dir.path(), "pyproject.toml", pyproject);
        assert!(
            find_manifest_in(dir.path())
                .unwrap()
                .unwrap()
                .ends_with("pixi.toml")
        );
    }
}

#[test]
fn discovery_walks_up_to_the_workspace_root() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "pixi.toml", "[workspace]\n");
    let nested = dir.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let manifest = discover_workspace(&nested).unwrap().unwrap();
    assert!(manifest.ends_with("pixi.toml"));
    assert_eq!(manifest.parent().unwrap(), dir.path());
}

#[test]
fn discovery_fails_outside_any_workspace() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(discover_workspace(dir.path()).unwrap(), None);
}

#[test]
fn discovery_errors_on_unparsable_pyproject_along_the_way() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "pyproject.toml", "not toml [");
    let nested = dir.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    assert!(discover_workspace(&nested).is_err());
}

#[test]
fn parse_band_accepts_the_four_bands_only() {
    assert_eq!(parse_band("low").unwrap(), SeverityBand::Low);
    assert_eq!(parse_band("medium").unwrap(), SeverityBand::Medium);
    assert_eq!(parse_band("high").unwrap(), SeverityBand::High);
    assert_eq!(parse_band("critical").unwrap(), SeverityBand::Critical);
    assert!(parse_band("unknown").is_err());
    assert!(parse_band("HIGH").is_err());
}
