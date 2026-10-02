use super::*;
use crate::config::load_config;
use pixi_audit::IgnoreRule;

fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
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
    assert_eq!(
        load_config(&manifest).unwrap().rules,
        [IgnoreRule::from_id("CVE-9".into(), false)]
    );
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
