# pixi-audit uv-parity Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add config-file support, `--ignore-until-fixed`, `--severity` threshold, `--fix` mode, and default lockfile discovery to the pixi-audit CLI.

**Architecture:** Categorization semantics (`--ignore-until-fixed`) go into the `pixi_audit` library via a new `IgnoreSpec` parameter and `Finding.ignore_reason` field. The CLI crate gains `config.rs` (workspace discovery + `[tool.pixi-audit]` parsing) and `fix.rs` (`pixi update` orchestration); `main.rs` grows the new flags and severity exit-gating; `render.rs` marks until-fixed ignores.

**Tech Stack:** Rust (edition 2024), clap 4, toml 0.8 (serde), tempfile 3 (tests), existing axum mock for integration tests.

**Spec:** `docs/superpowers/specs/2026-07-30-pixi-audit-uv-parity-design.md`

## Global Constraints

- Work on branch `feat/pixi-audit-uv-parity` (already checked out in this worktree; do not switch branches).
- Exit codes stay 0/1/2; clap usage errors already exit 2.
- The report is never filtered: `--severity` gates the exit code only; rendering and `--json` always show the full report.
- `Unknown` severity always counts as at-or-above any `--severity` threshold.
- `--ignore-until-fixed` suppression lifts when ANY fix is known (own-ecosystem OR upstream). `--ignore` wins when an id is in both lists.
- Ignore lists from config and CLI are unioned; CLI `--severity` overrides config `severity`.
- A present-but-invalid `[tool.pixi-audit]` table is an error (exit 2); a missing manifest/table is an empty config. Unrecognized keys in the table warn on stderr.
- `--fix` never edits the manifest; it only runs `pixi update` and re-audits.
- pixi.toml officially supports `[tool.*]` ("Third-party tool configurations, ignored by pixi"), so `[tool.pixi-audit]` is valid in both manifest kinds.
- Every task ends with `cargo test --workspace`-relevant tests passing and no clippy/fmt violations; run `cargo fmt --all` before each commit.
- Commit messages end with: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
- Run all commands from the worktree root `/Users/graf/oss/pixi-audit/.claude/worktrees/uv-parity`.

---

### Task 1: `IgnoreSpec` + `ignore_reason` in the `pixi_audit` library

**Files:**
- Modify: `crates/pixi_audit/src/report.rs` (audit signature, Finding, categorization, tests)
- Modify: `crates/pixi_audit/src/lock.rs` (audit_lock_file signature + its tests)
- Modify: `crates/pixi_audit/src/lib.rs` (re-exports)
- Modify: `crates/pixi_audit/examples/audit_lockfile.rs` (call site)
- Modify: `crates/pixi_audit_cli/src/main.rs` (call site only — new flags come in Task 3)

**Interfaces:**
- Produces (later tasks rely on these exact names):
  ```rust
  // pixi_audit::report
  #[derive(Debug, Default, Clone, Copy)]
  pub struct IgnoreSpec<'a> {
      pub ignore: &'a [String],
      pub ignore_until_fixed: &'a [String],
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
  #[serde(rename_all = "kebab-case")]
  pub enum IgnoreReason { Always, UntilFixed }

  // Finding gains:
  #[serde(skip_serializing_if = "Option::is_none")]
  pub ignore_reason: Option<IgnoreReason>,

  pub async fn audit(client: &BasiliskClient, packages: Vec<AuditPackage>, ignore: IgnoreSpec<'_>) -> Result<AuditReport, AuditError>
  // pixi_audit::lock
  pub async fn audit_lock_file(client: &BasiliskClient, lock_file: &LockFile, environment_filter: &[String], platform_filter: &[String], ignore: IgnoreSpec<'_>) -> Result<AuditReport, LockFileAuditError>
  ```
  `lib.rs` re-exports `IgnoreSpec` and `IgnoreReason` alongside the existing report types.

- [ ] **Step 1: Write the failing tests**

In `crates/pixi_audit/src/report.rs`'s `#[cfg(test)] mod tests`, add a no-fix vulnerability doc helper and the categorization tests. The existing `vuln_doc()` (BSLK-1) HAS a fix (`3.1.1`), which is exactly what the fix-known case needs:

```rust
    /// Like `vuln_doc`, but with no fixed events anywhere (id BSLK-NOFIX).
    fn vuln_doc_nofix() -> serde_json::Value {
        serde_json::json!({
            "id": "BSLK-NOFIX",
            "aliases": ["CVE-2026-7777"],
            "summary": "No fix yet",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{
                "package": {"ecosystem": "conda-forge", "name": "openssl"},
                "versions": ["3.1.0"]
            }]
        })
    }

    /// Mock server serving `doc` for every openssl query.
    async fn spawn_mock_serving(doc: serde_json::Value) -> Url {
        let vuln_id = doc["id"].as_str().unwrap().to_string();
        let doc_for_get = doc.clone();
        let app = Router::new()
            .route(
                "/v1/querybatch",
                post(move |Json(body): Json<serde_json::Value>| {
                    let vuln_id = vuln_id.clone();
                    async move {
                        let results: Vec<serde_json::Value> = body["queries"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|q| {
                                if q["package"]["name"] == "openssl" {
                                    serde_json::json!({"vulns": [{"id": vuln_id}]})
                                } else {
                                    serde_json::json!({})
                                }
                            })
                            .collect();
                        Json(serde_json::json!({"results": results}))
                    }
                }),
            )
            .route(
                "/v1/vulns/{id}",
                get(move || {
                    let doc = doc_for_get.clone();
                    async move { Json(doc) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Url::parse(&format!("http://{addr}/")).unwrap()
    }

    fn ignore_until_fixed(ids: &[String]) -> IgnoreSpec<'_> {
        IgnoreSpec {
            ignore: &[],
            ignore_until_fixed: ids,
        }
    }

    #[tokio::test]
    async fn until_fixed_with_no_known_fix_is_ignored_with_reason() {
        let base = spawn_mock_serving(vuln_doc_nofix()).await;
        let ids = vec!["BSLK-NOFIX".to_string()];
        let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
            .await
            .unwrap();
        assert!(report.vulnerabilities.is_empty());
        assert_eq!(report.ignored.len(), 1);
        assert_eq!(
            report.ignored[0].ignore_reason,
            Some(IgnoreReason::UntilFixed)
        );
        // The JSON field serializes kebab-case.
        let json = serde_json::to_value(&report.ignored[0]).unwrap();
        assert_eq!(json["ignore_reason"], "until-fixed");
    }

    #[tokio::test]
    async fn until_fixed_with_known_fix_stays_vulnerable() {
        // BSLK-1 has fixed 3.1.1, so suppression does not apply.
        let base = spawn_mock().await;
        let ids = vec!["BSLK-1".to_string()];
        let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
            .await
            .unwrap();
        assert_eq!(report.vulnerabilities.len(), 1);
        assert!(report.ignored.is_empty());
        assert_eq!(report.vulnerabilities[0].ignore_reason, None);
    }

    #[tokio::test]
    async fn until_fixed_matches_aliases_case_insensitively() {
        let base = spawn_mock_serving(vuln_doc_nofix()).await;
        let ids = vec!["cve-2026-7777".to_string()];
        let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
            .await
            .unwrap();
        assert_eq!(report.ignored.len(), 1);
    }

    #[tokio::test]
    async fn ignore_wins_over_until_fixed() {
        // BSLK-1 has a fix; plain ignore still suppresses it, reason Always.
        let base = spawn_mock().await;
        let ignore = vec!["BSLK-1".to_string()];
        let until = vec!["BSLK-1".to_string()];
        let spec = IgnoreSpec {
            ignore: &ignore,
            ignore_until_fixed: &until,
        };
        let report = audit(&test_client(base), packages(), spec).await.unwrap();
        assert!(report.vulnerabilities.is_empty());
        assert_eq!(report.ignored.len(), 1);
        assert_eq!(report.ignored[0].ignore_reason, Some(IgnoreReason::Always));
    }

    #[tokio::test]
    async fn plain_ignored_findings_carry_reason_always_and_it_serializes() {
        let base = spawn_mock().await;
        let ignore = vec!["BSLK-1".to_string()];
        let spec = IgnoreSpec {
            ignore: &ignore,
            ignore_until_fixed: &[],
        };
        let report = audit(&test_client(base), packages(), spec).await.unwrap();
        assert_eq!(report.ignored[0].ignore_reason, Some(IgnoreReason::Always));
        let json = serde_json::to_value(&report.ignored[0]).unwrap();
        assert_eq!(json["ignore_reason"], "always");
        // Vulnerable findings must NOT carry the key at all.
        let base2 = spawn_mock().await;
        let clean = audit(&test_client(base2), packages(), IgnoreSpec::default())
            .await
            .unwrap();
        let vuln_json = serde_json::to_value(&clean.vulnerabilities[0]).unwrap();
        assert!(vuln_json.get("ignore_reason").is_none());
    }
```

Existing tests that call `audit(..., &[...])` change to the new signature:
- `audit_reports_findings_and_unchecked`: `audit(&test_client(base), packages(), IgnoreSpec::default())`
- `ignored_findings_are_sorted_like_vulnerabilities`: `IgnoreSpec { ignore: &["BSLK-1".to_string()], ignore_until_fixed: &[] }` (bind the vec to a variable first so the reference lives long enough)
- `ignore_list_matches_id_and_aliases_case_insensitively`: same pattern with `["cve-2026-1234".to_string()]`
- any other `audit(`/`audit_lock_file(` test call sites in `report.rs` and `lock.rs`: replace the final `&[]` ignore argument with `IgnoreSpec::default()`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pixi_audit 2>&1 | tail -20`
Expected: compile errors (IgnoreSpec/IgnoreReason not defined) — that is the failing state for a signature change.

- [ ] **Step 3: Implement**

In `crates/pixi_audit/src/report.rs`:

1. Add above `Finding`:

```rust
/// Which suppression list put a finding into the ignored bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IgnoreReason {
    /// Listed in the unconditional ignore list.
    Always,
    /// Listed in the ignore-until-fixed list and no fix is known yet. The
    /// finding resurfaces once any fixed version (own ecosystem or
    /// upstream) is published.
    UntilFixed,
}

/// Suppression lists applied during an audit. Ids/aliases match
/// case-insensitively; `ignore` wins when an id appears in both lists.
#[derive(Debug, Default, Clone, Copy)]
pub struct IgnoreSpec<'a> {
    /// Always suppress these vulnerability ids/aliases.
    pub ignore: &'a [String],
    /// Suppress these only while no fixed release is known.
    pub ignore_until_fixed: &'a [String],
}
```

2. Add to `Finding` (after `url`):

```rust
    /// Set only on findings in the ignored bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_reason: Option<IgnoreReason>,
```

and update the `Finding { ... }` construction in `audit()` to include `ignore_reason: None,`.

3. Change `audit`'s signature and categorization. Replace

```rust
pub async fn audit(
    client: &BasiliskClient,
    packages: Vec<AuditPackage>,
    ignore: &[String],
) -> Result<AuditReport, AuditError> {
```

with

```rust
pub async fn audit(
    client: &BasiliskClient,
    packages: Vec<AuditPackage>,
    ignore: IgnoreSpec<'_>,
) -> Result<AuditReport, AuditError> {
```

replace the single `ignore_set` construction with:

```rust
    let ignore_set: BTreeSet<String> = ignore.ignore.iter().map(|s| s.to_lowercase()).collect();
    let until_fixed_set: BTreeSet<String> = ignore
        .ignore_until_fixed
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
```

and replace the `is_ignored` block:

```rust
            let matches = |set: &BTreeSet<String>| {
                set.contains(&finding.id.to_lowercase())
                    || finding
                        .aliases
                        .iter()
                        .any(|a| set.contains(&a.to_lowercase()))
            };
            let has_known_fix =
                !finding.fixed_versions.is_empty() || !finding.upstream_fixed_versions.is_empty();
            let reason = if matches(&ignore_set) {
                Some(IgnoreReason::Always)
            } else if matches(&until_fixed_set) && !has_known_fix {
                Some(IgnoreReason::UntilFixed)
            } else {
                None
            };
            match reason {
                Some(reason) => {
                    let mut finding = finding;
                    finding.ignore_reason = Some(reason);
                    report.ignored.push(finding);
                }
                None => report.vulnerabilities.push(finding),
            }
```

(`finding` is currently immutable — bind it `let mut finding = finding;` only inside the `Some` arm as shown, or make the original binding mutable; either is fine as long as clippy is clean.)

4. In `crates/pixi_audit/src/lock.rs`, change:

```rust
pub async fn audit_lock_file(
    client: &BasiliskClient,
    lock_file: &LockFile,
    environment_filter: &[String],
    platform_filter: &[String],
    ignore: IgnoreSpec<'_>,
) -> Result<AuditReport, LockFileAuditError> {
    let packages = collect_packages(lock_file, environment_filter, platform_filter)?;
    Ok(audit(client, packages, ignore).await?)
}
```

with `use crate::report::IgnoreSpec;` added to the imports.

5. In `crates/pixi_audit/src/lib.rs`, extend the report re-export line to include the new types:

```rust
pub use report::{
    AuditPackage, AuditReport, AuditSummary, Finding, IgnoreReason, IgnoreSpec, PackageEcosystem,
    SeverityBand, UncheckedPackage, audit,
};
```

6. Update the two remaining call sites so the workspace compiles:
- `crates/pixi_audit/examples/audit_lockfile.rs`: `audit_lock_file(&client, &lock_file, &[], &[], pixi_audit::IgnoreSpec::default()).await?`
- `crates/pixi_audit_cli/src/main.rs` `run()`:

```rust
    audit_lock_file(
        &client,
        &lock_file,
        &cli.environments,
        &cli.platforms,
        pixi_audit::IgnoreSpec {
            ignore: &cli.ignore,
            ignore_until_fixed: &[],
        },
    )
    .await
    .map_err(miette::Report::new)
```

- `crates/pixi_audit_cli/src/render.rs`: the test helper `finding()` gains `ignore_reason: None,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: all pass (5 new library tests included).

- [ ] **Step 5: Commit**

```bash
git add crates/pixi_audit crates/pixi_audit_cli
git commit -m "feat: IgnoreSpec with ignore-until-fixed semantics and Finding.ignore_reason"
```

---

### Task 2: `config.rs` — workspace discovery and `[tool.pixi-audit]`

**Files:**
- Modify: `Cargo.toml` (workspace deps: add `tempfile = "3"` and `toml = "0.8"`, alphabetically ordered)
- Modify: `crates/pixi_audit_cli/Cargo.toml` (add `toml = { workspace = true }` to `[dependencies]`, `tempfile = { workspace = true }` to `[dev-dependencies]`)
- Create: `crates/pixi_audit_cli/src/config.rs`
- Modify: `crates/pixi_audit_cli/src/main.rs` (add `mod config;` only; reference it so no dead-code warning: not needed — the module's tests reference everything; add `#[allow(dead_code)]` NEVER — instead mark items `pub` and add `mod config;`; if a dead-code warning remains in this intermediate state, add a `let _ = ...;` in `main()` and remove it in Task 3)

**Interfaces:**
- Consumes: `pixi_audit::SeverityBand`.
- Produces (Task 3/5 rely on these exact names):

```rust
pub struct AuditConfig {
    pub ignore: Vec<String>,
    pub ignore_until_fixed: Vec<String>,
    pub severity: Option<SeverityBand>,
}
/// Walk up from `start` to the first dir with a workspace manifest.
pub fn discover_workspace(start: &Path) -> Option<PathBuf>;   // returns manifest path
/// pixi.toml, or pyproject.toml containing [tool.pixi], in `dir`.
pub fn find_manifest_in(dir: &Path) -> Option<PathBuf>;
/// Parse [tool.pixi-audit] from the manifest. Missing table => defaults.
pub fn load_config(manifest: &Path) -> miette::Result<AuditConfig>;
/// "low"|"medium"|"high"|"critical" => SeverityBand (used by clap too).
pub fn parse_band(s: &str) -> Result<SeverityBand, String>;
```

- [ ] **Step 1: Write the failing tests**

Create `crates/pixi_audit_cli/src/config.rs` with the API stubbed as `todo!()` bodies and this test module:

```rust
#[cfg(test)]
mod tests {
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
        let manifest = write(dir.path(), "pixi.toml", "[tool.pixi-audit]\nignore = \"CVE-1\"\n");
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
        write(dir.path(), "pyproject.toml", "[tool.pixi]\n[tool.pixi-audit]\nignore = [\"CVE-9\"]\n");
        let manifest = find_manifest_in(dir.path()).unwrap();
        assert!(manifest.ends_with("pyproject.toml"));
        assert_eq!(load_config(&manifest).unwrap().ignore, vec!["CVE-9"]);
    }

    #[test]
    fn pyproject_without_tool_pixi_is_not_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pyproject.toml", "[project]\nname = \"x\"\n");
        assert_eq!(find_manifest_in(dir.path()), None);
    }

    #[test]
    fn pixi_toml_wins_over_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pixi.toml", "[workspace]\n");
        write(dir.path(), "pyproject.toml", "[tool.pixi]\n");
        assert!(find_manifest_in(dir.path()).unwrap().ends_with("pixi.toml"));
    }

    #[test]
    fn discovery_walks_up_to_the_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pixi.toml", "[workspace]\n");
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let manifest = discover_workspace(&nested).unwrap();
        assert!(manifest.ends_with("pixi.toml"));
        assert_eq!(manifest.parent().unwrap(), dir.path());
    }

    #[test]
    fn discovery_fails_outside_any_workspace() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(discover_workspace(dir.path()), None);
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
}
```

Add `mod config;` to `main.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pixi_audit_cli config 2>&1 | tail -5`
Expected: panics at `todo!()` (or compile errors until the stubs exist — write the stubs first, then confirm test failures).

- [ ] **Step 3: Implement**

`crates/pixi_audit_cli/src/config.rs` (replacing the stubs; keep the test module):

```rust
//! Workspace manifest discovery and `[tool.pixi-audit]` configuration.

use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic, miette};
use pixi_audit::SeverityBand;

/// Persistent audit configuration from `[tool.pixi-audit]`.
#[derive(Debug, Default, PartialEq)]
pub struct AuditConfig {
    pub ignore: Vec<String>,
    pub ignore_until_fixed: Vec<String>,
    pub severity: Option<SeverityBand>,
}

const KNOWN_KEYS: &[&str] = &["ignore", "ignore-until-fixed", "severity"];

/// The workspace manifest in `dir`: `pixi.toml`, or `pyproject.toml` that
/// contains a `[tool.pixi]` table.
pub fn find_manifest_in(dir: &Path) -> Option<PathBuf> {
    let pixi = dir.join("pixi.toml");
    if pixi.is_file() {
        return Some(pixi);
    }
    let pyproject = dir.join("pyproject.toml");
    if pyproject.is_file()
        && let Ok(content) = std::fs::read_to_string(&pyproject)
        && let Ok(value) = content.parse::<toml::Value>()
        && value.get("tool").and_then(|t| t.get("pixi")).is_some()
    {
        return Some(pyproject);
    }
    None
}

/// Walks up from `start` to the first directory containing a workspace
/// manifest and returns the manifest path.
pub fn discover_workspace(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if let Some(manifest) = find_manifest_in(current) {
            return Some(manifest);
        }
        dir = current.parent();
    }
    None
}

/// Parses `[tool.pixi-audit]` from `manifest`. A missing table is an empty
/// config; a present-but-invalid table is an error — a security tool must
/// not silently drop configured suppressions. Unknown keys warn on stderr.
pub fn load_config(manifest: &Path) -> miette::Result<AuditConfig> {
    let content = std::fs::read_to_string(manifest)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read '{}'", manifest.display()))?;
    let value: toml::Value = content
        .parse()
        .into_diagnostic()
        .wrap_err_with(|| format!("'{}' is not valid TOML", manifest.display()))?;

    let Some(table) = value
        .get("tool")
        .and_then(|t| t.get("pixi-audit"))
    else {
        return Ok(AuditConfig::default());
    };
    let table = table.as_table().ok_or_else(|| {
        miette!("[tool.pixi-audit] in '{}' must be a table", manifest.display())
    })?;

    for key in table.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            eprintln!(
                "warning: unrecognized key '{key}' in [tool.pixi-audit] of '{}'",
                manifest.display()
            );
        }
    }

    let string_list = |key: &str| -> miette::Result<Vec<String>> {
        match table.get(key) {
            None => Ok(Vec::new()),
            Some(value) => value
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| {
                    miette!(
                        "'{key}' in [tool.pixi-audit] of '{}' must be an array of strings",
                        manifest.display()
                    )
                }),
        }
    };

    let severity = match table.get("severity") {
        None => None,
        Some(value) => {
            let text = value.as_str().ok_or_else(|| {
                miette!(
                    "'severity' in [tool.pixi-audit] of '{}' must be a string",
                    manifest.display()
                )
            })?;
            Some(parse_band(text).map_err(|err| {
                miette!("invalid severity in [tool.pixi-audit] of '{}': {err}", manifest.display())
            })?)
        }
    };

    Ok(AuditConfig {
        ignore: string_list("ignore")?,
        ignore_until_fixed: string_list("ignore-until-fixed")?,
        severity,
    })
}

/// Parses a severity band name. Shared by clap's value parser and the
/// config file, so both accept exactly the same values.
pub fn parse_band(s: &str) -> Result<SeverityBand, String> {
    match s {
        "low" => Ok(SeverityBand::Low),
        "medium" => Ok(SeverityBand::Medium),
        "high" => Ok(SeverityBand::High),
        "critical" => Ok(SeverityBand::Critical),
        other => Err(format!(
            "'{other}' is not a severity band (expected low, medium, high, or critical)"
        )),
    }
}
```

Workspace `Cargo.toml` `[workspace.dependencies]` additions (alphabetical):

```toml
tempfile = "3"
toml = "0.8"
```

`crates/pixi_audit_cli/Cargo.toml`: add `toml = { workspace = true }` under `[dependencies]` and `tempfile = { workspace = true }` under `[dev-dependencies]`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p pixi_audit_cli && cargo clippy -p pixi_audit_cli --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 11 new config tests pass; note a `dead_code` warning is possible for unused pub items in this intermediate state — if clippy flags it, silence by referencing `config::discover_workspace` etc. is NOT needed: items in a private module used only by tests DO warn. Add temporarily to `main()`:

```rust
    let _ = (
        config::discover_workspace,
        config::load_config,
        config::parse_band,
        config::find_manifest_in,
    );
```

and remove it in Task 3 when the real call sites land.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/pixi_audit_cli
git commit -m "feat: [tool.pixi-audit] config parsing and workspace discovery"
```

---

### Task 3: Wire flags, discovery, config merge, and severity gating into `main.rs`

**Files:**
- Modify: `crates/pixi_audit_cli/src/main.rs`

**Interfaces:**
- Consumes: Task 1's `IgnoreSpec`, Task 2's `config::{discover_workspace, find_manifest_in, load_config, parse_band, AuditConfig}`.
- Produces (Task 5 relies on): `struct ResolvedTargets { lockfile: PathBuf, manifest: Option<PathBuf> }` and `fn resolve_targets(cli_lockfile: Option<PathBuf>) -> miette::Result<ResolvedTargets>`; `fn gate_exit(report: &AuditReport, threshold: Option<SeverityBand>) -> bool` (true = should exit 1); the `Cli` struct gaining `ignore_until_fixed: Vec<String>`, `severity: Option<SeverityBand>`, `fix: bool`.

- [ ] **Step 1: Write the failing tests**

Add to `main.rs`'s test module:

```rust
    #[test]
    fn lockfile_is_now_optional() {
        assert!(Cli::try_parse_from(["pixi-audit"]).is_ok());
    }

    #[test]
    fn new_flags_parse() {
        let cli = Cli::try_parse_from([
            "pixi-audit",
            "pixi.lock",
            "--ignore-until-fixed",
            "CVE-1",
            "--severity",
            "high",
            "--fix",
        ])
        .unwrap();
        assert_eq!(cli.ignore_until_fixed, vec!["CVE-1"]);
        assert_eq!(cli.severity, Some(SeverityBand::High));
        assert!(cli.fix);
    }

    #[test]
    fn invalid_severity_is_rejected_at_parse_time() {
        assert!(Cli::try_parse_from(["pixi-audit", "pixi.lock", "--severity", "severe"]).is_err());
    }

    #[test]
    fn gate_exit_applies_threshold_with_unknown_failsafe() {
        let finding = |severity| pixi_audit::Finding {
            package: "p".into(),
            version: "1".into(),
            ecosystem: "conda-forge".into(),
            environments: vec![],
            id: "X".into(),
            aliases: vec![],
            severity,
            fixed_versions: vec![],
            upstream_fixed_versions: vec![],
            summary: None,
            url: None,
            ignore_reason: None,
        };
        let report = |severity| AuditReport {
            vulnerabilities: vec![finding(severity)],
            summary: pixi_audit::AuditSummary {
                vulnerable: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        // No threshold: any vulnerability fails.
        assert!(gate_exit(&report(SeverityBand::Low), None));
        // Threshold high: medium passes, high and critical fail.
        assert!(!gate_exit(&report(SeverityBand::Medium), Some(SeverityBand::High)));
        assert!(gate_exit(&report(SeverityBand::High), Some(SeverityBand::High)));
        assert!(gate_exit(&report(SeverityBand::Critical), Some(SeverityBand::High)));
        // Unknown always fails, even against critical.
        assert!(gate_exit(&report(SeverityBand::Unknown), Some(SeverityBand::Critical)));
        // Clean report never fails.
        assert!(!gate_exit(&AuditReport::default(), Some(SeverityBand::Low)));
        assert!(!gate_exit(&AuditReport::default(), None));
    }
```

(`use pixi_audit::{AuditReport, SeverityBand};` as needed in the test module.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pixi_audit_cli 2>&1 | tail -5`
Expected: compile errors (new Cli fields, `gate_exit` missing). Note `lockfile_is_required` must be DELETED (replaced by `lockfile_is_now_optional`), and the existing `repeatable_flags_accumulate` assertion changes to `assert_eq!(cli.lockfile, Some(PathBuf::from("pixi.lock")));`.

- [ ] **Step 3: Implement**

Changes to `main.rs`:

1. `Cli` struct — `lockfile` becomes optional, three new flags:

```rust
    /// Path to the pixi.lock file to audit. When omitted, searches the
    /// current directory and its parents for a pixi workspace.
    lockfile: Option<PathBuf>,
```

and after the `ignore` field:

```rust
    /// Vulnerability id or alias to ignore only while no fixed release is
    /// known (repeatable, case-insensitive). Resurfaces once a fix exists.
    #[arg(long = "ignore-until-fixed", value_name = "ID")]
    ignore_until_fixed: Vec<String>,

    /// Fail (exit 1) only for findings at or above this severity band.
    /// Findings with unknown severity always fail. Overrides the config
    /// file's `severity`.
    #[arg(long, value_name = "BAND", value_parser = config::parse_band)]
    severity: Option<SeverityBand>,

    /// Re-lock vulnerable packages via `pixi update`, then re-audit
    #[arg(long)]
    fix: bool,
```

with `use pixi_audit::SeverityBand;` added to imports. Remove the Task 2 placeholder `let _ = (...)` line.

2. Target resolution:

```rust
/// The lockfile to audit and the workspace manifest that governs it.
struct ResolvedTargets {
    lockfile: PathBuf,
    /// `None` when an explicit lockfile has no manifest beside it.
    manifest: Option<PathBuf>,
}

/// An explicit lockfile is used as-is (manifest = its sibling, if any).
/// Otherwise the workspace is discovered by walking up from the cwd.
fn resolve_targets(cli_lockfile: Option<PathBuf>) -> miette::Result<ResolvedTargets> {
    match cli_lockfile {
        Some(lockfile) => {
            let manifest = lockfile
                .canonicalize()
                .ok()
                .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
                .and_then(|dir| config::find_manifest_in(&dir));
            Ok(ResolvedTargets { lockfile, manifest })
        }
        None => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot determine the current directory")?;
            let manifest = config::discover_workspace(&cwd).ok_or_else(|| {
                miette::miette!(
                    "no pixi workspace found; pass a lockfile path or run inside a pixi workspace"
                )
            })?;
            let root = manifest.parent().expect("manifest has a directory");
            let lockfile = root.join("pixi.lock");
            if !lockfile.is_file() {
                return Err(miette::miette!(
                    "workspace at '{}' has no pixi.lock; run `pixi lock` first",
                    root.display()
                ));
            }
            Ok(ResolvedTargets {
                lockfile,
                manifest: Some(manifest),
            })
        }
    }
}
```

3. Severity gating:

```rust
/// Whether the report should fail the audit (exit 1) under `threshold`.
/// Unknown severity always fails: an unscored advisory must not slip
/// under a threshold.
fn gate_exit(report: &AuditReport, threshold: Option<SeverityBand>) -> bool {
    report.vulnerabilities.iter().any(|finding| match threshold {
        None => true,
        Some(band) => {
            finding.severity == SeverityBand::Unknown || finding.severity >= band
        }
    })
}
```

4. `run()` reshaped (config merge + resolved targets; keep the HTTP client construction unchanged). Replace the current `run` with:

```rust
struct RunOutcome {
    report: AuditReport,
    threshold: Option<SeverityBand>,
}

async fn run(cli: Cli) -> miette::Result<RunOutcome> {
    let targets = resolve_targets(cli.lockfile.clone())?;
    let config = match &targets.manifest {
        Some(manifest) => config::load_config(manifest)?,
        None => config::AuditConfig::default(),
    };

    // Union config + CLI ignore lists; CLI severity overrides config.
    let mut ignore = config.ignore;
    ignore.extend(cli.ignore.iter().cloned());
    let mut ignore_until_fixed = config.ignore_until_fixed;
    ignore_until_fixed.extend(cli.ignore_until_fixed.iter().cloned());
    let threshold = cli.severity.or(config.severity);

    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(&targets.lockfile)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read lock file '{}'", targets.lockfile.display()))?;

    let base_url = std::env::var(BASE_URL_ENV_VAR).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let base_url = url::Url::parse(&base_url)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {BASE_URL_ENV_VAR} value '{base_url}'"))?;

    eprintln!("Auditing {} against {base_url} ...", targets.lockfile.display());

    let http_client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .into_diagnostic()
        .wrap_err("failed to construct the HTTP client")?;
    let http = reqwest_middleware::ClientBuilder::new(http_client).build();
    let client = BasiliskClient::new(http, base_url);

    let ignore_spec = pixi_audit::IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &ignore_until_fixed,
    };
    let report = audit_lock_file(
        &client,
        &lock_file,
        &cli.environments,
        &cli.platforms,
        ignore_spec,
    )
    .await
    .map_err(miette::Report::new)?;

    Ok(RunOutcome { report, threshold })
}
```

(`cli.fix` is accepted but not yet acted on — Task 5 wires it; add `let _ = cli.fix;` in `run()` if a warning appears, removed in Task 5. `--fix` MUST NOT change behavior in this task.)

5. `main()` exit logic:

```rust
        Ok(RunOutcome { report, threshold }) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                print!("{}", render::render_human(&report));
            }
            if gate_exit(&report, threshold) {
                eprintln!("error: audit found vulnerabilities");
                ExitCode::from(EXIT_VULNERABLE)
            } else {
                if report.summary.vulnerable > 0 {
                    let band = threshold.expect("vulnerabilities below a threshold imply one");
                    eprintln!(
                        "note: {} vulnerabilities found below the '{band}' severity threshold",
                        report.summary.vulnerable
                    );
                }
                ExitCode::SUCCESS
            }
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p pixi_audit_cli && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: all pass, including the existing integration tests (explicit-lockfile behavior is unchanged; the fixture directory has no manifest, so config resolves empty).

- [ ] **Step 5: Commit**

```bash
git add crates/pixi_audit_cli
git commit -m "feat: optional lockfile with discovery, config merge, and --severity gating"
```

---

### Task 4: Renderer marker for until-fixed ignores

**Files:**
- Modify: `crates/pixi_audit_cli/src/render.rs`

**Interfaces:**
- Consumes: `Finding.ignore_reason` / `pixi_audit::IgnoreReason` from Task 1.
- Produces: ignored-section lines shaped `  {id} ({package} {version}) — until a fix is released` for `UntilFixed`, unchanged for `Always`/`None`.

- [ ] **Step 1: Write the failing test**

Add to `render.rs` tests (the `finding()` helper already sets `ignore_reason: None` after Task 1):

```rust
    #[test]
    fn until_fixed_ignores_are_marked() {
        let mut always = finding("openssl", "CVE-2026-0001", SeverityBand::High);
        always.ignore_reason = Some(pixi_audit::IgnoreReason::Always);
        let mut until = finding("openssl", "CVE-2026-0002", SeverityBand::High);
        until.ignore_reason = Some(pixi_audit::IgnoreReason::UntilFixed);
        let report = AuditReport {
            ignored: vec![always, until],
            summary: AuditSummary {
                ignored: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert!(text.contains("  CVE-2026-0001 (openssl 3.1.0)\n"));
        assert!(text.contains("  CVE-2026-0002 (openssl 3.1.0) — until a fix is released\n"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pixi_audit_cli until_fixed_ignores_are_marked`
Expected: FAIL (marker not rendered).

- [ ] **Step 3: Implement**

In `render_human`'s ignored loop, replace the `writeln!` with:

```rust
        for finding in &report.ignored {
            let marker = match finding.ignore_reason {
                Some(pixi_audit::IgnoreReason::UntilFixed) => " — until a fix is released",
                _ => "",
            };
            writeln!(
                out,
                "  {} ({} {}){marker}",
                finding.id, finding.package, finding.version
            )
            .unwrap();
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p pixi_audit_cli render`
Expected: all render tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/pixi_audit_cli/src/render.rs
git commit -m "feat: mark until-fixed suppressions in the ignored section"
```

---

### Task 5: `fix.rs` — `pixi update` orchestration

**Files:**
- Create: `crates/pixi_audit_cli/src/fix.rs`
- Modify: `crates/pixi_audit_cli/src/main.rs` (wire `--fix` into `run()`)

**Interfaces:**
- Consumes: Task 3's `ResolvedTargets`, `RunOutcome`, and the audit pieces in `run()`.
- Produces:

```rust
/// Distinct package names among non-ignored findings, first-appearance order.
pub fn vulnerable_package_names(report: &AuditReport) -> Vec<String>;
/// Runs `pixi update --manifest-path <manifest> <names...>`, relaying its
/// output to stderr. Errors if pixi is missing or exits non-zero.
pub fn run_pixi_update(manifest: &Path, names: &[String]) -> miette::Result<()>;
```

The post-fix re-audit stays in `main.rs::run()` (it owns the client and filters).

- [ ] **Step 1: Write the failing unit tests**

Create `crates/pixi_audit_cli/src/fix.rs` with stubs and:

```rust
#[cfg(test)]
mod tests {
    use pixi_audit::{AuditReport, AuditSummary, Finding, SeverityBand};

    use super::*;

    fn finding(package: &str, id: &str) -> Finding {
        Finding {
            package: package.to_string(),
            version: "1.0".to_string(),
            ecosystem: "conda-forge".to_string(),
            environments: vec![],
            id: id.to_string(),
            aliases: vec![],
            severity: SeverityBand::High,
            fixed_versions: vec![],
            upstream_fixed_versions: vec![],
            summary: None,
            url: None,
            ignore_reason: None,
        }
    }

    #[test]
    fn vulnerable_package_names_dedupes_and_skips_ignored() {
        let report = AuditReport {
            vulnerabilities: vec![
                finding("openssl", "CVE-1"),
                finding("openssl", "CVE-2"),
                finding("pillow", "CVE-3"),
            ],
            ignored: vec![finding("zlib", "CVE-4")],
            summary: AuditSummary::default(),
            ..Default::default()
        };
        assert_eq!(vulnerable_package_names(&report), vec!["openssl", "pillow"]);
    }

    #[test]
    fn empty_report_yields_no_names() {
        assert!(vulnerable_package_names(&AuditReport::default()).is_empty());
    }

    #[test]
    fn missing_pixi_binary_is_an_error() {
        // A PATH with no `pixi` in it.
        let dir = tempfile::tempdir().unwrap();
        let old_path = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", dir.path()) };
        let result = run_pixi_update(
            std::path::Path::new("pixi.toml"),
            &["openssl".to_string()],
        );
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pixi_audit_cli fix 2>&1 | tail -5`
Expected: `todo!()` panics.

- [ ] **Step 3: Implement**

```rust
//! `--fix`: re-lock vulnerable packages via `pixi update`, then re-audit.

use std::path::Path;
use std::process::Command;

use miette::{IntoDiagnostic, WrapErr, miette};
use pixi_audit::AuditReport;

/// Distinct package names among the report's non-ignored findings, in
/// first-appearance order.
pub fn vulnerable_package_names(report: &AuditReport) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for finding in &report.vulnerabilities {
        if !names.contains(&finding.package) {
            names.push(finding.package.clone());
        }
    }
    names
}

/// Runs `pixi update --manifest-path <manifest> <names...>`. pixi's output
/// is relayed to our stderr so stdout stays reserved for the report.
pub fn run_pixi_update(manifest: &Path, names: &[String]) -> miette::Result<()> {
    let output = Command::new("pixi")
        .arg("update")
        .arg("--manifest-path")
        .arg(manifest)
        .args(names)
        .output()
        .into_diagnostic()
        .wrap_err("failed to run `pixi update` (is pixi on PATH?)")?;
    eprint!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(miette!("`pixi update` failed with {}", output.status));
    }
    Ok(())
}
```

Add `mod fix;` to `main.rs`, and extend `run()` — after the first `audit_lock_file` call, replace `Ok(RunOutcome { report, threshold })` with:

```rust
    if !cli.fix {
        return Ok(RunOutcome { report, threshold });
    }

    let names = fix::vulnerable_package_names(&report);
    if names.is_empty() {
        return Ok(RunOutcome { report, threshold });
    }
    let manifest = targets.manifest.as_deref().ok_or_else(|| {
        miette::miette!(
            "--fix requires a pixi workspace (no pixi.toml/pyproject.toml next to '{}')",
            targets.lockfile.display()
        )
    })?;
    fix::run_pixi_update(manifest, &names)?;

    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(&targets.lockfile)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to re-read lock file '{}' after pixi update",
                targets.lockfile.display()
            )
        })?;
    let after = audit_lock_file(
        &client,
        &lock_file,
        &cli.environments,
        &cli.platforms,
        ignore_spec,
    )
    .await
    .map_err(miette::Report::new)?;

    let before_count = report.summary.vulnerable;
    let resolved = before_count.saturating_sub(after.summary.vulnerable);
    eprintln!("fixed: resolved {resolved} of {before_count} vulnerabilities via pixi update");

    Ok(RunOutcome {
        report: after,
        threshold,
    })
```

(Remove the Task 3 `let _ = cli.fix;` placeholder. Note `ignore_spec` borrows `ignore`/`ignore_until_fixed`, which stay in scope — this compiles as long as the vectors are declared before `ignore_spec` and not moved.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p pixi_audit_cli && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: all pass. (`missing_pixi_binary_is_an_error` mutates PATH — if it ever flakes against parallel tests, mark it `#[serial_test::serial]`? NO — do not add dependencies; instead have it construct the Command with an absolute path override? Keep it simple: the test as written restores PATH immediately and no other unit test in this crate spawns processes, so it is safe.)

- [ ] **Step 5: Commit**

```bash
git add crates/pixi_audit_cli
git commit -m "feat: --fix re-locks vulnerable packages via pixi update and re-audits"
```

---

### Task 6: End-to-end integration tests for all five features

**Files:**
- Modify: `crates/pixi_audit_cli/tests/cli.rs`

**Interfaces:**
- Consumes: the compiled binary (`CARGO_BIN_EXE_pixi-audit`), existing helpers `lockfile()`, `vuln_doc()`, `spawn_mock()`, `run_cli()`.
- Produces: nothing further.

- [ ] **Step 1: Add helpers**

Append to `tests/cli.rs` (existing helpers stay):

```rust
/// A vuln doc with no fixed events anywhere (severity MEDIUM so severity
/// tests can gate above it).
fn vuln_doc_nofix_medium() -> serde_json::Value {
    serde_json::json!({
        "id": "BSLK-NOFIX",
        "aliases": ["CVE-2026-7777"],
        "summary": "No fix yet",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "versions": ["3.1.0"]
        }]
    })
}

/// Mock that serves `doc` for openssl at `vulnerable_version` only.
async fn spawn_mock_versioned(doc: serde_json::Value, vulnerable_version: &str) -> String {
    let vuln_id = doc["id"].as_str().unwrap().to_string();
    let version = vulnerable_version.to_string();
    let doc_for_get = doc.clone();
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(move |Json(body): Json<serde_json::Value>| {
                let vuln_id = vuln_id.clone();
                let version = version.clone();
                async move {
                    let results: Vec<serde_json::Value> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|q| {
                            if q["package"]["name"] == "openssl" && q["version"] == version.as_str()
                            {
                                serde_json::json!({"vulns": [{"id": vuln_id}]})
                            } else {
                                serde_json::json!({})
                            }
                        })
                        .collect();
                    Json(serde_json::json!({"results": results}))
                }
            }),
        )
        .route(
            "/v1/vulns/{id}",
            get(move || {
                let doc = doc_for_get.clone();
                async move { Json(doc) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

/// Copies the fixture lockfile into a temp workspace with the given
/// manifest content; returns the tempdir (keep it alive).
fn temp_workspace(manifest_name: &str, manifest_content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(lockfile(), dir.path().join("pixi.lock")).unwrap();
    std::fs::write(dir.path().join(manifest_name), manifest_content).unwrap();
    dir
}

/// Like run_cli but with a working directory and extra env.
async fn run_cli_in(
    dir: std::path::PathBuf,
    base_url: String,
    args: Vec<String>,
    path_override: Option<std::ffi::OsString>,
) -> Output {
    tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new(BIN);
        cmd.args(&args)
            .current_dir(&dir)
            .env("PIXI_AUDIT_BASE_URL", base_url);
        if let Some(path) = path_override {
            cmd.env("PATH", path);
        }
        cmd.output().expect("binary runs")
    })
    .await
    .unwrap()
}
```

Add `use std::ffi::OsString;`-style imports as needed (`tempfile` is already a dev-dependency from Task 2).

- [ ] **Step 2: Write the tests**

```rust
#[tokio::test(flavor = "multi_thread")]
async fn severity_threshold_gates_exit_code_but_not_output() {
    // MEDIUM finding vs --severity high => exit 0, finding still printed.
    let base = spawn_mock_versioned(vuln_doc_nofix_medium(), "3.1.0").await;
    let output = run_cli(
        base,
        vec![lockfile(), "--severity".to_string(), "high".to_string()],
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("BSLK-NOFIX"), "stdout: {stdout}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("below the 'high' severity threshold"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("error: audit found vulnerabilities"));
}

#[tokio::test(flavor = "multi_thread")]
async fn severity_threshold_still_fails_at_or_above() {
    // CRITICAL finding vs --severity high => exit 1.
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--severity".to_string(), "high".to_string()],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn ignore_until_fixed_suppresses_only_unfixed_findings() {
    // No fix known => suppressed, marked, exit 0.
    let base = spawn_mock_versioned(vuln_doc_nofix_medium(), "3.1.0").await;
    let output = run_cli(
        base,
        vec![
            lockfile(),
            "--ignore-until-fixed".to_string(),
            "BSLK-NOFIX".to_string(),
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("BSLK-NOFIX (openssl 3.1.0) — until a fix is released"),
        "stdout: {stdout}"
    );

    // Fix known (BSLK-1 fixes at 3.1.1) => NOT suppressed, exit 1.
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![
            lockfile(),
            "--ignore-until-fixed".to_string(),
            "BSLK-1".to_string(),
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_and_config_file_drive_a_bare_invocation() {
    let workspace = temp_workspace(
        "pixi.toml",
        "[workspace]\nname = \"demo\"\n\n[tool.pixi-audit]\nignore = [\"BSLK-1\"]\n",
    );
    // Run bare (no lockfile arg) from a nested directory.
    let nested = workspace.path().join("src");
    std::fs::create_dir(&nested).unwrap();
    let base = spawn_mock(true).await;
    let output = run_cli_in(nested, base, vec![], None).await;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Ignored 1 finding(s):"), "stdout: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bare_invocation_outside_a_workspace_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let base = spawn_mock(false).await;
    let output = run_cli_in(dir.path().to_path_buf(), base, vec![], None).await;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no pixi workspace found"), "stderr: {stderr}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn fix_runs_pixi_update_and_reaudits() {
    use std::os::unix::fs::PermissionsExt;

    let workspace = temp_workspace("pixi.toml", "[workspace]\nname = \"demo\"\n");
    // "Fixed" lockfile: openssl bumped to 3.1.1 (the mock only flags 3.1.0).
    let fixed_lock = std::fs::read_to_string(lockfile())
        .unwrap()
        .replace("openssl-3.1.0-hd590300_3", "openssl-3.1.1-hd590300_0");
    std::fs::write(workspace.path().join("fixed.lock"), fixed_lock).unwrap();
    // Fake pixi: records argv, swaps in the fixed lockfile.
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let fake_pixi = bin_dir.join("pixi");
    std::fs::write(
        &fake_pixi,
        format!(
            "#!/bin/sh\necho \"$@\" > '{ws}/pixi-args.txt'\ncp '{ws}/fixed.lock' '{ws}/pixi.lock'\n",
            ws = workspace.path().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_pixi, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_override = {
        let mut paths = vec![bin_dir.clone()];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        std::env::join_paths(paths).unwrap()
    };

    let base = spawn_mock_versioned(vuln_doc(), "3.1.0").await;
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base,
        vec!["--fix".to_string()],
        Some(path_override),
    )
    .await;

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("fixed: resolved 1 of 1 vulnerabilities via pixi update"),
        "stderr: {stderr}"
    );
    let args = std::fs::read_to_string(workspace.path().join("pixi-args.txt")).unwrap();
    assert!(args.contains("update"), "pixi argv: {args}");
    assert!(args.contains("--manifest-path"), "pixi argv: {args}");
    assert!(args.contains("openssl"), "pixi argv: {args}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No vulnerabilities found"), "stdout: {stdout}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn fix_without_pixi_on_path_exits_2() {
    let workspace = temp_workspace("pixi.toml", "[workspace]\nname = \"demo\"\n");
    let empty_dir = workspace.path().join("empty");
    std::fs::create_dir(&empty_dir).unwrap();
    let base = spawn_mock(true).await;
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base,
        vec!["--fix".to_string()],
        Some(empty_dir.into_os_string()),
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("is pixi on PATH?"), "stderr: {stderr}");
}
```

Note: `vuln_doc_nofix_medium`'s CVSS vector `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` scores 6.5 (MEDIUM). The severity test gates with `--severity high`, so MEDIUM passes — verify the rendered band in the failure message if the assertion trips.

- [ ] **Step 3: Run the integration tests**

Run: `cargo test -p pixi_audit_cli --test cli`
Expected: all previous 7 plus 7 new tests pass. Debug failures by printing the captured stdout/stderr (the assertions already carry them).

- [ ] **Step 4: Full workspace gate**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: everything passes.

- [ ] **Step 5: Commit**

```bash
git add crates/pixi_audit_cli/tests
git commit -m "test: end-to-end coverage for severity, until-fixed, config, discovery, and --fix"
```

---

### Task 7: README documentation

**Files:**
- Modify: `README.md` (the existing `## \`pixi audit\` (CLI extension)` section)

**Interfaces:** consumes the CLI surface from Tasks 3/5; nothing depends on it.

- [ ] **Step 1: Extend the README section**

Read the existing section first and extend it in place (keep its tone). Content to cover, matching actual behavior exactly:

```markdown
`pixi audit` can be invoked bare inside a workspace — it walks up from the
current directory to find `pixi.toml` (or `pyproject.toml` with
`[tool.pixi]`) and audits the workspace's `pixi.lock`:

```shell
pixi audit                                # discover the workspace
pixi audit --severity high                # fail CI only for high/critical
pixi audit --ignore-until-fixed CVE-2026-7777
pixi audit --fix                          # pixi update vulnerable packages, re-audit
```

Persistent configuration lives in the workspace manifest:

```toml
[tool.pixi-audit]
ignore = ["CVE-2023-0464"]              # always suppress
ignore-until-fixed = ["CVE-2026-7777"]  # suppress until a fix is released
severity = "high"                       # low | medium | high | critical
```

Ignore lists from the config and the command line are combined;
`--severity` on the command line overrides the config. Findings with
unknown severity always fail the threshold. `--fix` re-locks vulnerable
packages via `pixi update` within your existing manifest constraints (it
never edits the manifest) and reports what was resolved.
```

- [ ] **Step 2: Verify and commit**

Run: `cargo test --workspace 2>&1 | tail -3` (regression check only).

```bash
git add README.md
git commit -m "docs: document severity, until-fixed, config, discovery, and --fix"
```

---

### Task 8: Push branch and open the PR

**Files:** none (git/GitHub only)

- [ ] **Step 1: Push**

```bash
git push -u origin feat/pixi-audit-uv-parity
```

- [ ] **Step 2: Open the PR targeting the stacked base branch**

```bash
gh pr create --base feat/pixi-audit-cli --title "feat: uv-parity features for pixi audit (config, until-fixed, severity, fix, discovery)" --body "$(cat <<'EOF'
## What

Stacked on #3. Closes the main feature gaps with `uv audit`:

- **Config file**: `[tool.pixi-audit]` in `pixi.toml`/`pyproject.toml`
  (`ignore`, `ignore-until-fixed`, `severity`); lists union with CLI
  flags, CLI `--severity` overrides config.
- **`--ignore-until-fixed <ID>`**: suppresses a finding only while no
  fixed release is known (own-ecosystem or upstream); resurfaces once a
  fix is published. Ignored findings now carry `ignore_reason` in JSON.
- **`--severity <BAND>`**: exit-code threshold (low|medium|high|critical).
  The report is never filtered; unknown severity always fails (fail-safe).
- **`--fix`**: re-locks vulnerable packages via `pixi update` (never edits
  the manifest), re-audits, and reports what was resolved.
- **Lockfile discovery**: the lockfile positional is now optional — bare
  `pixi audit` walks up to the workspace root.

## Library change

`pixi_audit::audit`/`audit_lock_file` now take an `IgnoreSpec { ignore,
ignore_until_fixed }`; `Finding` gains `ignore_reason: Option<IgnoreReason>`
(serialized only when ignored).

## Testing

- Library unit tests for until-fixed categorization and JSON shape.
- Config/discovery unit tests (both manifest kinds, precedence, invalid
  tables, unknown-key warning).
- 7 new end-to-end tests: severity gating both directions, until-fixed
  with and without a known fix, config+discovery bare invocation,
  no-workspace error, `--fix` against a fake `pixi` on PATH, missing-pixi
  error.

Spec: docs/superpowers/specs/2026-07-30-pixi-audit-uv-parity-design.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
