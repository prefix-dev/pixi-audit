# pixi-audit CLI Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `pixi-audit` binary (discovered by pixi as `pixi audit`) that audits a `pixi.lock` file for known vulnerabilities and reports them human-readably or as JSON.

**Architecture:** New thin CLI crate `crates/pixi_audit_cli` on top of the existing `pixi_audit` library, which already does lock parsing, filtering, ignoring, and report building. The CLI adds clap argument parsing, a human renderer for `AuditReport`, exit-code mapping, and an integration test against an axum mock of the OSV API.

**Tech Stack:** Rust (edition 2024), clap 4 (derive), console 0.16, tokio, miette, axum (tests only).

**Spec:** `docs/superpowers/specs/2026-07-30-pixi-audit-cli-design.md`

## Global Constraints

- Work on branch `feat/pixi-audit-cli` off `main` (create it before Task 1 if it does not exist: `git checkout -b feat/pixi-audit-cli`).
- Package name `pixi_audit_cli` (snake_case like `osv_protocol`, `pixi_audit`); binary name `pixi-audit` (required by pixi's extension discovery).
- Exit codes: `0` clean (ignored-only findings are clean), `1` vulnerabilities found, `2` execution error. clap usage errors already exit 2 by default — do not change that.
- API endpoint comes only from the `PIXI_AUDIT_BASE_URL` env var (library constant `BASE_URL_ENV_VAR`), default `DEFAULT_BASE_URL`. No `--base-url` flag.
- In `--json` mode stdout carries only the JSON report; progress and error text go to stderr in every mode.
- Run commands from the repo root `/Users/graf/oss/pixi-audit`.
- The workspace `Cargo.toml` uses `members = ["crates/*"]`, so the new crate is picked up automatically; CI runs workspace-wide and needs no changes.

---

### Task 1: Scaffold `pixi_audit_cli` crate with clap argument parsing

**Files:**
- Modify: `Cargo.toml` (workspace dependencies)
- Create: `crates/pixi_audit_cli/Cargo.toml`
- Create: `crates/pixi_audit_cli/src/main.rs`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `struct Cli` (in `main.rs`) with fields `lockfile: PathBuf`, `environments: Vec<String>`, `platforms: Vec<String>`, `ignore: Vec<String>`, `json: bool`. Task 3 wires it up; Task 2 is independent.

- [ ] **Step 1: Add workspace dependencies**

In the root `Cargo.toml`, add to `[workspace.dependencies]` (keep the list alphabetically ordered, as it is today):

```toml
clap = "4.6"
console = "0.16"
pixi_audit = { path = "crates/pixi_audit", version = "0.1.0" }
```

- [ ] **Step 2: Create the crate manifest**

Create `crates/pixi_audit_cli/Cargo.toml`:

```toml
[package]
authors.workspace = true
description = "pixi extension that audits a pixi.lock file for known vulnerabilities"
edition.workspace = true
homepage.workspace = true
license.workspace = true
name = "pixi_audit_cli"
readme.workspace = true
repository.workspace = true
version = "0.1.0"

# pixi discovers extensions as `pixi-<cmd>` executables on PATH, so the
# binary name must be `pixi-audit` even though the package is snake_case.
[[bin]]
name = "pixi-audit"
path = "src/main.rs"

[dependencies]
clap = { workspace = true, features = ["derive"] }
console = { workspace = true }
miette = { workspace = true, features = ["fancy"] }
pixi_audit = { workspace = true }
# rustls so the binary can talk to the real HTTPS API.
reqwest = { workspace = true, features = ["json", "rustls"] }
reqwest-middleware = { workspace = true, features = ["json"] }
serde_json = { workspace = true }
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
url = { workspace = true }

[dev-dependencies]
axum = { workspace = true, features = ["http1", "tokio", "json"] }
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "net"] }
```

- [ ] **Step 3: Write `main.rs` with the Cli struct, parse-only main, and unit tests**

Create `crates/pixi_audit_cli/src/main.rs`:

```rust
//! `pixi-audit` — a pixi extension (`pixi audit`) that audits a `pixi.lock`
//! file for known vulnerabilities against an OSV-compatible API.

use std::path::PathBuf;

use clap::Parser;

/// Audit a pixi.lock file for known vulnerabilities.
///
/// Exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found,
/// 2 = execution error.
#[derive(Debug, Parser)]
#[command(name = "pixi-audit", version)]
struct Cli {
    /// Path to the pixi.lock file to audit
    lockfile: PathBuf,

    /// Audit only this environment (repeatable)
    #[arg(long = "environment", value_name = "ENV")]
    environments: Vec<String>,

    /// Audit only this platform (repeatable)
    #[arg(long = "platform", value_name = "PLATFORM")]
    platforms: Vec<String>,

    /// Vulnerability id or alias to ignore, case-insensitive (repeatable).
    /// Ignored findings still appear in the report's ignored section.
    #[arg(long = "ignore", value_name = "ID")]
    ignore: Vec<String>,

    /// Emit the report as pretty-printed JSON on stdout
    #[arg(long)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();
    // Wired up in a later task.
    let _ = cli;
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn lockfile_is_required() {
        assert!(Cli::try_parse_from(["pixi-audit"]).is_err());
    }

    #[test]
    fn repeatable_flags_accumulate() {
        let cli = Cli::try_parse_from([
            "pixi-audit",
            "pixi.lock",
            "--environment",
            "default",
            "--environment",
            "prod",
            "--platform",
            "linux-64",
            "--ignore",
            "CVE-2026-1234",
            "--json",
        ])
        .unwrap();
        assert_eq!(cli.lockfile, PathBuf::from("pixi.lock"));
        assert_eq!(cli.environments, vec!["default", "prod"]);
        assert_eq!(cli.platforms, vec!["linux-64"]);
        assert_eq!(cli.ignore, vec!["CVE-2026-1234"]);
        assert!(cli.json);
    }
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cargo test -p pixi_audit_cli`
Expected: 3 tests PASS. (`cargo check -p pixi_audit_cli` must also be warning-free.)

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/pixi_audit_cli
git commit -m "feat: scaffold pixi_audit_cli crate with pixi-audit binary and CLI parsing"
```

---

### Task 2: Human renderer for `AuditReport`

**Files:**
- Create: `crates/pixi_audit_cli/src/render.rs`
- Modify: `crates/pixi_audit_cli/src/main.rs` (add `mod render;` line only)

**Interfaces:**
- Consumes: `pixi_audit::{AuditReport, Finding, SeverityBand, UncheckedPackage}` — all fields `pub`, directly constructible. `Finding` fields: `package: String, version: String, ecosystem: String, environments: Vec<String>, id: String, aliases: Vec<String>, severity: SeverityBand, fixed_versions: Vec<String>, upstream_fixed_versions: Vec<String>, summary: Option<String>, url: Option<String>`. `UncheckedPackage` fields: `package: String, version: Option<String>, ecosystem: String, environments: Vec<String>`. `AuditSummary` fields: `audited, vulnerable, ignored, unchecked: usize`.
- Produces: `pub fn render_human(report: &AuditReport) -> String` — used by Task 3.

Rendering rules (colors via `console::style`, which auto-disables when stdout is not a TTY, so tests assert on plain text):

- Vulnerable packages: findings grouped by `(package, version)` in first-appearance order (the library already sorts findings highest-severity-first, then by package name). Group header: `{package} {version} ({ecosystem}) — {environments joined with ", "}`. Per finding, an indented line `  {id}  {SEVERITY}` where SEVERITY is uppercased and left-padded to 8 chars (critical/high red, medium yellow, low/unknown dim), followed by ` fixed in: {fixed_versions joined ", "}`, or ` fix released upstream: {upstream_fixed_versions joined ", "}` when `fixed_versions` is empty but `upstream_fixed_versions` is not, or ` no known fixed version` when both are empty. When `url` is `Some`, an indented line with the URL follows.
- Ignored findings (if any): a section `Ignored {n} finding(s):` with one line per finding: `  {id} ({package} {version})`.
- Unchecked packages (if any): a section `{n} package(s) could not be checked:` with one line per package: `  {package} {version-or-"?"} ({ecosystem}) — {environments joined ", "}`.
- Final summary line: if `summary.vulnerable > 0`: `{vulnerable} vulnerabilities in {distinct vulnerable packages} package(s) ({audited} audited, {ignored} ignored, {unchecked} unchecked)`; otherwise `No vulnerabilities found ({audited} audited, {ignored} ignored, {unchecked} unchecked)`.
- Sections are separated by single blank lines; output ends with a trailing newline.

- [ ] **Step 1: Write the failing tests**

Create `crates/pixi_audit_cli/src/render.rs` containing only the test module for now:

```rust
//! Human-readable rendering of an [`AuditReport`].

use pixi_audit::AuditReport;

pub fn render_human(_report: &AuditReport) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use pixi_audit::{AuditReport, AuditSummary, Finding, SeverityBand, UncheckedPackage};

    use super::*;

    fn finding(package: &str, id: &str, severity: SeverityBand) -> Finding {
        Finding {
            package: package.to_string(),
            version: "3.1.0".to_string(),
            ecosystem: "conda-forge".to_string(),
            environments: vec!["default".to_string(), "prod".to_string()],
            id: id.to_string(),
            aliases: vec![],
            severity,
            fixed_versions: vec!["3.1.4".to_string()],
            upstream_fixed_versions: vec![],
            summary: None,
            url: Some(format!("https://osv.dev/{id}")),
        }
    }

    #[test]
    fn empty_report_renders_clean_summary() {
        let report = AuditReport {
            summary: AuditSummary {
                audited: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert_eq!(text, "No vulnerabilities found (5 audited, 0 ignored, 0 unchecked)\n");
    }

    #[test]
    fn findings_are_grouped_per_package_with_fix_and_url() {
        let mut second = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
        second.fixed_versions = vec![];
        second.upstream_fixed_versions = vec!["3.2.0".to_string()];
        second.url = None;
        let report = AuditReport {
            vulnerabilities: vec![
                finding("openssl", "CVE-2026-0001", SeverityBand::High),
                second,
            ],
            summary: AuditSummary {
                audited: 10,
                vulnerable: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render_human(&report);
        // One header for both findings of the same package+version.
        assert_eq!(text.matches("openssl 3.1.0 (conda-forge) — default, prod").count(), 1);
        assert!(text.contains("CVE-2026-0001  HIGH      fixed in: 3.1.4"));
        assert!(text.contains("https://osv.dev/CVE-2026-0001"));
        assert!(text.contains("CVE-2026-0002  MEDIUM    fix released upstream: 3.2.0"));
        assert!(text.contains("2 vulnerabilities in 1 package(s) (10 audited, 0 ignored, 0 unchecked)"));
    }

    #[test]
    fn finding_without_any_fix_says_so() {
        let mut f = finding("openssl", "CVE-2026-0003", SeverityBand::Unknown);
        f.fixed_versions = vec![];
        let report = AuditReport {
            vulnerabilities: vec![f],
            summary: AuditSummary {
                audited: 1,
                vulnerable: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert!(text.contains("CVE-2026-0003  UNKNOWN   no known fixed version"));
    }

    #[test]
    fn ignored_and_unchecked_sections_render() {
        let report = AuditReport {
            ignored: vec![finding("openssl", "CVE-2026-0001", SeverityBand::High)],
            unchecked: vec![UncheckedPackage {
                package: "samtools".to_string(),
                version: Some("1.19".to_string()),
                ecosystem: "bioconda".to_string(),
                environments: vec!["default".to_string()],
            }],
            summary: AuditSummary {
                audited: 3,
                vulnerable: 0,
                ignored: 1,
                unchecked: 1,
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert!(text.contains("Ignored 1 finding(s):"));
        assert!(text.contains("  CVE-2026-0001 (openssl 3.1.0)"));
        assert!(text.contains("1 package(s) could not be checked:"));
        assert!(text.contains("  samtools 1.19 (bioconda) — default"));
        assert!(text.contains("No vulnerabilities found (3 audited, 1 ignored, 1 unchecked)"));
    }

    #[test]
    fn unchecked_package_without_version_renders_question_mark() {
        let report = AuditReport {
            unchecked: vec![UncheckedPackage {
                package: "mypkg".to_string(),
                version: None,
                ecosystem: "unknown".to_string(),
                environments: vec!["default".to_string()],
            }],
            summary: AuditSummary {
                unchecked: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(render_human(&report).contains("  mypkg ? (unknown) — default"));
    }
}
```

Add `mod render;` to `main.rs` after the `use` items, and add `let _ = render::render_human;` as the first line of `fn main()` so this intermediate state compiles without a dead-code warning (Task 3 replaces `main` and removes that line).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pixi_audit_cli render`
Expected: FAIL — each test panics at `todo!()`.

- [ ] **Step 3: Implement `render_human`**

Replace the `todo!()` implementation with:

```rust
use std::fmt::Write as _;

use console::style;
use pixi_audit::{Finding, SeverityBand};

/// Renders the report for terminal consumption. Colors are applied by
/// `console`, which disables styling automatically when stdout is not a
/// terminal, so the output is plain text in pipes and tests.
pub fn render_human(report: &AuditReport) -> String {
    let mut out = String::new();

    for (header, findings) in grouped(&report.vulnerabilities) {
        writeln!(out, "{header}").unwrap();
        for finding in findings {
            writeln!(out, "  {}  {}{}", finding.id, severity_cell(finding.severity), fix_note(finding)).unwrap();
            if let Some(url) = &finding.url {
                writeln!(out, "  {}", style(url).dim()).unwrap();
            }
        }
        out.push('\n');
    }

    if !report.ignored.is_empty() {
        writeln!(out, "Ignored {} finding(s):", report.ignored.len()).unwrap();
        for finding in &report.ignored {
            writeln!(out, "  {} ({} {})", finding.id, finding.package, finding.version).unwrap();
        }
        out.push('\n');
    }

    if !report.unchecked.is_empty() {
        writeln!(out, "{} package(s) could not be checked:", report.unchecked.len()).unwrap();
        for package in &report.unchecked {
            writeln!(
                out,
                "  {} {} ({}) — {}",
                package.package,
                package.version.as_deref().unwrap_or("?"),
                package.ecosystem,
                package.environments.join(", ")
            )
            .unwrap();
        }
        out.push('\n');
    }

    let summary = &report.summary;
    if summary.vulnerable > 0 {
        let packages: std::collections::BTreeSet<(&str, &str)> = report
            .vulnerabilities
            .iter()
            .map(|f| (f.package.as_str(), f.version.as_str()))
            .collect();
        writeln!(
            out,
            "{} vulnerabilities in {} package(s) ({} audited, {} ignored, {} unchecked)",
            style(summary.vulnerable).red().bold(),
            packages.len(),
            summary.audited,
            summary.ignored,
            summary.unchecked
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "{} ({} audited, {} ignored, {} unchecked)",
            style("No vulnerabilities found").green(),
            summary.audited,
            summary.ignored,
            summary.unchecked
        )
        .unwrap();
    }
    out
}

/// Groups findings by (package, version) preserving first-appearance order
/// (the library sorts highest severity first, so groups appear by their most
/// severe finding).
fn grouped(findings: &[Finding]) -> Vec<(String, Vec<&Finding>)> {
    let mut groups: Vec<((&str, &str), String, Vec<&Finding>)> = Vec::new();
    for finding in findings {
        let key = (finding.package.as_str(), finding.version.as_str());
        match groups.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, _, members)) => members.push(finding),
            None => {
                let header = format!(
                    "{} {} ({}) — {}",
                    style(&finding.package).bold(),
                    finding.version,
                    finding.ecosystem,
                    finding.environments.join(", ")
                );
                groups.push((key, header, vec![finding]));
            }
        }
    }
    groups
        .into_iter()
        .map(|(_, header, members)| (header, members))
        .collect()
}

/// Uppercased severity, left-aligned to 8 columns, colored by band.
fn severity_cell(band: SeverityBand) -> String {
    let text = format!("{:<8}", band.to_string().to_uppercase());
    let styled = match band {
        SeverityBand::Critical | SeverityBand::High => style(text).red().bold(),
        SeverityBand::Medium => style(text).yellow(),
        SeverityBand::Low | SeverityBand::Unknown => style(text).dim(),
    };
    styled.to_string()
}

fn fix_note(finding: &Finding) -> String {
    if !finding.fixed_versions.is_empty() {
        format!("  fixed in: {}", finding.fixed_versions.join(", "))
    } else if !finding.upstream_fixed_versions.is_empty() {
        format!(
            "  fix released upstream: {}",
            finding.upstream_fixed_versions.join(", ")
        )
    } else {
        "  no known fixed version".to_string()
    }
}
```

Note the column math the tests encode: the finding line is `"  {id}  {severity_cell}{fix_note}"` where `severity_cell` pads to 8 and `fix_note` starts with two spaces — e.g. `CVE-2026-0001  HIGH      fixed in: 3.1.4` (severity `HIGH` + 4 pad spaces + 2 note spaces).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p pixi_audit_cli render`
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pixi_audit_cli/src/render.rs crates/pixi_audit_cli/src/main.rs
git commit -m "feat: human-readable renderer for audit reports"
```

---

### Task 3: Wire up `main`: audit, output modes, exit codes

**Files:**
- Modify: `crates/pixi_audit_cli/src/main.rs`

**Interfaces:**
- Consumes: `Cli` (Task 1), `render::render_human` (Task 2), and from `pixi_audit`: `audit_lock_file(&BasiliskClient, &LockFile, &[String], &[String], &[String]) -> Result<AuditReport, LockFileAuditError>`, `BasiliskClient::new(ClientWithMiddleware, Url)`, `BASE_URL_ENV_VAR`, `DEFAULT_BASE_URL`, `rattler_lock::LockFile::from_path(&Path)`.
- Produces: the finished binary behavior that Task 4's integration tests exercise.

- [ ] **Step 1: Implement the runtime**

Replace `fn main()` in `main.rs` with (keep the `Cli` struct and its tests):

```rust
use std::process::ExitCode;

use miette::{Context, IntoDiagnostic};
use pixi_audit::{AuditReport, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, audit_lock_file};

mod render;

const EXIT_VULNERABLE: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli).await {
        Ok(report) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                print!("{}", render::render_human(&report));
            }
            if report.summary.vulnerable > 0 {
                eprintln!("error: audit found vulnerabilities");
                ExitCode::from(EXIT_VULNERABLE)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

async fn run(cli: Cli) -> miette::Result<AuditReport> {
    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(&cli.lockfile)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read lock file '{}'", cli.lockfile.display()))?;

    let base_url = std::env::var(BASE_URL_ENV_VAR).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let base_url = url::Url::parse(&base_url)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {BASE_URL_ENV_VAR} value '{base_url}'"))?;

    eprintln!("Auditing {} against {base_url} ...", cli.lockfile.display());

    let http = reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build();
    let client = BasiliskClient::new(http, base_url);

    audit_lock_file(&client, &lock_file, &cli.environments, &cli.platforms, &cli.ignore)
        .await
        .map_err(miette::Report::new)
}
```

(`miette` errors print their fancy diagnostic rendering via `{error:?}` on `miette::Report`.)

- [ ] **Step 2: Verify it builds and the unit tests still pass**

Run: `cargo test -p pixi_audit_cli && cargo clippy -p pixi_audit_cli -- -D warnings`
Expected: all tests PASS, no clippy warnings.

- [ ] **Step 3: Smoke-test against the sample lockfile (network-free failure path)**

Run: `PIXI_AUDIT_BASE_URL="http://127.0.0.1:1" cargo run -p pixi_audit_cli -- crates/pixi_audit/examples/pixi.lock; echo "exit: $?"`
Expected: a miette-rendered connection error on stderr, `exit: 2`.

Run: `cargo run -p pixi_audit_cli -- does-not-exist.lock; echo "exit: $?"`
Expected: "failed to read lock file 'does-not-exist.lock'" on stderr, `exit: 2`.

- [ ] **Step 4: Commit**

```bash
git add crates/pixi_audit_cli/src/main.rs
git commit -m "feat: wire pixi-audit binary: audit, json/human output, exit codes"
```

---

### Task 4: Integration tests for the binary against a mock OSV API

**Files:**
- Create: `crates/pixi_audit_cli/tests/data/pixi.lock`
- Create: `crates/pixi_audit_cli/tests/cli.rs`

**Interfaces:**
- Consumes: the compiled binary via `env!("CARGO_BIN_EXE_pixi-audit")` (Cargo sets this for integration tests of a crate with that bin target); the mock-server pattern from `crates/pixi_audit/src/report.rs` tests.
- Produces: nothing further; this is the final verification layer.

- [ ] **Step 1: Create the lockfile fixture**

Create `crates/pixi_audit_cli/tests/data/pixi.lock` (same shape as the `pixi_audit::lock` test fixture: openssl in two environments, a bioconda package that will be unchecked, and a PyPI wheel):

```yaml
version: 6
environments:
  default:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      linux-64:
      - conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
      - conda: https://conda.anaconda.org/bioconda/linux-64/samtools-1.19-h50ea8bc_0.conda
      - pypi: https://files.pythonhosted.org/packages/py3/r/requests/requests-2.32.0-py3-none-any.whl
  prod:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      linux-64:
      - conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
packages:
- conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  md5: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  license: Apache-2.0
  size: 100
  timestamp: 1700000000000
- conda: https://conda.anaconda.org/bioconda/linux-64/samtools-1.19-h50ea8bc_0.conda
  sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  md5: cccccccccccccccccccccccccccccccc
  license: MIT
  size: 100
  timestamp: 1700000000000
- pypi: https://files.pythonhosted.org/packages/py3/r/requests/requests-2.32.0-py3-none-any.whl
  name: requests
  version: 2.32.0
  sha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  requires_python: '>=3.8'
```

- [ ] **Step 2: Write the integration tests**

Create `crates/pixi_audit_cli/tests/cli.rs`:

```rust
//! End-to-end tests: run the compiled `pixi-audit` binary against a local
//! mock of the OSV API and assert on output and exit codes.

use std::path::Path;
use std::process::Output;

use axum::{
    Json, Router,
    routing::{get, post},
};

const BIN: &str = env!("CARGO_BIN_EXE_pixi-audit");

fn lockfile() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/pixi.lock")
        .to_string_lossy()
        .into_owned()
}

fn vuln_doc() -> serde_json::Value {
    serde_json::json!({
        "id": "BSLK-1",
        "aliases": ["CVE-2026-1234"],
        "summary": "Buffer overflow in openssl",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.1"}]}]
        }],
        "references": [{"type": "ADVISORY", "url": "https://example.com/adv"}]
    })
}

/// Mock server: openssl has BSLK-1 when `vulnerable`, everything else clean.
async fn spawn_mock(vulnerable: bool) -> String {
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(move |Json(body): Json<serde_json::Value>| async move {
                let results: Vec<serde_json::Value> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| {
                        if vulnerable && q["package"]["name"] == "openssl" {
                            serde_json::json!({"vulns": [{"id": "BSLK-1"}]})
                        } else {
                            serde_json::json!({})
                        }
                    })
                    .collect();
                Json(serde_json::json!({"results": results}))
            }),
        )
        .route("/v1/vulns/{id}", get(|| async { Json(vuln_doc()) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

/// Runs the binary without blocking the tokio worker serving the mock.
async fn run_cli(base_url: String, args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(BIN)
            .args(&args)
            .env("PIXI_AUDIT_BASE_URL", base_url)
            .output()
            .expect("binary runs")
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn vulnerable_lockfile_reports_and_exits_1() {
    let base = spawn_mock(true).await;
    let output = run_cli(base, vec![lockfile()]).await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("openssl 3.1.0 (conda-forge) — default, prod"), "stdout: {stdout}");
    assert!(stdout.contains("BSLK-1"));
    assert!(stdout.contains("CRITICAL"));
    assert!(stdout.contains("fixed in: 3.1.1"));
    assert!(stdout.contains("https://example.com/adv"));
    // samtools (bioconda) and requests (PyPI) are outside covered ecosystems.
    assert!(stdout.contains("2 package(s) could not be checked:"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error: audit found vulnerabilities"), "stderr: {stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_lockfile_exits_0() {
    let base = spawn_mock(false).await;
    let output = run_cli(base, vec![lockfile()]).await;

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No vulnerabilities found"), "stdout: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn json_mode_emits_only_the_report_on_stdout() {
    let base = spawn_mock(true).await;
    let output = run_cli(base, vec![lockfile(), "--json".to_string()]).await;

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is exactly one JSON document");
    assert_eq!(report["summary"]["vulnerable"], 1);
    assert_eq!(report["vulnerabilities"][0]["id"], "BSLK-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn ignored_finding_exits_0_but_is_reported() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--ignore".to_string(), "cve-2026-1234".to_string()],
    )
    .await;

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Ignored 1 finding(s):"), "stdout: {stdout}");
    assert!(stdout.contains("BSLK-1 (openssl 3.1.0)"));
}

#[tokio::test(flavor = "multi_thread")]
async fn environment_filter_limits_the_audit() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--environment".to_string(), "prod".to_string()],
    )
    .await;

    // prod only contains openssl: nothing unchecked.
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("could not be checked"), "stdout: {stdout}");
    assert!(stdout.contains("openssl 3.1.0 (conda-forge) — prod"));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_environment_exits_2() {
    let base = spawn_mock(false).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--environment".to_string(), "nope".to_string()],
    )
    .await;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no environment named 'nope'"), "stderr: {stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_lockfile_exits_2() {
    let base = spawn_mock(false).await;
    let output = run_cli(base, vec!["does-not-exist.lock".to_string()]).await;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("does-not-exist.lock"), "stderr: {stderr}");
}
```

- [ ] **Step 3: Run the integration tests**

Run: `cargo test -p pixi_audit_cli --test cli`
Expected: 7 tests PASS. If an assertion on exact spacing fails, fix the test's expectation only if the renderer matches Task 2's specified format; otherwise fix the renderer — Task 2's format rules are the source of truth.

- [ ] **Step 4: Run the full workspace verification**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: everything passes.

- [ ] **Step 5: Commit**

```bash
git add crates/pixi_audit_cli/tests
git commit -m "test: end-to-end CLI tests against a mock OSV API"
```

---

### Task 5: README usage documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the CLI surface from Task 1/3.
- Produces: user-facing docs; nothing depends on it.

- [ ] **Step 1: Read the current README and add a CLI section**

Read `README.md` first and match its tone/structure. Add a section documenting the extension (adjust heading level to fit the existing document):

```markdown
## `pixi audit` (CLI extension)

`pixi_audit_cli` ships a `pixi-audit` binary. pixi discovers any executable
named `pixi-<cmd>` on `PATH` (or in `$PIXI_HOME/bin`) as an extension, so once
installed it runs as `pixi audit`:

```shell
pixi audit pixi.lock
pixi audit pixi.lock --environment prod --platform linux-64
pixi audit pixi.lock --ignore CVE-2026-1234 --json
```

Exit codes: `0` no vulnerabilities, `1` vulnerabilities found, `2` execution
error. Set `PIXI_AUDIT_BASE_URL` to audit against a different OSV-compatible
instance. Install from a checkout with:

```shell
cargo install --path crates/pixi_audit_cli
```
```

- [ ] **Step 2: Verify and commit**

Run: `cargo test --workspace` (unchanged code — a quick regression check).

```bash
git add README.md
git commit -m "docs: document the pixi audit CLI extension"
```

---

### Task 6: Push branch and open the PR

**Files:** none (git/GitHub only)

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feat/pixi-audit-cli
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "feat: pixi-audit CLI extension (pixi audit)" --body "$(cat <<'EOF'
## What

Adds `crates/pixi_audit_cli`, a thin CLI over the `pixi_audit` library that
builds a `pixi-audit` binary. pixi discovers `pixi-<cmd>` executables on
`PATH`/`$PIXI_HOME/bin` as extensions, so this provides `pixi audit` —
analogous to `uv audit`.

## Usage

    pixi audit pixi.lock [--environment ENV]... [--platform PLATFORM]...
                         [--ignore ID]... [--json]

- Human-readable findings (severity, fixed versions, advisory URL) by
  default; `--json` emits the structured `AuditReport`.
- Exit codes: 0 clean, 1 vulnerabilities found, 2 execution error.
- `PIXI_AUDIT_BASE_URL` selects the OSV-compatible endpoint.

## Testing

- Renderer unit tests (grouping, fix notes, ignored/unchecked sections).
- End-to-end tests running the binary against an axum mock of the OSV API,
  asserting stdout/stderr content and all three exit codes.

Spec: docs/superpowers/specs/2026-07-30-pixi-audit-cli-design.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
