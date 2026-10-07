# pixi-audit

Audit [Pixi](https://pixi.sh) lock files for known vulnerabilities. `pixi-audit` checks conda-forge packages with [Basilisk](https://github.com/prefix-dev/basilisk) and PyPI packages with [OSV](https://osv.dev).

It runs as a `pixi audit` extension or a standalone `pixi-audit` command.

## Installation

From a local checkout:

```console
pixi global install --path .
```

Or with Cargo:

```console
cargo install --path crates/pixi_audit_cli --locked
```

## Usage

Audit the current workspace or a specific lock file:

```console
pixi audit
pixi audit path/to/pixi.lock
```

Limit the audit to an environment or platform:

```console
pixi audit --environment production --platform linux-64
```

### Ignore known findings

Ignore an advisory by ID or alias for one run:

```console
pixi audit --ignore CVE-2023-0464
```

Ignore a finding until a fix is known, or ignore all findings without a known fix:

```console
pixi audit --ignore-until-fixed CVE-2023-0464
pixi audit --ignore-unfixed
```

These findings return when an ecosystem-specific or upstream fix becomes known. Ignored findings remain in the report.

Save rules in the workspace manifest:

```console
pixi audit ignore CVE-2023-0464 --reason "Not affected in this deployment"
pixi audit ignore CVE-2023-0464 --until-fixed
pixi audit ignore CVE-2023-0464 --until 2026-12-01
```

Limit a rule to a package, ecosystem, or installed version:

```console
pixi audit ignore CVE-2023-0464 --package openssl
pixi audit ignore CVE-2023-0464 --package openssl --ecosystem conda-forge --version 3.1.0
```

Use `--max-affected-version` instead of `--version` to match versions up to a limit. Ecosystems are `conda-forge` and `PyPI`.

Omit the ID to ignore all findings for a package:

```console
pixi audit ignore --package vendored-thing --reason "Only used for its data files"
```

Expired rules and rules that match no findings produce warnings.

### Set a severity threshold

Fail only on findings at or above a severity level:

```console
pixi audit --severity high
```

Levels are `low`, `medium`, `high`, and `critical`. Findings with unknown severity still fail the audit.

Report an ecosystem's findings without letting them fail the audit:

```console
pixi audit --warn-only conda-forge
```

### Rank findings by risk

The default table sorts by risk, combining severity, [EPSS](https://www.first.org/epss/) exploitation probability, and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) data. Risk affects ordering, not exit codes.

Sort by another field or explain the scores:

```console
pixi audit --sort-by severity
pixi audit --explain
```

If threat data is unavailable, the audit continues with a warning.

### Update vulnerable dependencies

Update dependencies and audit again:

```console
pixi audit --fix
```

This raises direct dependency constraints to known compatible fixed versions and runs `pixi update`, preserving existing upper bounds. It does not rewrite transitive dependency constraints. Upstream-only fixes are reported but cannot be installed.

### Choose an output format

Use the default table, group findings by package, or export JSON or SARIF:

```console
pixi audit
pixi audit --format grouped
pixi audit --json > audit-report.json
pixi audit --format sarif > pixi-audit.sarif
```

Choose table columns and their order:

```console
pixi audit --sort-by name --fields name,version,vulnerability,fixed-in,url
```

An empty *Fixed in* cell means no fix is known; fixes available only upstream or in another ecosystem are labeled. Add `--explain` to table or grouped output for definitions.

Reports go to stdout; progress and diagnostics go to stderr. Piped output is plain text; use `CLICOLOR_FORCE=1` to keep colors in CI logs.

Run `pixi audit --help` for all options and fields.

### Use in GitHub Actions

Findings are emitted as workflow annotations. To upload a SARIF report to GitHub code scanning, add these steps after installing the extension:

```yaml
- run: pixi audit --format sarif > pixi-audit.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pixi-audit.sarif
```

The upload requires `security-events: write` permission. Ignored findings are included as suppressed results.

## Configuration

Store recurring settings in `pixi.toml` or `pyproject.toml`:

```toml
[tool.pixi-audit]
severity = "high"
ignore-unfixed = true
ignore-until-fixed = ["CVE-2026-7777"]
ignore = [
  "CVE-2023-0464",
  { id = "CVE-2026-1234", reason = "Not affected in this deployment", until = "2026-12-01" },
  { package = "vendored-thing", reason = "Only used for its data files" },
]
```

Rules can also specify `ecosystem`, `version`, or `max-affected-version`. Keep dates quoted. Command-line severity overrides the manifest; ignore lists are combined.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | No actionable vulnerabilities |
| `1` | Actionable vulnerabilities found |
| `2` | The audit could not run |

## Coverage

Packages are deduplicated across selected environments and platforms. Withdrawn advisories are skipped. Packages from channels other than conda-forge and source dependencies are reported as unchecked, not safe.

Override service endpoints with these environment variables:

| Variable | Default |
| --- | --- |
| `PIXI_AUDIT_BASE_URL` | `https://api.basilisk.prefix.dev` |
| `PIXI_AUDIT_PYPI_BASE_URL` | `https://api.osv.dev` |
| `PIXI_AUDIT_EPSS_BASE_URL` | `https://api.first.org` |
| `PIXI_AUDIT_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

Requests time out after 30 seconds. EPSS and KEV responses are cached in the Pixi cache directory.

## Rust crates

- `pixi_audit_cli`: CLI and report rendering.
- `pixi_audit`: lock file auditing and `AuditReport` types.
- `osv_protocol`: types for OSV-compatible clients and servers.

The library enables `rattler_lock` support by default. Try the example:

```console
cargo run -p pixi_audit --example audit_lockfile -- crates/pixi_audit/examples/pixi.lock
```

## Development

```console
pixi install
pixi run check
```

`check` runs formatting, Clippy, workspace tests, and no-default-features checks. Tests use local mock servers and need no credentials.

Install the current checkout with `pixi run install`. See [RELEASING.md](RELEASING.md) for release instructions.

## License

[BSD-3-Clause](LICENSE).
