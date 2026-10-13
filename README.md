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

### Authenticate in CI with a Basilisk API token

```yaml
# GitHub Actions
- run: pixi-audit
  env:
    PIXI_AUDIT_TOKEN: ${{ secrets.BASILISK_API_TOKEN }}
```

### Ignore known vulnerability matches

Ignore an advisory by ID or alias for one run:

```console
pixi audit --ignore CVE-2023-0464
```

Ignore a vulnerability match until a fix is known, or ignore all vulnerability matches without a known fix:

```console
pixi audit --ignore-until-fixed CVE-2023-0464
pixi audit --ignore-unfixed
```

These vulnerability matches return when a fix becomes known in the package's ecosystem, another ecosystem, or an upstream release. Ignored vulnerability matches remain in the report.

Save rules in the workspace manifest:

```console
pixi audit ignore CVE-2023-0464 --reason "Not affected in this deployment"
pixi audit ignore CVE-2023-0464 --until-fixed
pixi audit ignore CVE-2023-0464 --expired-at 2026-12-01
```

Limit a rule to a package, ecosystem, or installed version:

```console
pixi audit ignore CVE-2023-0464 --package openssl
pixi audit ignore CVE-2023-0464 --package openssl --ecosystem conda-forge --version 3.1.0
```

Use `--up-to-version` instead of `--version` to match versions up to a limit. Ecosystems are `conda-forge` and `PyPI`.

Omit the ID to ignore all vulnerability matches for a package:

```console
pixi audit ignore --package vendored-thing --reason "Only used for its data files"
```

Expired rules and rules that match no vulnerabilities produce warnings.

### Set a severity threshold

Fail only on vulnerability matches at or above a severity rating:

```console
pixi audit --fail-on high
```

Ratings are `low`, `medium`, `high`, and `critical`. Vulnerability matches with unknown severity still fail the audit.

Report an ecosystem's vulnerability matches without letting them fail the audit:

```console
pixi audit --warn-only-ecosystem conda-forge
```

### Rank vulnerability matches by risk

The default table sorts by risk, combining severity, [EPSS](https://www.first.org/epss/) exploitation probability, and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) data. Risk affects ordering, not exit codes.

Sort by another column or explain the scores:

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

This raises direct dependency constraints to known compatible fixed versions and runs `pixi update`, preserving existing upper bounds. It does not rewrite transitive dependency constraints. Fixes available only elsewhere are reported but cannot be installed.

### Choose an output format

Use the default table, group vulnerability matches by package, or export JSON or SARIF:

```console
pixi audit
pixi audit --format by-package
pixi audit --json > audit-report.json
pixi audit --format sarif > pixi-audit.sarif
```

Choose table columns and their order:

```console
pixi audit --sort-by name --columns name,version,vulnerability,fixed-in,url
```

An empty *Fixed in* cell means no fix is known; fixes available only in another ecosystem or an upstream release are labeled. Add `--explain` to table or by-package output for definitions.

Reports go to stdout; progress and diagnostics go to stderr. Piped output is plain text; use `CLICOLOR_FORCE=1` to keep colors in CI logs.

Run `pixi audit --help` for all options and columns.

### Use in GitHub Actions

Vulnerability matches are emitted as workflow annotations. To upload a SARIF report to GitHub code scanning, add these steps after installing the extension:

```yaml
- run: pixi audit --format sarif > pixi-audit.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pixi-audit.sarif
```

The upload requires `security-events: write` permission. Ignored vulnerability matches are included as SARIF suppressions.

## Configuration

Store recurring settings in `pixi.toml` or `pyproject.toml`:

```toml
[tool.pixi-audit]
fail-on = "high"
ignore-unfixed = true
ignore-until-fixed = ["CVE-2026-7777"]
ignore = [
  "CVE-2023-0464",
  { id = "CVE-2026-1234", reason = "Not affected in this deployment", expired-at = "2026-12-01" },
  { package = "vendored-thing", reason = "Only used for its data files" },
]
```

Rules can also specify `ecosystem`, `version`, or `up-to-version`. Keep dates quoted. Command-line `--fail-on` overrides the manifest; ignore lists are combined.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | No vulnerability matches fail the audit |
| `1` | At least one vulnerability match fails the audit |
| `2` | The audit could not run |

## Coverage

Packages are deduplicated across selected environments and platforms. Withdrawn advisories are skipped. Packages from channels other than conda-forge and source dependencies are reported as not audited, not safe.

Override service endpoints with these environment variables:

| Variable | Default |
| --- | --- |
| `PIXI_AUDIT_BASILISK_URL` | `https://api.basilisk.prefix.dev` |
| `PIXI_AUDIT_OSV_URL` | `https://api.osv.dev` |
| `PIXI_AUDIT_EPSS_BASE_URL` | `https://api.first.org` |
| `PIXI_AUDIT_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

`PIXI_AUDIT_TOKEN`, or an API token stored for the custom host, can authenticate
against a custom `PIXI_AUDIT_BASILISK_URL`.

Requests time out after 30 seconds. EPSS and KEV responses are cached in the Pixi cache directory.

## Rust crates

- `pixi_audit_cli`: CLI and report rendering.
- `pixi_audit`: vulnerability database selection, lock file auditing, report assembly, ignore rules, risk scoring, and `AuditReport` types.
- `osv_protocol`: serializable OSV wire types, without an HTTP client.
- `osv_client`: OSV HTTP client with ordered batching, pagination, and document fetching.
- `threat_feeds`: EPSS and KEV clients, catalogs, and records, independent of audit reports.
- `pixi_audit_test_support`: shared mock services for workspace tests. Dev-only, unpublished, and never depends on `pixi_audit`.

The HTTP clients take a caller-configured `reqwest_middleware::ClientWithMiddleware` and do not choose TLS, timeouts, caching, or authentication. `BasiliskClient` and `OsvDevClient` remain distinct types in `pixi_audit`. `threat_feeds` shares the send/status/JSON path through `osv_client::http`.

Use `pixi_audit::audit` to run an audit and `pixi_audit::types` for OSV wire types. The reusable `[tool.pixi-audit]` schema, including ignore entries and expiry handling, lives in `pixi_audit::config`; the CLI owns manifest I/O and warnings. `IgnoreSpec` takes one list of parsed `IgnoreRule`s plus `ignore_unfixed`. `AuditReport::fixable_package_names()` returns distinct borrowed names with an installable fix, excluding ignored vulnerability matches and those with fixes only elsewhere.

The library enables `rattler_lock` support by default. Try the example:

```console
cargo run -p pixi_audit --example audit_lock_file -- crates/pixi_audit/examples/pixi.lock
```

## Development

```console
pixi install
pixi run check
```

`check` runs formatting, Clippy, workspace tests, and no-default-features checks. Tests use shared local mock servers and need no credentials; ignore and alias-merging tests run pure report assembly without a server.

Install the current checkout with `pixi run install`. See [RELEASING.md](RELEASING.md) for release instructions.

## License

[BSD-3-Clause](LICENSE).
