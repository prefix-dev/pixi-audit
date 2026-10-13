# pixi-audit

Audit [Pixi](https://pixi.sh) lock files for known vulnerabilities. `pixi-audit` checks conda-forge packages with [Basilisk](https://github.com/prefix-dev/basilisk) and PyPI packages with [OSV](https://osv.dev).

It runs as a `pixi audit` extension or a standalone `pixi-audit` command.

## Installation

Install the binary from [prefix-labs](https://prefix.dev/channels/@prefix-dev/prefix-labs/packages/pixi-audit) with [Pixi](https://pixi.sh):

```console
pixi global install --channel https://prefix.dev/prefix-dev/prefix-labs pixi-audit
```

Packages are available for Linux x86-64, macOS Intel and Apple Silicon, and Windows x86-64. You do not need Rust or a source checkout.

Check the installation:

```console
pixi audit --version
```

To update:

```console
pixi global update pixi-audit
```

The channel contains releases and dev builds. An unpinned install or update can select a dev build; use an exact package version, such as `pixi-audit==0.2.0`, if you need a specific release.

To run an audit without a global install:

```console
pixi exec --channel https://prefix.dev/prefix-dev/prefix-labs pixi-audit
```

## Usage

Audit the current workspace or a specific lock file:

```console
pixi audit
pixi audit path/to/pixi.lock
```

You can also run `pixi-audit` directly with the same arguments. For `pixi audit` to find the extension, the installed `pixi-audit` executable must be on your `PATH`.

Limit the audit to an environment or platform:

```console
pixi audit --environment production --platform linux-64
```

### Ignore known vulnerability matches

Ignore an advisory by ID or alias for one run:

```console
pixi audit --ignore CVE-2023-0464
```

Ignore a match until a fix is known, or ignore all matches without a known fix:

```console
pixi audit --ignore-until-fixed CVE-2023-0464
pixi audit --ignore-unfixed
```

These matches stop being ignored when a fix becomes known in the package's ecosystem, another ecosystem, or an upstream release. They remain visible in the report while ignored.

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

Omit the ID to ignore all matches for a package:

```console
pixi audit ignore --package vendored-thing --reason "Only used for its data files"
```

Expired rules and rules that match no vulnerabilities produce warnings.

### Set a severity threshold

Fail only on matches at or above a severity rating:

```console
pixi audit --fail-on high
```

Ratings are `low`, `medium`, `high`, and `critical`. Matches with unknown severity still fail the audit.

Report an ecosystem's matches without letting them fail the audit:

```console
pixi audit --warn-only-ecosystem conda-forge
```

### Rank vulnerability matches by risk

The default table sorts by risk, combining severity, [EPSS](https://www.first.org/epss/) exploitation probability, and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) data. Risk affects ordering, not exit codes.

Sort by another column or show an explanation of the scores:

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

This raises direct dependency constraints to known compatible fixed versions and runs `pixi update`, preserving existing upper bounds. It does not rewrite transitive dependency constraints. The report also lists fixes available only in another ecosystem or an upstream release, but `--fix` cannot install them.

### Choose an output format

Use the default table, group matches by package, or export JSON or SARIF:

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

An empty *Fixed in* cell means no fix is known. The report labels fixes available only in another ecosystem or an upstream release. Add `--explain` to table or by-package output for definitions.

Reports go to stdout; progress and diagnostics go to stderr. Piped output is plain text; use `CLICOLOR_FORCE=1` to keep colors in CI logs.

Run `pixi audit --help` for all options and columns.

### Use in GitHub Actions

In GitHub Actions, `pixi-audit` also reports matches as workflow annotations. To upload a SARIF report to GitHub code scanning, add these steps after checking out your workspace and installing Pixi:

```yaml
- run: pixi global install --channel https://prefix.dev/prefix-dev/prefix-labs pixi-audit
- run: pixi audit --format sarif > pixi-audit.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: pixi-audit.sarif
```

The upload requires `security-events: write` permission and, for private repositories, `contents: read`. Ignored matches are included as SARIF suppressions. The example uses `continue-on-error` so the report is uploaded even when the audit fails; it does not block the workflow on vulnerabilities.

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

The audit checks each package once across the selected environments and platforms and skips withdrawn advisories. It reports packages from channels other than conda-forge and source dependencies as not audited, not safe.

Override service endpoints with these environment variables:

| Variable | Default |
| --- | --- |
| `PIXI_AUDIT_BASILISK_URL` | `https://api.basilisk.prefix.dev` |
| `PIXI_AUDIT_OSV_URL` | `https://api.osv.dev` |
| `PIXI_AUDIT_EPSS_BASE_URL` | `https://api.first.org` |
| `PIXI_AUDIT_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

Requests time out after 30 seconds. EPSS and KEV responses are cached in the Pixi cache directory.

## Rust crates

- `pixi_audit_cli`: CLI and report rendering.
- `pixi_audit`: vulnerability database selection, lock file auditing, report assembly, ignore rules, risk scoring, and `AuditReport` types.
- `osv_protocol`: serializable OSV wire types, without an HTTP client.
- `osv_client`: OSV HTTP client with ordered batching, pagination, and document fetching.
- `threat_feeds`: EPSS and KEV clients, catalogs, and records, independent of audit reports.
- `pixi_audit_test_support`: shared mock services for workspace tests. It is unpublished, used only in development, and does not depend on `pixi_audit`.

The HTTP clients take a caller-configured `reqwest_middleware::ClientWithMiddleware`; the caller controls TLS, timeouts, caching, and authentication. `BasiliskClient` and `OsvDevClient` are distinct types in `pixi_audit`. `threat_feeds` uses `osv_client::http` to send requests, check status codes, and decode JSON.

Use `pixi_audit::audit` to run an audit and `pixi_audit::types` for OSV wire types. The `[tool.pixi-audit]` schema, including ignore entries and expiry handling, lives in `pixi_audit::config`; the CLI reads and writes manifests and reports warnings.

`IgnoreSpec` takes one list of parsed `IgnoreRule`s plus `ignore_unfixed`. `AuditReport::fixable_package_names()` returns distinct borrowed names with an installable fix, excluding ignored matches and those with fixes only elsewhere.

The library enables `rattler_lock` support by default. Try the example:

```console
cargo run -p pixi_audit --example audit_lock_file -- crates/pixi_audit/examples/pixi.lock
```

## Development

From a local checkout:

```console
pixi install
pixi run check
```

`check` runs formatting, Clippy, workspace tests, and no-default-features checks. Tests use local mock servers and need no credentials; ignore and alias-merging tests assemble reports without a server.

Build and install the checkout with Pixi:

```console
pixi global install --path .
```

Or install it with Cargo and the repository's Rust toolchain:

```console
cargo install --path crates/pixi_audit_cli --locked
```

`pixi run install` runs the same Cargo command. See [RELEASING.md](RELEASING.md) for release instructions.

## License

[BSD-3-Clause](LICENSE).
