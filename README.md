# pixi-audit

Audit [Pixi](https://pixi.sh) lock files for known vulnerabilities. `pixi-audit` checks conda-forge packages with [Basilisk](https://github.com/prefix-dev/basilisk) and PyPI packages with [OSV](https://osv.dev).

It runs as a `pixi audit` extension or a standalone `pixi-audit` command. Packages from other channels and source dependencies are reported as unchecked.

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

Update vulnerable dependencies and audit again:

```console
pixi audit --fix
```

This raises direct dependency constraints to known fixed versions and runs `pixi update`, preserving existing upper bounds. It does not rewrite transitive dependency constraints.

### Ignore findings

Ignore an advisory for one run, or save a rule in the workspace manifest:

```console
pixi audit --ignore CVE-2023-0464
pixi audit ignore CVE-2023-0464 --reason "Not affected in this deployment"
```

Use `--ignore-until-fixed <ID>` to ignore a finding until a fix is known, or `--ignore-unfixed` to ignore all findings without a known fix. Ignored findings remain in the report.

See `pixi audit ignore --help` for rules scoped by package, ecosystem, version, or expiry date.

### Reports

The default table sorts findings by risk, using severity, EPSS scores, and CISA's Known Exploited Vulnerabilities catalog. Use `--explain` for report and scoring definitions.

Other output formats:

```console
pixi audit --format grouped
pixi audit --json > audit-report.json
pixi audit --format sarif > pixi-audit.sarif
```

Reports go to stdout; progress and diagnostics go to stderr. In GitHub Actions, findings also appear as workflow annotations.

Run `pixi audit --help` for all options.

## Configuration

Store recurring settings in `pixi.toml` or `pyproject.toml`:

```toml
[tool.pixi-audit]
severity = "high"
ignore = [
  { id = "CVE-2023-0464", reason = "Not affected in this deployment", until = "2026-12-01" },
]
```

Severity can be `low`, `medium`, `high`, or `critical`. Findings with unknown severity still fail the audit. Command-line severity overrides the manifest; ignore lists are combined.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | No actionable vulnerabilities |
| `1` | Actionable vulnerabilities found |
| `2` | The audit could not run |

## Development

```console
pixi install
pixi run check
```

`check` runs formatting, Clippy, workspace tests, and no-default-features checks. Tests use local mock servers and need no credentials.

Install the current checkout with `pixi run install`. See [RELEASING.md](RELEASING.md) for release instructions.

## License

[BSD-3-Clause](LICENSE).
