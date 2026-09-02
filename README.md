# pixi-audit

`pixi-audit` checks the packages in a [`pixi.lock`](https://pixi.sh/latest/workspace/lockfile/) for known vulnerabilities. It audits conda-forge packages with [Basilisk](https://github.com/prefix-dev/basilisk) and PyPI packages with [OSV](https://osv.dev).

It works as both a `pixi audit` extension and a standalone CLI.

## Install

From a local checkout, Pixi can build and install the extension directly:

```console
pixi global install --path .
```

Or install it with Cargo:

```console
cargo install --path crates/pixi_audit_cli --locked
```

Both commands install `pixi-audit`. Pixi discovers executables named `pixi-<command>` as extensions, so these are equivalent:

```console
pixi audit --help
pixi-audit --help
```

## Use

Run the command inside a Pixi workspace to discover its manifest and lock file:

```console
pixi audit
```

You can also pass a lock file explicitly:

```console
pixi audit path/to/pixi.lock
```

Filter by environment or platform when a lock file contains more than you want to check:

```console
pixi audit \
  --environment production \
  --platform linux-64
```

Unknown environment and platform names are errors. A typo should not produce an empty, clean-looking audit.

### Ignore known findings

Ignore an advisory by its vulnerability ID or one of its aliases:

```console
pixi audit --ignore CVE-2026-1234
```

Ignored findings stay visible in the report. If you only want to ignore an advisory until a fix exists, use:

```console
pixi audit --ignore-until-fixed CVE-2026-7777
```

The finding returns as soon as either an ecosystem-specific or upstream fix is known.

### Set a severity threshold

Use `--severity` to fail only on conda findings at or above a given level:

```console
pixi audit --severity high
```

Accepted values are `low`, `medium`, `high`, and `critical`. Findings with unknown severity still fail the audit. The threshold does not apply to PyPI findings, which are currently reported with unknown severity.

### Update vulnerable dependencies

`--fix` raises matching direct dependency constraints to the lowest known compatible fixed version, runs `pixi update`, and audits the updated lock file again:

```console
pixi audit --fix
```

Existing upper bounds are preserved. Transitive dependencies and Git, path, or URL dependencies without a version are left alone. `pixi update` only runs when at least one finding has a fixed release in its own ecosystem. Fixes that exist only upstream are reported but cannot be installed.

### Write JSON

```console
pixi audit --json > audit-report.json
```

Progress and diagnostics go to stderr. The report goes to stdout, so redirecting or piping JSON is safe.

## Configuration

Keep recurring audit settings in the workspace manifest:

```toml
[tool.pixi-audit]
ignore = ["CVE-2023-0464"]
ignore-until-fixed = ["CVE-2026-7777"]
severity = "high"
```

Command-line ignore lists are combined with the manifest values. A command-line severity overrides the configured value.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The audit completed without actionable vulnerabilities |
| `1` | The audit found actionable vulnerabilities |
| `2` | The audit could not run |

## Coverage

Packages are deduplicated across the selected environments and platforms. Withdrawn advisories are skipped.

Conda-forge packages are checked against Basilisk. PyPI packages are checked directly against OSV. Packages from bioconda, custom channels, and source dependencies are reported as unchecked instead of being treated as safe.

The default endpoints are:

- `https://api.basilisk.prefix.dev` for conda-forge packages
- `https://api.osv.dev` for PyPI packages

Override them with `PIXI_AUDIT_BASE_URL` and `PIXI_AUDIT_PYPI_BASE_URL` respectively. Each HTTP request has a 30-second timeout.

## Rust crates

The workspace contains three crates:

- `pixi_audit_cli` provides the `pixi-audit` executable and report rendering.
- `pixi_audit` reads lock files, queries the audit services, and builds an `AuditReport`.
- `osv_protocol` contains serializable types for OSV-compatible clients and servers.

The `pixi_audit` crate enables `rattler_lock` support by default. To try it with the included example lock file:

```console
cargo run -p pixi_audit --example audit_lockfile -- \
  crates/pixi_audit/examples/pixi.lock
```

## Development

Pixi installs the pinned Rust toolchain and the compilers needed by `pixi-build-rust`:

```console
pixi install
pixi run check
```

`pixi run check` runs formatting, Clippy, the workspace tests, and the no-default-features checks from CI. Tests use local mock HTTP servers and do not need credentials.

Install the current checkout with Cargo through the Pixi environment using:

```console
pixi run install
```

Release automation and trusted-publisher setup are documented in [RELEASING.md](RELEASING.md).

## License

BSD-3-Clause. See [LICENSE](LICENSE).
