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

An ignore rule that matches no finding produces a warning on stderr, so suppressions left behind after an upgrade stand out. The JSON report lists them under `unmatched_ignores`.

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

### Choose an output format

The default report is a short status block followed by one row per finding:

```console
 ✔ Audited pixi.lock                 [312 packages audited, 1 unchecked]
 ✔ Scanned for vulnerabilities       [3 vulnerability matches]
   ├── by severity: 1 critical, 0 high, 1 medium, 0 low, 1 unknown
   └── by status:   2 fixed, 1 not-fixed, 0 ignored

 Name        Version  Fixed in  Vulnerability        Severity  Environments
 C openssl   3.1.0    3.1.1     CVE-2023-0464        Critical  default, prod
 C openssl   3.1.0              CVE-2023-2975        Medium    default, prod
 P requests  2.32.0   2.32.4    GHSA-9hjg-9r4m-mvj7  Unknown   default
```

As in `pixi lock`, a green `C` marks a conda package and a blue `P` a PyPI package; without colors the marker reads `(conda)` or `(pypi)`. Rows are sorted most severe first. `--sort-by` picks another column, and `--fields` picks which columns to show and in what order, as in `pixi list`:

```console
pixi audit --sort-by name --fields name,version,vulnerability,fixed-in,url
```

Available fields are `name`, `version`, `fixed-in`, `kind`, `source`, `vulnerability`, `severity`, `environments`, `aliases`, `summary`, `url`, and `ignored`. Kind and source are off by default: the `C`/`P` marker already tells conda-forge and PyPI apart, and those are the only sources that are audited today. Unchecked packages keep a Source column, since the channel is what explains why they were skipped. An empty *Fixed in* cell means no fixed release is known. When a fix exists but not as a release in the audited ecosystem, the cell says where: `PyPI: 1.2.3` names the ecosystem that has it, `upstream: 1.2.3` means the project released it but conda-forge has no build yet, and `upstream: 1.2.3 (unconfirmed)` means basilisk could not tell whether conda-forge has a build. In JSON these appear under `upstream_fixes`, each with its `origin`.

On a terminal the table is colored and advisory IDs link to their advisory pages. When stdout is piped or `NO_COLOR` is set, the same table is written as plain text at full width, so nothing is clipped in logs. Set `CLICOLOR_FORCE=1` to keep colors in CI logs that render them.

`--format grouped` prints findings grouped per package instead, and `--format json` (or `--json`) writes the report as pretty-printed JSON:

```console
pixi audit --json > audit-report.json
```

Progress and diagnostics go to stderr. The report goes to stdout, so redirecting or piping JSON is safe.

### Continuous integration

Inside GitHub Actions, every finding is also emitted as a [workflow command](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions) on stderr, so vulnerabilities show up as annotations on the job and on the pull request. They are errors when the audit fails and warnings when every finding sits below the `--severity` threshold.

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
