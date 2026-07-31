# pixi-audit

Audit packages in a [`pixi.lock`](https://pixi.sh/latest/workspace/lockfile/) file for known vulnerabilities.

`pixi-audit` queries [basilisk](https://github.com/prefix-dev/basilisk), prefix.dev's OSV-compatible vulnerability database, and reports affected packages, severity, available fixes, and packages that could not be checked. It can be used as either a `pixi audit` extension or a Rust library.

> [!NOTE]
> The default service currently audits packages from conda-forge. Packages from PyPI, bioconda, custom channels, and source dependencies are listed as unchecked rather than silently treated as safe.

## Install

Install the CLI from a checkout:

```console
$ cargo install --path crates/pixi_audit_cli
```

Cargo places the `pixi-audit` executable on `PATH`. pixi discovers executables named `pixi-<command>` as extensions, so both forms work:

```console
$ pixi audit pixi.lock
$ pixi-audit pixi.lock
```

## Usage

Audit every environment and platform in a lock file:

```console
$ pixi audit pixi.lock
```

Limit the audit to one or more environments or platforms:

```console
$ pixi audit pixi.lock \
    --environment default \
    --environment production \
    --platform linux-64
```

Ignore an advisory by its vulnerability ID or any alias. Matching is case-insensitive, and ignored findings remain visible in the report:

```console
$ pixi audit pixi.lock --ignore CVE-2026-1234 --ignore GHSA-xxxx-yyyy-zzzz
```

Emit the complete report as JSON:

```console
$ pixi audit pixi.lock --json > audit-report.json
```

### Options

```text
Usage: pixi-audit [OPTIONS] <LOCKFILE>

Arguments:
  <LOCKFILE>  Path to the pixi.lock file to audit

Options:
      --environment <ENV>       Audit only this environment (repeatable)
      --platform <PLATFORM>     Audit only this platform (repeatable)
      --ignore <ID>             Vulnerability ID or alias to ignore (repeatable)
      --json                    Emit pretty-printed JSON on stdout
  -h, --help                    Print help
  -V, --version                 Print version
```

Unknown environment and platform names are errors. This prevents a typo from producing an empty, clean-looking audit.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Audit completed with no non-ignored vulnerabilities |
| `1` | Audit completed and found vulnerabilities |
| `2` | The audit could not run, for example because of an invalid lock file, filter, or API response |

Progress and diagnostics are written to stderr. Human-readable or JSON results are written to stdout, so `--json` can be safely piped to another command. Each HTTP request has a 30-second timeout.

### API endpoint

The default endpoint is `https://api.basilisk.prefix.dev`. Override it for a self-hosted OSV-compatible service with `PIXI_AUDIT_BASE_URL`:

```console
$ PIXI_AUDIT_BASE_URL=https://audit.example.com pixi audit pixi.lock
```

The service must implement `POST /v1/querybatch` and `GET /v1/vulns/{id}`.

## Audit behavior

- Packages are deduplicated across the selected environments and platforms.
- Withdrawn advisories are skipped.
- Severity is derived from CVSS v2, v3, or v4 data.
- A failed vulnerability detail request fails the audit. A missing detail document is kept as a finding with unknown severity.

## Rust crates

This workspace contains three crates:

- **`pixi_audit_cli`** provides the `pixi-audit` executable and human-readable report renderer.
- **`pixi_audit`** collects packages from lock files, queries the vulnerability API, applies ignore rules, classifies CVSS v2/v3/v4 severity, and builds an `AuditReport`. Its default `lock` feature enables `rattler_lock` integration.
- **`osv_protocol`** provides serializable request, response, and vulnerability-document types for OSV-compatible clients and servers. Ecosystem names are represented as strings, allowing values such as `conda-forge` that are not enumerated by the upstream `osv` crate.

Try the library against the included example lock file:

```console
$ cargo run -p pixi_audit --example audit_lockfile -- \
    crates/pixi_audit/examples/pixi.lock | jq .
```

## Development

The workspace requires Rust 1.90 or newer. Run the same checks as CI with:

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo test --workspace
$ cargo test --workspace --all-features
$ cargo check --workspace --no-default-features --all-targets
$ cargo test -p pixi_audit --no-default-features
```

Tests use in-process mock HTTP servers and require no network access or credentials.

## Migration notes

The crates were extracted from `prefix-dev/pixi#6682`. Compared with the original `audit-command` branch:

- `AuditPackage.version` and `UncheckedPackage.version` are optional. Packages without a known version are not queried and are reported as unchecked.
- `Finding.fixed_versions` contains fixes from the package's own ecosystem; fixes published only in another ecosystem are in `upstream_fixed_versions`.
- `AuditError::Status` includes the API's error message when available.
- Lock-file collection is available through `pixi_audit::lock::collect_packages`, and channel classification through `PackageEcosystem::from_channel_url`.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
