# pixi-audit

Rust crates for checking packages in a `pixi.lock` file against an
[OSV](https://ossf.github.io/osv-schema/)-compatible vulnerability database.
By default, audits use [basilisk](https://github.com/prefix-dev/basilisk),
prefix.dev's conda-forge vulnerability database.

## Try it

Run the example against the included lock file:

```shell
cargo run -p pixi_audit --example audit_lockfile -- \
  crates/pixi_audit/examples/pixi.lock | jq .
```

The report is written to stdout as JSON. Progress goes to stderr, so it is safe
to pipe the output. To use another OSV-compatible API:

```shell
PIXI_AUDIT_BASE_URL=https://example.com \
  cargo run -p pixi_audit --example audit_lockfile -- path/to/pixi.lock
```

## Crates

### `pixi_audit`

The audit client and report model. Its main entry points are:

- `audit_lock_file` to audit a `rattler_lock::LockFile`
- `collect_packages` to inspect and filter lock-file packages
- `audit` to audit an explicit list of packages
- `BasiliskClient` for batched OSV queries and vulnerability details

The default `lock` feature enables `pixi.lock` support through `rattler_lock`.
Disable default features if you only need the client and report types.

### `osv_protocol`

Serde types for OSV queries, batch responses, and vulnerability documents. The
ecosystem is stored as a `String`, so the types also support ecosystems such as
`conda-forge` that are not covered by the upstream `osv` crate's enum.

## Audit behavior

- Packages are deduplicated across selected environments and platforms.
- Basilisk currently audits conda-forge packages. Unsupported ecosystems and
  packages without a known version are listed as unchecked.
- Withdrawn advisories are skipped. Vulnerability IDs and aliases can be
  ignored explicitly.
- Severity is derived from CVSS v2, v3, or v4 data.
- Fixed versions from the audited ecosystem are kept separate from upstream
  fixes.
- A failed vulnerability detail request fails the audit. A missing detail
  document is kept as a finding with unknown severity.

## Development

```shell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p pixi_audit --no-default-features
```

Tests use local mock servers and do not need network access or credentials.

## Origin

These crates were extracted from the
[pixi audit work](https://github.com/prefix-dev/pixi/pull/6682) so the audit
library can be developed independently from the pixi CLI.
