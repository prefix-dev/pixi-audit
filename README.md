# pixi-audit

Library crates for auditing locked packages against an OSV-compatible
vulnerability database (such as [basilisk](https://github.com/prefix-dev/basilisk),
prefix.dev's conda-forge vulnerability database).

## Crates

- **`osv_protocol`** — serde types for the OSV wire format: `POST /v1/querybatch`
  queries and responses, and OSV vulnerability documents (including
  `schema_version`, `published`, `withdrawn`, `details`, and
  `database_specific` payloads as emitted by basilisk). Unlike the upstream
  `osv` crate, the ecosystem is an open `String`, so ecosystems the OSV schema
  doesn't enumerate (e.g. `conda-forge`) are representable. All types are
  bidirectional (`Serialize` + `Deserialize`) with compact serialization
  (absent options and empty arrays are omitted), so the same crate serves both
  OSV clients and OSV-compatible servers. Depends only on `serde`/`serde_json`.

- **`pixi_audit`** — the client side used by `pixi audit`:
  - `BasiliskClient`: batched `POST /v1/querybatch` (chunks of ≤1000,
    order-preserving, defensive pagination cap) and concurrent
    `GET /v1/vulns/{id}` detail fetches. Server error bodies
    (`{"error": "..."}`) are surfaced in error messages.
  - `lock` module (default-on `lock` feature, via `rattler_lock`):
    `collect_packages` deduplicates a `pixi.lock` file's packages across
    environments/platforms with optional filters, and `audit_lock_file`
    composes collection with the audit — lock file in, report out.
  - Audit orchestration: CVSS v2/v3/v4 severity bands (critical ≥9.0,
    high ≥7.0, medium ≥4.0; v2 caps at high), withdrawn advisories skipped,
    ignore-list matching by vulnerability id or alias, ecosystem-aware
    fixed-version extraction (upstream fixes reported separately), packages
    without a known version reported as unchecked instead of queried, and an
    `AuditReport` ready for rendering.

## Development

```shell
cargo test
cargo clippy --all-targets
```

The test suite runs entirely against in-process mock HTTP servers; no network
access or credentials are required.

## Breaking changes vs the pixi `audit-command` branch

The crates were extracted from prefix-dev/pixi#6682; consumers written
against that branch need three adjustments:

- `AuditPackage.version` is now `Option<String>` (`None` = version unknown;
  such packages are reported unchecked instead of queried), and
  `UncheckedPackage.version` is optional and omitted from JSON when absent.
- `Finding` gained `upstream_fixed_versions`; `fixed_versions` now only
  contains fixes from the package's own ecosystem.
- `AuditError::Status` gained a `message` field, and the lock-file collection
  previously in the pixi CLI (`collect_packages`, `classify_channel`) now
  lives here as `pixi_audit::lock::collect_packages` and
  `PackageEcosystem::from_channel_url`.

## Origin

Extracted from the [pixi](https://github.com/prefix-dev/pixi) repository
(branch `pixi-audit-crates`, prefix-dev/pixi#6682) to develop the audit
library independently of the pixi CLI.
