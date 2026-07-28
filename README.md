# pixi-audit

Library crates for auditing locked packages against an OSV-compatible
vulnerability database (such as [basilisk](https://github.com/prefix-dev/basilisk),
prefix.dev's conda-forge vulnerability database).

## Crates

- **`osv_protocol`** — serde types for the OSV wire format: `POST /v1/querybatch`
  queries and responses, and OSV vulnerability documents. Unlike the upstream
  `osv` crate, the ecosystem is an open `String`, so ecosystems the OSV schema
  doesn't enumerate (e.g. `conda-forge`) are representable. All types are
  bidirectional (`Serialize` + `Deserialize`) with compact serialization
  (absent options and empty arrays are omitted), so the same crate serves both
  OSV clients and OSV-compatible servers. Depends only on `serde`.

- **`pixi_audit`** — the client side used by `pixi audit`:
  - `BasiliskClient`: batched `POST /v1/querybatch` (chunks of ≤1000,
    order-preserving, defensive pagination cap) and concurrent
    `GET /v1/vulns/{id}` detail fetches.
  - Audit orchestration: CVSS severity bands (critical ≥9.0, high ≥7.0,
    medium ≥4.0), ignore-list matching by vulnerability id or alias,
    fixed-version extraction, and an `AuditReport` ready for rendering.

## Development

```shell
cargo test
cargo clippy --all-targets
```

The test suite runs entirely against in-process mock HTTP servers; no network
access or credentials are required.

## Origin

Extracted from the [pixi](https://github.com/prefix-dev/pixi) repository
(branch `pixi-audit-crates`, prefix-dev/pixi#6682) to develop the audit
library independently of the pixi CLI.
