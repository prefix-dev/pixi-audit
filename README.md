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

To apply that to every finding at once, so CI only fails on what can be acted on today, use `--ignore-unfixed` or set `ignore-unfixed = true` in the manifest. Unfixed findings stay listed in the ignored section and come back the moment a fix is published.

An ignore rule that matches no finding produces a warning on stderr, so suppressions left behind after an upgrade stand out. The JSON report lists them under `unmatched_ignores`.

Record rules in the manifest with `pixi audit ignore` instead of repeating them on the command line:

```console
pixi audit ignore CVE-2026-1234 --reason "only reachable through the TLS backend, which we do not ship"
pixi audit ignore --until-fixed CVE-2026-7777
```

This appends to `ignore` or `ignore-until-fixed` in `[tool.pixi-audit]`, keeps the file's formatting, and leaves rules that are already listed alone. `--until 2026-12-01` records the last day the rule applies; after that the finding is reported again and the audit warns about the expired rule. `--package` scopes a rule to one package, or ignores every finding in it when no id is given:

```console
pixi audit ignore --package vendored-thing --reason "never runs, only shipped for its data files"
pixi audit ignore CVE-2026-1234 --package requests
```

Package names are matched under their ecosystem's rules, so `Ruamel.YAML` finds `ruamel-yaml` on PyPI. In the manifest an entry is either a bare id or a table with an `id`, a `package`, or both:

```toml
[tool.pixi-audit]
ignore = [
  "CVE-2023-0464",
  { id = "CVE-2026-1234", reason = "only reachable through the TLS backend", until = 2026-12-01 },
  { package = "vendored-thing", reason = "never runs, only shipped for its data files" },
]
```

### Set a severity threshold

Use `--severity` to fail only on findings at or above a given level:

```console
pixi audit --severity high
```

Accepted values are `low`, `medium`, `high`, and `critical`. Severity comes from the advisory's CVSS vectors, for conda-forge and PyPI packages alike. Findings without a parsable vector have unknown severity and still fail the audit.

### Rank findings by risk

Each finding carries the same threat data [grype](https://github.com/anchore/grype) reports:

- **EPSS**: the percentile rank among scored CVEs followed by the probability that the CVE is exploited within 30 days.
- **KEV**: whether the CVE is listed in CISA's Known Exploited Vulnerabilities catalog, and whether it is known to be used in ransomware campaigns.
- **Risk**: a 0-100 finding prioritization score computed as `min(threat × severity × boost, 1) × 100`. Threat is 1.0 for a KEV-listed finding and otherwise uses the highest EPSS probability among its CVEs. Severity uses an internal band weight, averaged with the mean CVSS base score when available. The boost is 1.05 for KEV entries and 1.1 for known ransomware use.

Risk orders individual findings from highest to lowest priority. The table shows EPSS with percentile first and risk columns by default. A finding in the KEV catalog reads `81.4 (kev)` in the risk column, or `(kev, ransomware)`. Sort by another column with `--sort-by`. The `risk`, `severity`, `epss`, and `kev` fields sort highest first and break ties the way grype does. Threat data never changes the exit code. Use `--severity` for that.

If a feed cannot be reached, the audit still completes. Findings are reported without that data and a warning goes to stderr.

The assessment's **CISA KEV matches** count is the number of distinct CVEs among active findings with confirmed exploitation in the wild. Repeated occurrences of the same CVE count once. A zero is shown only after the catalog loaded successfully. Otherwise the count is `n/a`.

### Update vulnerable dependencies

`--fix` raises matching direct dependency constraints to the lowest known compatible fixed version, runs `pixi update`, and audits the updated lock file again:

```console
pixi audit --fix
```

Existing upper bounds are preserved. Transitive dependencies and Git, path, or URL dependencies without a version are left alone. `pixi update` only runs when at least one finding has a fixed release in its own ecosystem. Fixes that exist only upstream are reported but cannot be installed.

When vulnerabilities are found, human-readable reports include an assessment of the highest finding prioritization score, CISA KEV matches, critical or high findings, and fix availability. Every human-readable report ends with a next-steps section tailored to its results. It prioritizes KEV matches, identifies candidate updates, distinguishes upstream-only fixes from findings with no known fix, and calls out unchecked packages. After `--fix`, it reports remaining work without recommending another blind attempt.

### Choose an output format

The default report puts packages from unsupported sources first, then shows a short status block followed by one row per finding:

```console
 Unchecked (1) — no vulnerability database for these sources

    Name      Version  Source    Environments
 C  samtools  1.19     bioconda  default

 ✔ Audited pixi.lock                 [312 packages audited, 1 unchecked]
 ✔ Scanned for vulnerabilities       [3 vulnerability matches]
   ├── by severity: 1 critical, 0 high, 1 medium, 0 low, 1 unknown
   └── by status:   2 fixed, 1 not-fixed, 0 ignored

    Name      Version  Fixed in  Vulnerability        Severity  EPSS         Risk  Environments
 C  openssl   3.1.0    3.1.1     CVE-2023-0464        Critical  88th · 3.7%  3.5   default, prod
 C  openssl   3.1.0              CVE-2023-2975        Medium    47th · 0.6%  0.3   default, prod
 P  requests  2.32.0   2.32.4    GHSA-9hjg-9r4m-mvj7  Medium    57th · 0.9%  0.5   default

 ✖ 3 vulnerabilities in 2 package(s) (312 audited, 0 ignored, 1 unchecked)

 Assessment
   • Highest finding prioritization score:  3.5 / 100
   • CISA KEV matches:                      0 CVEs
   • Critical/high findings:                1
   • Fix available in audited ecosystem:    2 of 3 vulnerabilities across 2 audited packages
   • Fix only upstream:                     0 vulnerabilities
   • No known fix:                          1 vulnerability

 Next steps
   • Re-run this audit with `--fix` to ask pixi to update 2 package names. Fixed releases in the audited ecosystem are available for 2 vulnerabilities.
   • 1 vulnerability has no known fix. Remove, replace, or mitigate the affected dependencies. Use `pixi audit ignore <ID> --until-fixed` only after accepting the risk.
   • Review 1 unchecked package. Its source is not covered by the configured vulnerability databases.

 Add `--explain` for scoring and report definitions.
```

As in `pixi lock`, a green `C` marks a conda package and a blue `P` a PyPI package. Without colors the marker reads `(conda)` or `(pypi)`. The marker has its own column, so names stay aligned, and rows that repeat the package above are dimmed. Rows are sorted by risk. `--sort-by` picks another column, and `--fields` picks which columns to show and in what order, as in `pixi list`:

```console
pixi audit --sort-by name --fields name,version,vulnerability,fixed-in,url
```

Available fields are `name`, `version`, `fixed-in`, `kind`, `source`, `vulnerability`, `severity`, `epss`, `risk`, `kev`, `environments`, `aliases`, `summary`, `url`, `ignored`, and `match`. Kind and source are off by default: the `C`/`P` marker already tells conda-forge and PyPI apart, and those are the only sources that are audited today. Unchecked packages keep a Source column, since the channel is what explains why they were skipped. An empty *Fixed in* cell means no fixed release is known. When a fix exists but not as a release in the audited ecosystem, the cell says where: `PyPI: 1.2.3` names the ecosystem that has it, `upstream: 1.2.3` means the project released it but conda-forge has no build yet, and `upstream: 1.2.3 (unconfirmed)` means basilisk could not tell whether conda-forge has a build. In JSON these appear under `upstream_fixes`, each with its `origin`.

A fix in another ecosystem is only reported when it belongs to the package Basilisk matched: the entry whose package URL Basilisk recorded as the matched identity. An advisory matched through a CPE name never contributes fixes from other ecosystems, so conda-forge `libpq` does not inherit a fix from the npm package of the same name. Documents without a matched identity fall back to matching by name, but only when Basilisk evaluated the affected versions.

Not every match is equally certain. Basilisk records how far it got as the finding's *applicability*: `evaluated` means the affected versions were checked against the package, `unevaluated` means they were not, and `version-unbounded` means the advisory names the product without version bounds, so every version matches. The default table marks the last two with a dim `(unevaluated)` or `(unbounded)` after the advisory ID and counts them at the end of the `by status` line. The `match` field shows the applicability as a column of its own, and `--sort-by match` puts the most confident matches first. The grouped format, GitHub annotations, and SARIF result messages add a `match: version unbounded` or `match: unevaluated` note, and each SARIF rule lists the applicability and matched identity in its help text. In JSON each finding carries `applicability` (`unspecified` for PyPI findings and documents without Basilisk metadata) and `matched_identity`, an object with `kind` (`purl` or `cpe`) and `value`, or `null` when Basilisk recorded none.

On a terminal the table is colored and advisory IDs link to their advisory pages. When stdout is piped or `NO_COLOR` is set, the same table is written as plain text at full width, so nothing is clipped in logs. Set `CLICOLOR_FORCE=1` to keep colors in CI logs that render them.

Add `--explain` to the table or grouped format for a context-aware explanation of the terms present in that report:

```console
pixi audit --explain
pixi audit --format grouped --explain
```

Compact human-readable reports include a short `--explain` hint. With the option enabled, a context-aware **How this report works** section follows **Next steps**. It presents short, aligned definitions under Counts, Threat signals, Prioritization, Fixes, and Coverage. Terms use a separate color from their definitions, and Formula is nested under Risk. `--explain` is rejected with JSON and SARIF so machine-readable output stays unchanged.

`--format grouped` prints findings grouped per package instead, and `--format json` (or `--json`) writes the report as pretty-printed JSON:

```console
pixi audit --json > audit-report.json
```

Progress and diagnostics go to stderr. The report goes to stdout, so redirecting or piping JSON is safe.

`--format sarif` writes a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log with one rule per vulnerability and package and one result per finding, located at the package's line in `pixi.lock` with the path relative to the repository root. Ignored findings are included as suppressed results. GitHub code scanning derives its severity label from the CVSS score in each rule:

```yaml
- run: pixi audit --format sarif > pixi-audit.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pixi-audit.sarif
```

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
- `https://api.first.org` for EPSS scores
- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` for the KEV catalog

Override them with `PIXI_AUDIT_BASE_URL`, `PIXI_AUDIT_PYPI_BASE_URL`, `PIXI_AUDIT_EPSS_BASE_URL`, and `PIXI_AUDIT_KEV_URL` respectively. Each HTTP request has a 30-second timeout.

EPSS and KEV responses are cached under `pixi-audit/http-cache` in the pixi cache directory (`PIXI_CACHE_DIR`, else `RATTLER_CACHE_DIR`, else `rattler/cache` in the platform's cache directory), so the KEV catalog is revalidated instead of downloaded again on every run.

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
