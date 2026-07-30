# pixi-audit uv-parity features — design

Date: 2026-07-30
Status: approved

## Goal

Close the main feature gaps between `pixi audit` and `uv audit` in one PR:

1. config-file support (`[tool.pixi-audit]`)
2. `--ignore-until-fixed`
3. `--severity` threshold
4. `--fix` mode
5. default lockfile discovery (optional `LOCKFILE` positional)

Builds on the `pixi_audit_cli` crate from PR #3. Branch
`feat/pixi-audit-uv-parity` off `feat/pixi-audit-cli`; the PR targets
`feat/pixi-audit-cli` (retarget to `main` when #3 merges).

## Architecture

Semantics live in the library, orchestration in the CLI:

- `crates/pixi_audit` (library): `--ignore-until-fixed` categorization —
  it changes which bucket a finding lands in, and pixi itself will want
  identical semantics when it consumes the crate.
- `crates/pixi_audit_cli`: two new modules plus `main.rs` growth —
  - `config.rs` — workspace/manifest discovery and `[tool.pixi-audit]`
    parsing
  - `fix.rs` — `pixi update` orchestration and post-fix re-audit
  - `main.rs` — new flags, severity gating, wiring
  - `render.rs` — ignored-reason markers, below-threshold note

Breaking changes to the unreleased `pixi_audit` 0.1 API are fine.

## CLI surface (new/changed)

```
pixi-audit [LOCKFILE] [OPTIONS]

Arguments:
  [LOCKFILE]  Path to the pixi.lock file to audit. When omitted, walk up
              from the current directory to find a workspace (see
              Discovery).

Options (added to the existing set):
      --ignore-until-fixed <ID>  Suppress this vulnerability id/alias only
                                 while no fixed release is known
                                 (repeatable, case-insensitive)
      --severity <BAND>          Fail (exit 1) only for findings at or
                                 above this band: low|medium|high|critical
      --fix                      Re-lock vulnerable packages via
                                 `pixi update` and re-audit
```

## Discovery

When `LOCKFILE` is omitted: starting at the current directory and walking
up parents, find the first directory containing a workspace manifest —
`pixi.toml`, or `pyproject.toml` whose TOML contains a `[tool.pixi]`
table. That directory is the workspace root; the lockfile is its
`pixi.lock`. Errors (exit 2):

- no workspace manifest found up to the filesystem root: "no pixi
  workspace found; pass a lockfile path or run inside a pixi workspace"
- manifest found but no `pixi.lock` beside it: "workspace at <dir> has no
  pixi.lock; run `pixi lock` first"

An explicit `LOCKFILE` skips discovery for the lockfile, but config (and
`--fix`) still use the manifest **next to the given lockfile** if one
exists there — never a manifest from an unrelated cwd.

## Config file

`config.rs` reads the `[tool.pixi-audit]` table from the workspace
manifest (either kind). Recognized keys:

```toml
[tool.pixi-audit]
ignore = ["CVE-2023-0464"]              # array of id/alias strings
ignore-until-fixed = ["CVE-2025-15467"] # array of id/alias strings
severity = "high"                       # low|medium|high|critical
```

Precedence and merging:

- `ignore` and `ignore-until-fixed`: union of config values and CLI flags.
- `severity`: CLI flag overrides the config value; config applies
  otherwise; absent both, no threshold (any vulnerability fails).
- Unrecognized keys inside `[tool.pixi-audit]` produce a stderr warning
  naming the key (typo safety without breaking forward compatibility).
- Missing manifest, missing table, or an explicit lockfile with no
  sibling manifest: empty config, no error. A present-but-invalid table
  (wrong types, bad band string, TOML parse error) is an error (exit 2) —
  a security tool must not silently drop configured suppressions.

Parsing uses the `toml` crate with serde.

## `--ignore-until-fixed` (library)

`audit()` and `audit_lock_file()` change their ignore parameters to:

```rust
pub struct IgnoreSpec<'a> {
    /// Always suppress (existing behavior).
    pub ignore: &'a [String],
    /// Suppress only while no fix is known.
    pub ignore_until_fixed: &'a [String],
}
```

Matching is the existing rule: case-insensitive against the finding's id
and aliases. Categorization for a finding matching `ignore_until_fixed`:

- no known fix — `fixed_versions` AND `upstream_fixed_versions` both
  empty — → ignored bucket
- any known fix (own-ecosystem or upstream) → stays in `vulnerabilities`
  (the loud side: a finding may resurface slightly before a conda build
  of the upstream fix exists)

`ignore` always wins if an id appears in both lists.

`Finding` gains:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub ignore_reason: Option<IgnoreReason>, // enum: Always | UntilFixed
```

serialized kebab-case (`"always"` / `"until-fixed"`), set only on
findings in the ignored bucket. The renderer suffixes until-fixed entries
in the ignored section with `(until a fix is released)`.

## `--severity` (CLI)

Exit-code gating only — the report is never filtered:

- band order for the threshold: low < medium < high < critical, compared
  with `>=`. `Unknown` severity sits outside the order and **always
  counts as at-or-above** any threshold (fail-safe: an unscored advisory
  must not slip under a threshold).
- exit 1 iff any finding in `vulnerabilities` is at/above the threshold
  (or is Unknown); otherwise exit 0 with a stderr note:
  `note: 3 vulnerabilities found below the 'high' severity threshold`.
- rendering and `--json` output are unchanged (full report always).
- The `error: audit found vulnerabilities` stderr trailer appears only
  when exiting 1.

## `--fix` (CLI)

Flow in `fix.rs`:

1. Run the normal audit.
2. Collect the distinct package names from `vulnerabilities` (non-ignored
   findings only). If empty, behave exactly like a non-fix run.
3. Require a workspace manifest next to the lockfile; else exit 2:
   "--fix requires a pixi workspace (no pixi.toml/pyproject.toml next to
   <lockfile>)".
4. Run `pixi update --manifest-path <manifest> <name>...` as a
   subprocess (`pixi` from `PATH`; stdout/stderr stream to our stderr).
   Missing `pixi` binary or non-zero exit → exit 2 with the underlying
   error.
5. Reload the lockfile, re-audit with the same filters/ignores.
6. Render the post-fix report (human or `--json` — the JSON document is
   the post-fix `AuditReport`), preceded on stderr by a summary line:
   `fixed: resolved N of M vulnerabilities via pixi update`.
7. Exit code comes from the post-fix report (same severity gating).

`--fix` never edits the manifest; it re-locks within existing manifest
constraints. Findings that survive (manifest pins a vulnerable range, or
no fixed conda build exists) simply remain in the post-fix report.

## Error handling

All new failure modes are miette diagnostics exiting 2: discovery
failures, invalid `[tool.pixi-audit]` table, invalid `--severity` value
(clap `value_parser` rejects it at parse time, exit 2), missing pixi
binary, failed `pixi update`, unreadable post-fix lockfile.

## Testing

- Library unit tests: until-fixed categorization (no fix → ignored with
  `ignore_reason: "until-fixed"`; own-ecosystem fix → vulnerable;
  upstream-only fix → vulnerable; id in both lists → `always` wins),
  JSON field shape.
- `config.rs` unit tests: `pixi.toml` and `pyproject.toml` variants,
  missing file/table, union and override precedence, unknown-key warning,
  invalid table errors.
- Discovery tests in a temp directory tree (nested cwd → workspace root;
  no workspace → error; manifest without lockfile → error).
- CLI integration tests (existing axum mock): severity gating exit codes
  (high finding × `--severity critical` → 0 with note; × `--severity
  high` → 1), `--ignore-until-fixed` end-to-end for both fix-known and
  fix-unknown advisories, config-file-driven run (write manifest into a
  temp workspace), discovery-driven bare invocation (cwd inside temp
  workspace).
- `--fix` integration test: fake `pixi` executable (shell script
  prepended to `PATH`) that records its argv and swaps in a "fixed"
  lockfile; mock API marks the old version vulnerable and the new one
  clean; asserts the `update` invocation, the post-fix report content,
  and exit 0. Also: missing-pixi error path (empty PATH dir) → exit 2.

## Docs

README: extend the `pixi audit` section with the new flags, the
`[tool.pixi-audit]` table, discovery behavior, and a `--fix` example.

## Out of scope (this PR)

PyPI auditing via OSV.dev fallback, SARIF output, `--service-url` flag,
yanked/deprecated checks, OSV response caching, `--direct-only`,
warn-on-unmatched-ignore, `--deny-unchecked`.
