# pixi-audit CLI extension — design

Date: 2026-07-30
Status: approved

## Goal

Ship a `pixi audit` extension analogous to [`uv audit`](https://astral.sh/blog/uv-audit):
a command that scans a `pixi.lock` file for known vulnerabilities and reports
them in the terminal or as JSON. pixi discovers extensions the way cargo does —
any executable named `pixi-<cmd>` on `PATH` or in `$PIXI_HOME/bin` becomes
`pixi <cmd>` (see `pixi_cli::command_info::find_external_subcommand` in the
pixi repo) — so the deliverable is a `pixi-audit` binary.

The `pixi_audit` library crate in this workspace already implements the audit
itself: lock-file parsing, environment/platform filters, an ignore list, and a
structured `AuditReport`. This PR adds only the CLI layer.

## Architecture

New workspace member `crates/pixi_audit_cli`:

- package name `pixi_audit_cli` (matches the snake_case convention of
  `osv_protocol` and `pixi_audit`)
- `[[bin]] name = "pixi-audit"` so the executable satisfies pixi's extension
  discovery
- depends on `pixi_audit` (with the `lock` feature), `clap`, `miette`,
  `tokio`, `reqwest`/`reqwest-middleware`, `serde_json`, `url`

Modules:

- `main.rs` — clap argument parsing, tokio runtime, client construction,
  exit-code mapping
- `render.rs` — human-readable rendering of `AuditReport`

No changes to `pixi_audit` or `osv_protocol` are expected; `Finding` and
`AuditReport` already carry everything the output needs.

## CLI surface

```
pixi-audit <LOCKFILE> [OPTIONS]

Arguments:
  <LOCKFILE>  Path to the pixi.lock file to audit (required)

Options:
      --environment <ENV>    Audit only these environments (repeatable)
      --platform <PLATFORM>  Audit only these platforms (repeatable)
      --ignore <ID>          Vulnerability id or alias to ignore (repeatable,
                             case-insensitive; ignored findings still appear
                             in the report's ignored section)
      --json                 Emit the AuditReport as pretty-printed JSON
  -h, --help
  -V, --version
```

The lockfile path is an explicit required positional — no directory walking or
default lookup. The API endpoint comes from the existing `PIXI_AUDIT_BASE_URL`
environment variable, defaulting to the library's `DEFAULT_BASE_URL`; there is
no `--base-url` flag in this version.

## Output

Human mode (default):

- progress line ("Auditing <path> against <url> ...") goes to stderr
- findings grouped per package: name, version, ecosystem, environments, then
  one line per advisory with id, severity band, fixed versions (and upstream
  fixed versions when the package's own ecosystem has none), advisory URL
- summary line: vulnerability and package counts, audited/ignored/unchecked
  counts
- colors via the `console` crate, auto-disabled when stdout is not a TTY

Example:

```
$ pixi audit pixi.lock
Audited 142 packages (2 environments)

openssl 3.1.0 (conda-forge) — default, prod
  CVE-2023-XXXX  HIGH   fixed in: 3.1.4
  https://osv.dev/CVE-2023-XXXX

requests 2.32.0 (PyPI) — default
  GHSA-xxxx-yyyy MEDIUM fixed in: 2.32.4

2 vulnerabilities in 2 packages (140 ok, 3 unchecked)
error: audit found vulnerabilities (exit 1)
```

JSON mode (`--json`): pretty-printed `AuditReport` is the only thing written
to stdout, so output pipes cleanly; progress stays on stderr.

## Exit codes

- `0` — audit ran, no vulnerabilities (ignored-only findings count as clean)
- `1` — audit ran, vulnerabilities found
- `2` — execution error (unreadable/invalid lockfile, unknown environment or
  platform filter, network/API failure), reported via miette

## Error handling

Errors surface as miette diagnostics: lockfile read/parse errors point at the
path, filter errors name the unknown environment/platform, and API errors
carry the library's `AuditError` context. No partial reports — the library
already fails the audit if any detail fetch fails.

## Testing

- Unit tests in `render.rs`: report fixture → expected text, covering the
  empty report, findings with/without fixed versions, upstream-only fixes,
  ignored findings, and unchecked packages.
- Integration test for the binary: run `pixi-audit` against the existing
  sample lockfile with a local axum mock of the OSV API (the workspace
  already depends on axum for this), asserting stdout content and exit codes
  for the clean, vulnerable, and error cases, plus `--json` output shape.

## PR

Branch `feat/pixi-audit-cli` off `main` in this repo; separate PR from the
existing library work.
