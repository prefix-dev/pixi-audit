# Native `pixi audit` integration

## Scope and baselines

Prepare this repository; do not modify the Pixi checkout in this session. The destination is `../pixi`. Move the retained code into Pixi rather than introducing temporary sibling-path or Git dependencies here.

Inspection baselines: pixi-audit `00e3f574` (JJ `osnwmqqz`, v0.2.2), Pixi `a61c2f10` (JJ `tzkozrou`). Both working copies were initially clean. The uncommitted preparation patch is part of the migration input. Recheck the destination APIs and dependency versions when starting the move.

## Decisions from the interview

- Native command only; retire the standalone executable and this repository's independent release machinery at cutover. Retain domain/protocol crates where their boundaries remain useful.
- Require a Pixi workspace. Audit its existing canonical lockfile without solving or installing. Missing lockfile is an error; remove the standalone arbitrary-lockfile argument.
- Workspace-wide policy under `[workspace.audit]` in `pixi.toml`, `[tool.pixi.workspace.audit]` in `pyproject.toml`. No feature/environment policy inheritance. Use native validation; reject unknown policy keys. Document migration from `[tool.pixi-audit]`, without dual-schema precedence or compatibility shims.
- Any failed requested vulnerability lookup, including a missing detail document, fails the audit. Unsupported packages remain explicitly not audited and non-failing by default.
- Audit recognized public package identities only: conda-forge on its supported origins and artifacts served by public PyPI. Do not silently equate private mirrors, Git/path packages, or private forks with public names. Explicit mirror identity belongs in Pixi configuration, not hostname guessing.
- Use Pixi's table, color and progress conventions. Preserve information, sorting, selected columns, JSON and SARIF; do not preserve exact extension spacing/colors or introduce iocraft into Pixi.
- Follow native runtime-error behavior: vulnerabilities and runtime errors both exit 1. Clap's own usage-error behavior remains native. Document the change from the extension's runtime-error exit 2.
- Remediation is workspace-wide. Reject `--fix` with environment/platform filters until upstream temporary constraints support scoped remediation.
- First attempt remediation with temporary constraints, leaving the manifest untouched. Only a constraint conflict justifies offering manifest adaptation; network/auth failures do not.
- Show the proposed manifest diff and request consent before fallback edits. Noninteractive or machine-output runs must not prompt: require an explicit manifest-edit opt-in or return an actionable error.
- Failed solving must not leave manifest edits. A re-audit failure after successful persistence is an execution error with an explicit changed-files diagnostic, not a claim of rollback or success.

## Dependency direction and crate reuse

Reuse Pixi's lower-level types and helpers rather than duplicating them. Keep CLI/workspace orchestration outside the audit engine and the dependency graph acyclic. Dependencies on `pixi_manifest` or other Pixi crates are appropriate when they provide needed shared types or functionality without cycles or disproportionate unrelated dependencies. Let the native command translate workspace/configuration into audit inputs. Do not make manifest parsing depend on the audit engine's HTTP/threat-feed graph merely to reuse its TOML configuration struct.

| Current responsibility | Native replacement |
| --- | --- |
| `pixi_audit_cli/src/workspace.rs` discovery and target resolution | `pixi_cli::workspace_locator`, `WorkspaceConfig`, `pixi_core::WorkspaceLocator`, `Workspace::lock_file_path` |
| Custom editable `Manifest` and raw file writes | `Workspace::modify`, `WorkspaceMut`, `ManifestDocument`, typed manifest mutation and atomic persistence |
| Standalone auth-store construction | `pixi_auth::get_auth_store(&Config)` |
| Raw reqwest construction | `pixi_utils::reqwest::reqwest_client_builder(Some(config))`, with explicit audit redirect/timeout policy |
| Duplicated cache-root selection | Pixi configuration/cache helpers; add an audit cache kind upstream if necessary |
| Ignore-array editing | Native document API plus `pixi_toml_edit::push_array_element` |
| Recursive dependency-table traversal | `WorkspaceManifestMut` and `PixiSpec` / `PixiPypiSpec`, following declaration ownership |
| Spinner component and render loop | `pixi_progress` / shared reporters |
| Custom report grid | `comfy-table` and `console`, following `pixi_cli/src/list.rs` |
| `Command::new("pixi")` remediation | Shared native temporary-constraint solving, not a subprocess or duplicated update implementation |

Preserve Basilisk-specific security policy while reusing infrastructure: exact-origin API tokens, HTTPS except loopback, disabled redirects, production-only shared OAuth borrowing, and audience validation. Pixi's generic authenticated middleware is not a drop-in replacement. Respect configured auth files, proxies, roots, offline behavior and global progress/color settings. Offline must not silently contact services or imply a fresh successful audit when required data is unavailable.

The retained library already accepts caller-configured `ClientWithMiddleware`. Keep that boundary. `osv_protocol` owns wire types; `osv_client` owns batching/pagination; `pixi_audit` owns interpretation and reports. Do not add a utility crate solely to relocate the few HTTP helpers used by `threat_feeds`.

## Upstream remediation prerequisites

[Pixi #7464](https://github.com/prefix-dev/pixi/pull/7464) is the intended first-stage mechanism. At review time it is open, not present in the destination checkout. It adds runtime `WorkspaceManifest::extra_constraints` consumed by combined constraints, satisfiability checking and solving. It constrains transitives without adding dependencies, preserves other locked records as preferences, and avoids re-solving already-satisfying environments.

Its current limitations are part of the integration contract:

- Conda only. Complete native remediation also needs the PyPI equivalents in [#7493](https://github.com/prefix-dev/pixi/pull/7493) and [#7494](https://github.com/prefix-dev/pixi/pull/7494), or an equivalent upstream implementation. Reinspect these dependent patches after #7464 lands; do not assume their older descriptions match its current scope.
- Workspace-wide constraints; no environment/platform selection. Enforce the CLI conflict described above.
- The solver selects a newest allowed release, not necessarily the first fixed release. Preserve existing upper bounds, exclusions, channels, build selectors and `exclude-newer`. Do not silently exempt dates or widen policy.
- A temporary constraint does not persist protection against future unconstrained solves. Explain this distinction when reporting a successful fix.
- Use typed constraints directly inside Pixi. Do not construct CLI strings just to parse them again. If no suitable shared native orchestration API exists after those PRs land, add it upstream instead of a local workaround.
- Keep remediation lockfile-only unless explicitly requested otherwise; do not accidentally inherit `pixi update`'s installation behavior.

## Remaining blockers before native remediation

These are not resolved by replacing the frontend or by the preparation patch:

1. **Conflicting fixes after alias merging.** `audit/matches.rs` unions fixed versions; `Match::lowest_fixed_version()` chooses the minimum newer version. The existing alias fixture contains boundaries 3.1.1 and 3.1.2 for the same advisory identity. The first can still be vulnerable according to the other record. Retain affected-range provenance and derive constraints safe against every contributing record, including multiple release branches. Do not approximate this as one unconditional `>= minimum`, and do not choose a database winner silently. Re-audit the candidate before announcing success.
2. **Candidate selection precedes manifest admissibility.** The standalone `FixPlan` picks one candidate before checking constraints. An excluded first candidate can hide a later admissible fix. Native planning must consider admissible safe versions/ranges and report cases without one.
3. **Mutation ownership and scope.** The standalone recursive walker can touch unrelated tool tables, ignores native Python dependency locations, and expands report scope. Delete it during migration. Resolve actual declaration owners, inherited dependency pools, features and solve groups through Pixi's typed model. Show any proposed persistent policy change in the fallback diff.
4. **Persistence boundaries.** `WorkspaceMut` can restore intermediate manifest writes, but that is not an atomic transaction across manifest, lockfile and installed environments. Define the commit point; prefer solving and auditing candidate state before persistence. Preserve explicit error reporting for any post-write verification failure.

Do not ship native automatic remediation until these cases and both ecosystems are covered. The current standalone fix implementation remains present only until the native cutover; this preparation does not claim to repair it.

## Execution sequence

1. **Finish retained-engine readiness.** Land the prepared source-coverage, missing-document, package-severity, protocol and threat-feed corrections after verification. Simplify the duplicated `AuditError` transport mapping when migrating its consumers, rather than preserving duplicate variants and pagination-limit text. Resolve the remediation blockers above with focused consumer-visible regressions.
2. **Move crates into Pixi's workspace.** Reuse workspace dependencies and the existing middleware patch. Drop standalone packaging/release workflows and `pixi_audit_cli` after all command behavior has moved. Keep test-only services unpublished. The preparation aligns rattler package/lock types and uv types to the inspected Pixi baseline, including its Rust toolchain. Pixi manifest PyPI types still use `pep440_rs`/`pep508_rs`, not uv; prefer the native representation at that boundary rather than repeated string conversion.
3. **Integrate policy in `pixi_manifest`.** Add audit policy to the workspace model and span-aware parser, runtime conversion, native document editing and validation. Move manifest-specific TOML values/expiry parsing out of the engine; feed resolved ignore rules into it. Update `schema/model.py` and regenerate all Pixi/Pyproject schema outputs. Add the native ignore subcommand using the same editor. Preserve expiry inclusivity, alias matching, reasons, until-fixed rules and CLI override semantics.
4. **Add `pixi_cli::audit`.** Register the command and use shared workspace/configuration loading. Keep orchestration out of the domain library. Honor global color/no-progress/verbosity/offline controls. Render JSON/SARIF only to stdout, diagnostics/progress to stderr; handle broken pipes using Pixi's conventions. Port table and by-package output to native presentation and retain GitHub annotations without corrupting machine output.
5. **Integrate temporary-constraint remediation.** Reuse merged upstream APIs for both ecosystems; enforce workspace-wide scope. Implement conflict-only manifest fallback, explicit CI consent, safe candidate evaluation and persistence boundaries. Remove the external `pixi update` call and standalone constraint mutation code completely.
6. **Verify native behavior.** Run focused Rust/CLI integration tests, manifest/schema tests, formatting, Clippy and `pixi run typos`. Exercise an actual TTY as well as redirected JSON/SARIF. Cover clean/vulnerable/error outcomes; ignored and expired rules; withdrawn/missing documents; partial coverage; wrong-origin auth and redirects; custom auth/root/proxy settings; offline behavior; multiple environments/platforms; and no mutation during ordinary audit.
7. **Verify remediation with local package repositories.** Include direct/transitive conda and PyPI packages, multiple release branches, alias conflicts, already-fixed environments, excluded first candidates, unavailable fixes, upper bounds, `exclude-newer`, build/channel selectors, solve groups, inherited declarations, Python metadata, solver/network failures, noninteractive prompts, unchanged manifests on temporary success/failure, and re-audit failure after persistence. Confirm the lockfile diff, not only the exit status.
8. **Document the cutover.** Update native command/security/manifest docs and migration instructions for schema, workspace-only input and error exit codes. Do not manually edit Pixi's generated changelog. Remove obsolete standalone docs and adapters in the same cutover, without compatibility aliases.
9. **Before landing: invoke the `adversarial-review` skill and follow it.** Two fresh reviewers: one searches for bugs; the other writes end-to-end scenarios. Triage findings, fix defects, and retain only useful deterministic regressions.
10. **Invoke the `benchmark` skill and follow it.** Use the stated baselines plus the preparation patch, matching toolchain/dependencies and workload. Compare severity aggregation separately from network latency; compare native remediation on identical disposable lockfiles once integrated. Do not infer end-to-end speed from a scoring microbenchmark.
