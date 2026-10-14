# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/prefix-dev/pixi-audit/compare/v0.2.0...v0.2.1) - 2026-10-14

### Added

- *(auth)* accept a Basilisk user API token for CI audits ([#43](https://github.com/prefix-dev/pixi-audit/pull/43))
- *(auth)* reuse Pixi login for optional Basilisk authentication ([#40](https://github.com/prefix-dev/pixi-audit/pull/40))

### Other

- update README and RELEASING with new instructions ([#54](https://github.com/prefix-dev/pixi-audit/pull/54))

## [0.2.0](https://github.com/prefix-dev/pixi_audit/compare/v0.1.2...v0.2.0) - 2026-10-09

### Added

- show what Basilisk compared and keep conda findings visible ([#31](https://github.com/prefix-dev/pixi_audit/pull/31))
- scope ignore rules to an ecosystem and version ([#30](https://github.com/prefix-dev/pixi_audit/pull/30))
- add audit guidance and contextual explanations ([#27](https://github.com/prefix-dev/pixi_audit/pull/27))
- `--ignore-unfixed` suppresses findings without a fix ([#23](https://github.com/prefix-dev/pixi_audit/pull/23))
- package-scoped ignore rules ([#20](https://github.com/prefix-dev/pixi_audit/pull/20))
- `pixi audit ignore` records rules in the manifest ([#19](https://github.com/prefix-dev/pixi_audit/pull/19))
- SARIF output for code scanning ([#17](https://github.com/prefix-dev/pixi_audit/pull/17))
- rank findings by EPSS, KEV and a risk score ([#14](https://github.com/prefix-dev/pixi_audit/pull/14))
- accept upstream fixes only from the matched identity ([#16](https://github.com/prefix-dev/pixi_audit/pull/16))
- warn about ignore rules that match no finding ([#18](https://github.com/prefix-dev/pixi_audit/pull/18))
- table report with sort and field selection ([#15](https://github.com/prefix-dev/pixi_audit/pull/15))
- bump manifest constraints when fixing
- audit PyPI packages with uv-audit
- correctness fixes, lock-file auditing, JSON example, and CI
- osv_protocol and pixi_audit crates

### Fixed

- quote ignore expiry dates in pixi manifests ([#28](https://github.com/prefix-dev/pixi_audit/pull/28))
- move unchecked packages to the top of audit output ([#25](https://github.com/prefix-dev/pixi_audit/pull/25))
- support inline dependency tables
- address audit review feedback
- classify Basilisk fix versions by conda publication

### Other

- [**breaking**] align terminology with common vulnerability-tool vocabulary ([#52](https://github.com/prefix-dev/pixi_audit/pull/52))
- split audit clients and share config and test support (PFX-1998) ([#46](https://github.com/prefix-dev/pixi_audit/pull/46))
- share manifest loading and editing (PFX-2004) ([#41](https://github.com/prefix-dev/pixi_audit/pull/41))
- parse ignore scopes once and drop FixVersion ([#38](https://github.com/prefix-dev/pixi_audit/pull/38))
- simplify README ([#47](https://github.com/prefix-dev/pixi_audit/pull/47))
- publish dev builds from main and open release PRs with release-plz ([#48](https://github.com/prefix-dev/pixi_audit/pull/48))
- single audit pipeline with typed ecosystems ([#12](https://github.com/prefix-dev/pixi_audit/pull/12))
- publish attested packages from main ([#10](https://github.com/prefix-dev/pixi_audit/pull/10))
- split audit internals and harden OSV handling
- document severity, until-fixed, config, discovery, and --fix
- Merge remote-tracking branch 'origin/main' into feat/pixi-audit-cli
- polish pixi-audit CLI PR
- document the pixi audit CLI extension
