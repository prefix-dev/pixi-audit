# Releasing

Dev builds and releases publish to `PREFIX_CHANNEL` (for example, `prefix-dev/prefix-labs`). Uploads start only after builds pass for `linux-64`, `osx-64`, `osx-arm64`, and `win-64`. Nothing goes to crates.io.

## Publish a release

1. Merge changes into `main`. [release-plz](https://release-plz.dev) opens or updates a PR with version bumps and a changelog from conventional commits.
2. Review that PR and its CI results, then merge it when ready to ship.
3. The **Tag release** job creates the tags and GitHub release. The `v<version>` tag starts the **Release** workflow, which publishes the packages.

No local commands are needed. If the PR or tags are missing, check the **Update release PR** or **Tag release** job. Release-plz runs on pushes to `main`, with no **Run workflow** button.

## Dev builds

Merges to `main` publish `<next patch>.dev<N>`, where `<N>` is the first-parent commit count. For example, `0.1.3.dev52` reports `pixi-audit 0.1.3-dev.52` in the CLI. Conda sorts it as `0.1.2 < 0.1.3.dev52 < 0.1.3`, so unpinned installs can pick up dev builds.

Commits that change the CLI version skip the dev build and rely on the release tag instead. Documentation/config-only pushes listed in `release.yaml`'s `paths-ignore` are also skipped.

## Manual publishing

Use **Release → Run workflow** with `main` for a dev build or an existing `v<version>` tag for a release. This only builds and uploads; it doesn't bump versions or create tags. The CLI-version-change check still applies on `main`. Leave `channel` empty for `PREFIX_CHANNEL`, or select another channel with trusted-publisher access.

Release tags must match the CLI version and point to a commit on `main`. The workflow verifies package and binary versions before uploading. Retries keep the same version and build number and skip existing packages.

### Without a release PR

Run `pixi exec release-plz update` in a Git checkout, review the version bumps and changelog, and merge them into `main`. Check out the merged commit and create all three tags, using the version from its manifests:

```console
git tag v0.1.3
git tag osv_client-v0.1.3
git tag threat_feeds-v0.1.3
git push origin v0.1.3 osv_client-v0.1.3 threat_feeds-v0.1.3
```

## Setup

- Set the GitHub Actions repository variable `PREFIX_CHANNEL` to the target channel path. A missing or invalid path fails before building.
- On each prefix.dev channel, add a trusted publisher for owner `prefix-dev`, repository `pixi_audit`, workflow `release.yaml`. Publishing uses OIDC, not a `PREFIX_API_KEY` secret.
- Install the [octo-sts GitHub App](https://github.com/octo-sts/app) for this repository. release-plz uses `.github/chainguard/write.sts.yaml` to obtain a token whose tags and PRs trigger workflows; the ordinary `GITHUB_TOKEN` cannot do that.

## Version tracking

`release-plz.toml` groups the CLI and four libraries into one version, so library-only changes also trigger releases. Only the CLI gets a GitHub release and changelog.

The CLI, `pixi_audit`, and `osv_protocol` share `v<version>`. `osv_client` and `threat_feeds` need separate tags because they don't exist at `v0.1.2`. Only `v*` tags trigger publishing. Test support is excluded with `publish = false` and `git_only = false`.

Tagging runs before release-PR updates. Only PR updates share a concurrency group, so newer pushes cannot cancel pending tagging jobs. `release_always = false` prevents ordinary merges from being tagged.

## Attestations

`pixi upload prefix --generate-attestation` signs each `.conda` package with a CEP-27 Sigstore attestation. prefix.dev stores it with the package and shows it on the package page, and Sigstore's transparency log records it. Search [search.sigstore.dev](https://search.sigstore.dev) for the package's SHA-256.

GitHub's attestation API is not used. It rejects private repositories on the current plan, so `--store-github-attestation` fails the upload, and `gh attestation verify` finds nothing.
