# Releasing

`release.yaml` builds `linux-64`, `osx-64`, `osx-arm64`, and `win-64`, and uploads the packages only after all four builds succeed. It publishes two kinds of packages to the same channel:

- **Dev builds**: every merge to `main` publishes `<next>.dev<N>`, where `<next>` is the current version with the patch number bumped and `<N>` is the first-parent commit count. With `0.1.2` released, a merge publishes `0.1.3.dev52`, and `pixi-audit --version` reports `0.1.3-dev.52` because Cargo needs a semver pre-release. Conda sorts dev builds after the last release and before the next one (`0.1.2 < 0.1.3.dev52 < 0.1.3`), so unpinned installs get the latest merge. Merges that only touch Markdown, `LICENSE`, `release-plz.toml`, the octo-sts policy, or the other workflows are skipped; see `paths-ignore` in `release.yaml`.
- **Releases**: a `v<version>` tag on a commit in `main` publishes `<version>`.

## Release PRs

`release-plz.yaml` runs [release-plz](https://release-plz.dev) on every merge to `main`. It keeps a release PR open that bumps the version and updates `CHANGELOG.md` from the conventional commit messages since the last `v*` tag. To release, merge that PR. release-plz then tags the merge commit with `v<version>` and creates a GitHub release, and the tag starts `release.yaml`. The merge commit of a release PR gets no dev build, because it changes the version.

Tagging and release-PR updates run in separate jobs. Every push runs the tagging job; only PR updates share a concurrency group, so a newer push cannot cancel a pending release. The PR updater waits for tagging to finish and checks out the repository with the new tags.

`release-plz.toml` puts `pixi_audit_cli`, `pixi_audit`, `osv_protocol`, `osv_client`, and `threat_feeds` in one version group, so a change in any crate bumps all of them. Only `pixi_audit_cli` gets the GitHub release and the changelog. Nothing is published to crates.io.

release-plz compares each crate against the source at its latest release tag. `pixi_audit_cli`, `pixi_audit`, and `osv_protocol` share the `v<version>` tag. `osv_client` and `threat_feeds` didn't exist at `v0.1.2`, so they get their own `osv_client-v<version>` and `threat_feeds-v<version>` tags, which don't start `release.yaml`. `pixi_audit_test_support` is test-only and `publish = false`, so release-plz skips it.

release-plz needs a token that can start workflows, so tags and PRs created with `GITHUB_TOKEN` won't work. It gets one from [octo-sts](https://github.com/octo-sts/app) using the trust policy in `.github/chainguard/write.sts.yaml`. The octo-sts GitHub App must be installed for this repository.

## Configure prefix.dev

Create the target channel, then add a trusted publisher in the channel settings with:

- GitHub owner: `prefix-dev`
- Repository: `pixi_audit`
- Workflow file: `release.yaml`

Do this for every channel that the workflow may publish to. Authentication uses GitHub's OIDC token; do not add a `PREFIX_API_KEY` secret.

## Configure GitHub

Create an Actions repository variable named `PREFIX_CHANNEL` containing the default prefix.dev channel path, for example `tdejager/prefix-labs`. The release workflow fails before building if the variable is missing or invalid.

A manual run can override the default with the `channel` workflow input. Select `main` to publish a dev build, or a release tag to publish that release. The selected channel must grant the same repository and workflow trusted-publisher access on prefix.dev.

## Checks

For a tag, the workflow checks that the tag matches the `pixi_audit_cli` version and points to a commit in `main`. For every build it checks that the Conda package version and `pixi-audit --version` match the expected version.

The Conda build number is the first-parent commit count. Retrying the workflow for the same commit uses the same version and build number. Existing packages are skipped so an interrupted upload can finish without overwriting packages.

To release without the release PR, run `pixi exec release-plz update` to bump the versions and changelog, merge that change into `main`, and tag the merge commit for every tagged crate:

```console
git tag v0.1.3
git tag osv_client-v0.1.3
git tag threat_feeds-v0.1.3
git push origin v0.1.3 osv_client-v0.1.3 threat_feeds-v0.1.3
```

## Attestations

The release workflow pins Pixi to `0.81.0`. `pixi upload prefix --generate-attestation --store-github-attestation` generates one CEP-27 Sigstore attestation for each `.conda` package. The attestations are uploaded alongside the packages, recorded in Sigstore's transparency log, and stored in GitHub's attestation API. GitHub storage still requires `--store-github-attestation` in this Pixi version.

After downloading a package, verify its GitHub attestation with:

```console
gh attestation verify pixi-audit-*.conda \
  --repo prefix-dev/pixi_audit \
  --predicate-type https://schemas.conda.org/attestations-publish-1.schema.json
```
