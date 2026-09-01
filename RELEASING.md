# Releasing

Every commit pushed to `main` is built for `linux-64`, `osx-64`, `osx-arm64`, and `win-64`. The packages are uploaded only after all four builds succeed.

## Configure prefix.dev

Create the target channel, then add a trusted publisher in the channel settings with:

- GitHub owner: `prefix-dev`
- Repository: `pixi_audit`
- Workflow file: `release.yaml`

Do this for every channel that the workflow may publish to. Authentication uses GitHub's OIDC token; do not add a `PREFIX_API_KEY` secret.

## Configure GitHub

Create an Actions repository variable named `PREFIX_CHANNEL` containing the default prefix.dev channel path, for example `tdejager/prefix-labs`. The release workflow fails before building if the variable is missing or invalid.

A manual run can override the default with the `channel` workflow input. The selected channel must grant the same repository and workflow trusted-publisher access on prefix.dev.

## Package versions

The Conda package version comes from `pixi_audit_cli` in `crates/pixi_audit_cli/Cargo.toml`. Its build number is the first-parent commit count of `main`:

```console
git rev-list --first-parent --count HEAD
```

With squash merges, each merged pull request advances the build number once. For example, consecutive commits might publish `0.1.1` builds `42` and `43`. A later `0.1.2` version supersedes all `0.1.1` builds.

Rerunning a workflow for the same commit produces the same version and build number. Existing packages are skipped, so retries can finish an interrupted upload without overwriting packages.

## Attestations

`pixi upload prefix` generates one CEP-27 Sigstore attestation for each `.conda` package. The attestations are uploaded alongside the packages, recorded in Sigstore's transparency log, and stored in GitHub's attestation API.

After downloading a package, verify its GitHub attestation with:

```console
gh attestation verify pixi-audit-*.conda \
  --repo prefix-dev/pixi_audit \
  --predicate-type https://schemas.conda.org/attestations-publish-1.schema.json
```
