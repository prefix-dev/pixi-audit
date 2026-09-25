# Releasing

A `v<version>` tag on a commit in `main` builds `linux-64`, `osx-64`, `osx-arm64`, and `win-64`. The packages are uploaded only after all four builds succeed. Merges to `main` no longer publish a new build of the old version.

## Configure prefix.dev

Create the target channel, then add a trusted publisher in the channel settings with:

- GitHub owner: `prefix-dev`
- Repository: `pixi_audit`
- Workflow file: `release.yaml`

Do this for every channel that the workflow may publish to. Authentication uses GitHub's OIDC token; do not add a `PREFIX_API_KEY` secret.

## Configure GitHub

Create an Actions repository variable named `PREFIX_CHANNEL` containing the default prefix.dev channel path, for example `tdejager/prefix-labs`. The release workflow fails before building if the variable is missing or invalid.

A manual run can override the default with the `channel` workflow input. Select the release tag as the workflow ref. The selected channel must grant the same repository and workflow trusted-publisher access on prefix.dev.

## Package versions

Before releasing, bump `pixi_audit_cli` in `crates/pixi_audit_cli/Cargo.toml` and update `Cargo.lock`. Merge the change into `main`, then tag that exact commit with the same version:

```console
git tag v0.1.2
git push origin v0.1.2
```

The workflow checks that the tag matches the CLI version and points to a commit in `main`. It also checks that the built Conda package and `pixi-audit --version` report that version. A new release needs a new version. A pixi lock file still records the exact build hash, but the package version now identifies the release.

The Conda build number remains the first-parent commit count of the tagged commit. Retrying the workflow for the same tag uses the same version and build number. Existing packages are skipped so an interrupted upload can finish without overwriting packages.

## Attestations

`pixi upload prefix` generates one CEP-27 Sigstore attestation for each `.conda` package. The attestations are uploaded alongside the packages, recorded in Sigstore's transparency log, and stored in GitHub's attestation API.

After downloading a package, verify its GitHub attestation with:

```console
gh attestation verify pixi-audit-*.conda \
  --repo prefix-dev/pixi_audit \
  --predicate-type https://schemas.conda.org/attestations-publish-1.schema.json
```
