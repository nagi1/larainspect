# Releasing

This document describes the maintainer workflow for publishing larainspect.

Maintainer: Ahmed Nagi (`nagi1`) • X: `@nagiworks`

## Trigger Model

- CI runs on pushes to `master`, pull requests to `master`, and manual dispatch
- releases run on SemVer tag pushes matching `v*`
- the release workflow can also be run manually for snapshot validation

Normal pushes should validate code. Only tags should publish official releases.

## Release Steps

## Fast Path

From the repository root:

```bash
./scripts/release.sh v0.1.0
```

That command:

- runs `go test ./...`
- runs `go run github.com/goreleaser/goreleaser/v2@latest check`
- creates an annotated SemVer tag
- pushes the tag to `origin`
- triggers the GitHub Release workflow automatically

To test the packaging flow locally without publishing anything:

```bash
./scripts/release.sh --snapshot
```

## Release Steps

1. Ensure CI is green on `master`.
2. Confirm install docs in [docs/install.md](/Users/nagi/code/larainspect/docs/install.md) still match the current release asset names.
3. Run the release helper:

```bash
./scripts/release.sh v0.1.0
```

4. If you prefer the manual path, create and push a tag yourself:

```bash
git tag v0.1.0
git push origin v0.1.0
```

5. Open the GitHub Actions release workflow and watch it complete.
6. Verify the GitHub Release contains:

- macOS amd64 archive
- macOS arm64 archive
- Linux amd64 archive
- Linux arm64 archive
- Linux armv7 archive
- `checksums.txt`

7. Verify provenance attestation exists for the produced artifacts.
8. Run the install commands from [docs/install.md](/Users/nagi/code/larainspect/docs/install.md) on representative systems.

## What The Release Workflow Does

The release workflow:

- checks out full git history
- sets up Go from `go.mod`
- runs `go test ./...`
- runs GoReleaser with the latest stable version
- publishes release artifacts to GitHub Releases
- creates GitHub-native Sigstore-backed attestations for the generated artifacts
- uploads the `dist/` bundle as a workflow artifact for debugging and review

## Version Metadata

Tagged builds inject:

- semantic version
- commit SHA
- build date

The binary also prints maintainer identity:

- Ahmed Nagi
- `nagi1`
- `@nagiworks`

Check a built release with:

```bash
larainspect version
```

## Signing Model

Current release hardening uses GitHub artifact attestations signed through Sigstore-backed GitHub OIDC.

This provides provenance for the release artifacts without storing long-lived signing keys in the repository.

If checksum signing or GPG signing is later required in Ahmed Nagi's name, that should be added as a separate hardening step with explicit secret management.

## Homebrew

Homebrew tap automation is the next package-manager priority after the first public release is cut and verified.

Recommended target tap repository:

- `nagi1/homebrew-tap`

If and when Homebrew automation is added, prefer a dedicated PAT such as `TAP_GITHUB_TOKEN` rather than overloading the default `GITHUB_TOKEN`.

## Rollback

If a release is wrong:

1. Delete the GitHub Release.
2. Delete the tag locally and remotely.
3. Fix the issue on `master`.
4. Create and push a corrected tag.

## Verification Checklist

- `go test ./...`
- `go run github.com/goreleaser/goreleaser/v2@latest check`
- successful tag-triggered workflow run
- expected artifacts on the release page
- attestation created successfully
- install docs verified on representative macOS and Linux systems
