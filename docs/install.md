# Install

larainspect is designed to be easy to install on macOS and Linux without building from source.

Maintained by Ahmed Nagi (`nagi1`) • X: `@nagiworks`

## Choose Path

Use the prebuilt binary that matches your platform:

- macOS Apple Silicon: `larainspect_macOS_arm64.tar.gz`
- macOS Intel: `larainspect_macOS_x86_64.tar.gz`
- Linux x86_64: `larainspect_Linux_x86_64.tar.gz`
- Linux ARM64: `larainspect_Linux_arm64.tar.gz`
- Linux ARMv7: `larainspect_Linux_armv7.tar.gz`

All commands below install to `/usr/local/bin`. If you prefer a user-only install, replace that with `~/.local/bin` and make sure it is in your `PATH`.

## Install

### macOS Apple Silicon

```bash
curl -fsSL https://github.com/nagi1/larainspect/releases/latest/download/larainspect_macOS_arm64.tar.gz | tar -xz
sudo install -m 0755 larainspect /usr/local/bin/larainspect
```

### macOS Intel

```bash
curl -fsSL https://github.com/nagi1/larainspect/releases/latest/download/larainspect_macOS_x86_64.tar.gz | tar -xz
sudo install -m 0755 larainspect /usr/local/bin/larainspect
```

### Linux x86_64

```bash
curl -fsSL https://github.com/nagi1/larainspect/releases/latest/download/larainspect_Linux_x86_64.tar.gz | tar -xz
sudo install -m 0755 larainspect /usr/local/bin/larainspect
```

### Linux ARM64

```bash
curl -fsSL https://github.com/nagi1/larainspect/releases/latest/download/larainspect_Linux_arm64.tar.gz | tar -xz
sudo install -m 0755 larainspect /usr/local/bin/larainspect
```

### Linux ARMv7

```bash
curl -fsSL https://github.com/nagi1/larainspect/releases/latest/download/larainspect_Linux_armv7.tar.gz | tar -xz
sudo install -m 0755 larainspect /usr/local/bin/larainspect
```

## Verify

```bash
larainspect version
```

Expected output includes:

- the release version
- maintainer information for Ahmed Nagi (`nagi1`)
- X handle `@nagiworks`
- commit and build date for tagged releases

## Upgrade

Upgrade by running the same install command again for your platform. The new binary will replace the existing one in place.

After upgrading:

```bash
larainspect version
```

## Uninstall

If installed to `/usr/local/bin`:

```bash
sudo rm -f /usr/local/bin/larainspect
```

If installed to `~/.local/bin`:

```bash
rm -f ~/.local/bin/larainspect
```

## Verify Release Provenance

Tagged releases are designed to be accompanied by GitHub artifact attestations.

You can verify provenance with GitHub CLI after downloading a release asset:

```bash
gh attestation verify \
  --repo nagi1/larainspect \
  larainspect_Linux_x86_64.tar.gz
```

Checksums are also published in every release as `checksums.txt`.

## Source Install

If you prefer building from source:

```bash
go install github.com/nagi1/larainspect/cmd/larainspect@latest
```