# Install

larainspect is designed to be easy to install on macOS and Linux without building from source.

Maintained by Ahmed Nagi (`nagi1`) • X: `@nagiworks`

## Fastest Path

```bash
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh
```

What the installer does:

- detects macOS vs Linux automatically
- detects `x86_64`, `arm64`, and `armv7`
- downloads the matching release archive
- verifies the archive against `checksums.txt`
- installs `larainspect` into `/usr/local/bin` unless you override `INSTALL_DIR`

Common overrides:

```bash
# install a specific version instead of the latest release
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | VERSION=v0.1.0 sh

# install into a user-owned bin dir
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
```

## Choose Path

Use the prebuilt binary that matches your platform:

- macOS Apple Silicon: `larainspect_macOS_arm64.tar.gz`
- macOS Intel: `larainspect_macOS_x86_64.tar.gz`
- Linux x86_64: `larainspect_Linux_x86_64.tar.gz`
- Linux ARM64: `larainspect_Linux_arm64.tar.gz`
- Linux ARMv7: `larainspect_Linux_armv7.tar.gz`

All commands below install to `/usr/local/bin`. If you prefer a user-only install, replace that with `~/.local/bin` and make sure it is in your `PATH`.

## Install

If you want the installer to choose for you, use the one-line command above.

If you prefer to download a specific archive manually, use the commands below.

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

## First Run

After install, the fastest path is:

```bash
larainspect setup
larainspect audit
```

`larainspect setup` does more than write a starter config. It tries to detect the host layout, tune common service paths, and guess the deploy user, Laravel runtime user/group, and web user/group. It only prompts when some identity values are still missing, then persists them into `larainspect.yaml` so later findings stay aligned with the real host.

If you already have a config file and only want to fill missing or empty host-derived values, run:

```bash
larainspect populate
```

If you prefer a minimal config instead of guided detection:

```bash
larainspect init
```

In that case you can add an optional `identities` block yourself:

```yaml
identities:
  deploy_users:
    - deploy
  runtime_users:
    - www-data
  runtime_groups:
    - www-data
  web_users:
    - www-data
  web_groups:
    - www-data
```

These values make permission and runtime-boundary findings context-aware instead of depending only on service inference.

## Upgrade

Upgrade by re-running the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh
```

Or re-run the manual install command for your platform. The new binary will replace the existing one in place.

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

To install the just-built binary manually:

```bash
git clone https://github.com/nagi1/larainspect.git
cd larainspect
go build -o larainspect ./cmd/larainspect
sudo install -m 0755 larainspect /usr/local/bin/larainspect
```
