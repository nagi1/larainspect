# larainspect

[![Release](https://img.shields.io/github/v/release/nagi1/larainspect?display_name=tag)](https://github.com/nagi1/larainspect/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/nagi1/larainspect/ci.yml?branch=master&label=ci)](https://github.com/nagi1/larainspect/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-222222)](https://github.com/nagi1/larainspect/releases)

**Read-only security audit CLI for Laravel servers.** Inspects your VPS in seconds — never writes, never mutates, safe on production.

---

## Watch First

Prefer a quick overview before installing or running it? Watch the video walkthrough first.

🔴 **YouTube Video Walkthrough**

[![Watch the larainspect walkthrough on YouTube](https://img.youtube.com/vi/VngYhaj8Z9w/maxresdefault.jpg)](https://www.youtube.com/watch?v=VngYhaj8Z9w)

## Install

Full install, upgrade, verify, and uninstall instructions live in [docs/install.md](/Users/nagi/code/larainspect/docs/install.md).

### One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh
```

The installer auto-detects macOS vs Linux, resolves the right archive for your CPU, verifies `checksums.txt`, and installs `larainspect` into `/usr/local/bin`.

Useful overrides:

```bash
# install a specific release
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | VERSION=v0.1.0 sh

# install without sudo into a user bin dir
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
```

### Prebuilt release binaries

Tagged releases publish prebuilt archives for:

- macOS Apple Silicon (`larainspect_macOS_arm64.tar.gz`)
- macOS Intel (`larainspect_macOS_x86_64.tar.gz`)
- Linux x86_64 (`larainspect_Linux_x86_64.tar.gz`)
- Linux ARM64 (`larainspect_Linux_arm64.tar.gz`)
- Linux ARMv7 (`larainspect_Linux_armv7.tar.gz`)

Latest-download asset names are stable so users can rely on predictable install commands.

Manual examples:

```bash
# macOS Apple Silicon
curl -fsSL https://github.com/nagi1/larainspect/releases/latest/download/larainspect_macOS_arm64.tar.gz | tar -xz
sudo install -m 0755 larainspect /usr/local/bin/larainspect

# Linux x86_64
curl -fsSL https://github.com/nagi1/larainspect/releases/latest/download/larainspect_Linux_x86_64.tar.gz | tar -xz
sudo install -m 0755 larainspect /usr/local/bin/larainspect
```

Verify it works:

```bash
larainspect version
```

### From source (requires Go 1.25+)

```bash
go install github.com/nagi1/larainspect/cmd/larainspect@latest
```

Verify it works:

```bash
larainspect version
```

Homebrew tap automation is the next package-manager priority after the first public release is cut and verified.

---

## Quick start

```bash
larainspect setup
larainspect audit
```

`larainspect setup` tries to detect the hosting layout and guess the deploy user, runtime user/group, and web user/group from the host first. It only prompts when some of those identities cannot be inferred confidently, then writes them into the generated config so later findings stay context-aware.

If you already have a config file and only want to fill missing or empty host-derived values, use:

```bash
larainspect populate
```

If you want a config file first, start here:

```bash
larainspect init
larainspect audit
```

One command scans your server's filesystem permissions, Nginx config, PHP-FPM pools, cron jobs, queue workers, and your Laravel app source for security misconfigurations — then gives you a clear, prioritized report.

## Demo Environment

The repository includes a deliberately vulnerable Laravel demo in [demo/README.md](demo/README.md).

It is built for live demos and videos:

- vulnerable and normal Ubuntu-based Docker images side by side
- `larainspect` installed in each image through the same one-line installer shown in this README
- ready-to-use config at `demo/larainspect.yaml` and `/etc/larainspect/config.yaml` inside the containers
- package-managed Nginx, PHP-FPM, and Supervisor with UFW intentionally present but disabled for a familiar server layout
- intentionally insecure Laravel source, public artifacts, Nginx, PHP-FPM, and Supervisor configs that map to real larainspect checks

Fast path:

```bash
cd demo
docker compose build
docker compose up -d vulnerable
docker compose exec vulnerable larainspect audit --config /etc/larainspect/config.yaml
```

For the full step-by-step walkthrough and presenter-friendly commands, see [demo/README.md](demo/README.md).

---

## Usage

### Run a full audit

```bash
larainspect audit
```

Auto-detects Laravel apps under common paths (`/var/www`, `/srv/www`) and scans the host.

### Point at a specific app

```bash
larainspect audit --scope app --app-path /var/www/shop
```

### Interactive mode

Prompts you for missing info (app path, scope) without breaking automation defaults:

```bash
larainspect audit --interactive
```

### Bootstrap a config file

```bash
# write a starter config in the current directory
larainspect init

# fill missing config values in an existing file without replacing values you set
larainspect populate

# detect aaPanel / Forge / DigitalOcean / cPanel / common VPS layouts,
# then persist guessed deploy/runtime/web identities
larainspect setup
```

Use `setup` when you want Larainspect to generate a new tuned config for the current host. Use `populate` when you already have a config and want Larainspect to backfill only the missing server, Laravel, service, or identity values. Use `init` when you want a minimal starter file and prefer to fill in the identity policy yourself.

### Export reports

```bash
# JSON (pipe to jq, feed CI, store artifacts)
larainspect audit --format json

# Markdown file
larainspect audit --report-markdown-path ./audit-report.md

# JSON file
larainspect audit --report-json-path ./audit-report.json

# Both at once
larainspect audit --report-json-path ./out.json --report-markdown-path ./out.md
```

### Quiet mode (CI / scripts)

```bash
larainspect audit --format json --verbosity quiet
echo $?  # exit code tells you the worst severity found
```

### Custom scan roots

```bash
larainspect audit --scan-root /var/www --scan-root /home/deployer/apps
```

---

## What it checks

| Area                           | Examples                                                                                      |
| ------------------------------ | --------------------------------------------------------------------------------------------- |
| **Filesystem permissions**     | Owner/runtime identity split, .env exposure, world-writable paths, storage symlink boundaries |
| **Nginx boundaries**           | Public docroot validation, dotfile deny rules, PHP passthrough scope, header hardening        |
| **PHP-FPM security**           | Pool isolation, socket permissions, dangerous PHP directives                                  |
| **Secrets exposure**           | Leaked credentials in source, .env in public, debug endpoints left enabled                    |
| **Source config**              | APP_DEBUG, unsafe queue/session drivers, missing encryption keys                              |
| **Source security**            | Mass assignment risks, unvalidated input, raw SQL, unsafe file handling                       |
| **Framework heuristics**       | Laravel, Livewire, Filament, and admin panel misconfigurations                                |
| **Dependency vulnerabilities** | Known CVEs in Composer dependencies                                                           |
| **Cron & workers**             | Misconfigured schedules, supervisor gaps, queue driver mismatches                             |
| **Deploy & drift**             | Stale releases, uncommitted changes, permission drift after deploy                            |
| **Network hardening**          | Exposed debug ports, unnecessary open services                                                |
| **Forensics**                  | Webshell indicators, suspicious cron entries, anomalous file timestamps                       |

Every finding includes a severity (critical / high / medium / low / info), confidence level, evidence, and a plain-language explanation with next steps.

When evidence is missing or access is denied, larainspect reports it as an **unknown** — never silently skips.

---

## Exit codes

Designed for CI pipelines and scripts:

| Code | Meaning                           |
| ---: | --------------------------------- |
|  `0` | Clean — no findings, no unknowns  |
|  `2` | Usage or flag error               |
| `10` | Low / info risk, or unknowns only |
| `20` | Medium-risk finding               |
| `30` | High-risk finding                 |
| `40` | Critical-risk finding             |
| `50` | Audit execution failure           |

```bash
larainspect audit --format json --verbosity quiet
if [ $? -ge 30 ]; then
  echo "High or critical risk found — blocking deploy"
  exit 1
fi
```

---

## Configuration

Larainspect works with zero config. For recurring audits, drop a config file and it auto-loads:

To generate one instead of writing it by hand:

```bash
larainspect init
larainspect setup
```

**Search order:** `larainspect.yaml` → `larainspect.yml` → `.larainspect.yaml` → `.larainspect.yml` → `larainspect.json` → `.larainspect.json` → `/etc/larainspect/config.yaml` → `/etc/larainspect/config.json`

Or specify one explicitly:

```bash
larainspect audit --config /etc/larainspect/config.yaml
```

Example config (`larainspect.yaml`):

```yaml
version: 1

server:
  name: laravel-production

laravel:
  scope: auto
  app_path: /var/www/laravel/current
  scan_roots:
    - /var/www

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

output:
  format: terminal
  verbosity: normal

rules:
  disable:
    - source.config # skip source config checks on this host
```

The `identities` block is optional, but it is the preferred way to make permission, drift, runtime-boundary, and socket-boundary findings match your real deploy/runtime/web account model instead of relying on inference alone.

Identity fields:

- `deploy_users`: release, CI, or SSH users that deploy the app
- `runtime_users`: PHP-FPM, Horizon, queue, or scheduler users that execute Laravel code
- `runtime_groups`: groups that back those runtime processes
- `web_users`: Nginx or Apache worker users that front the app
- `web_groups`: groups used by the web tier

If you run `larainspect setup`, Larainspect will try to populate these from the host automatically and only ask for the missing values. If you already have a config, `larainspect populate` applies the same host inference only to missing or empty values and leaves the rest alone.

See [larainspect.example.yaml](larainspect.example.yaml) for all available options.

---

## Security controls

List the normalized external security controls (OWASP, Laravel docs, platform hardening guides) that drive larainspect's checks:

```bash
larainspect controls
larainspect controls --status implemented
larainspect controls --format json
```

---

## Accessibility

- `--screen-reader` — compact, explicit guidance for assistive tech
- `--no-color` — plain ASCII, no ANSI escapes
- `--verbosity quiet` — minimal output for focused use
- JSON output is always clean on stdout

---

## Safety promises

- **Never writes** to application code, service config, permissions, or runtime state
- **Never phones home** — no internet access needed during a normal audit
- **Bounded execution** — all shell commands are allowlisted with timeouts and output caps
- Findings, heuristics, compromise indicators, and unknowns are kept **separate and explicit**

---

## Contributing

```bash
go test ./...
go run ./cmd/larainspect audit
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for package boundaries, testing strategy, and how to add new checks.

## Docs

- [Product model](docs/product-model.md)
- [Architecture](docs/architecture.md)
- [Foundation contracts](docs/foundation-contracts.md)
- [CLI UX guide](docs/cli-ux-and-accessibility.md)
- [Security checklist](docs/security-checklist.md)

## Roadmap

Planned work to expand coverage, improve usability, and make larainspect easier to validate in real-world Laravel environments:

- [ ] Build comprehensive contributing guide with development setup, testing workflows, and contribution guidelines
- [ ] Write comprehensive project documentation covering installation, upgrade paths, usage patterns, CI integration, and troubleshooting
- [ ] Add CI build pipeline with automated release workflows
- [ ] Build a project landing page and homepage for better discoverability
- [ ] Create an introduction video demonstrating the tool's usage and value
- [x] Add a vulnerable demo Laravel project for end-to-end testing and live examples
- [x] Include intentionally vulnerable Nginx and PHP-FPM configurations in the demo environment
- [ ] Add an HTML report format for shareable audit output
- [ ] Add richer remediation guidance per finding with concrete fix steps
- [ ] Enhance the README with more examples, screenshots, and user guides
- [ ] Add CI-oriented output formats such as SARIF or JUnit where they provide downstream value
- [ ] Add report diffing and baseline comparison workflows for recurring audits
- [ ] Add first-class package coverage for Laravel Horizon
- [ ] Add first-class package coverage for Laravel Telescope
- [ ] Add first-class package coverage for Laravel Pulse
- [ ] Expand framework and ecosystem heuristics for more Laravel deployment patterns and admin stacks
- [ ] Keep iterating on new checks and workflows based on real audit results, common Laravel hosting failures, and contributor feedback

---

## Maintainer

Ahmed Nagi (`nagi1`) — X: [@nagiworks](https://x.com/nagiworks)

## Release

Release instructions live in [docs/releasing.md](docs/releasing.md).

Fast path:

```bash
./scripts/release.sh v0.1.0
```

That runs the test suite, validates `.goreleaser.yml`, creates an annotated tag, and pushes it to GitHub so the release workflow publishes the archives.

For a local dry run:

```bash
./scripts/release.sh --snapshot
```

## License

MIT
