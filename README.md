# larainspect

**Read-only security audit CLI for Laravel servers.** Inspects your VPS in seconds — never writes, never mutates, safe on production.

```
larainspect audit
```

That's it. One command scans your server's filesystem permissions, Nginx config, PHP-FPM pools, cron jobs, queue workers, and your Laravel app source for security misconfigurations — then gives you a clear, prioritized report.

---

## Install

### From source (requires Go 1.23+)

```bash
go install github.com/nagi1/larainspect/cmd/larainspect@latest
```

### Build locally

```bash
git clone https://github.com/nagi1/larainspect.git
cd larainspect
go build -o larainspect ./cmd/larainspect
sudo mv larainspect /usr/local/bin/
```

Verify it works:

```bash
larainspect version
```

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

output:
  format: terminal
  verbosity: normal

rules:
  disable:
    - source.config # skip source config checks on this host
```

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

## License

MIT
