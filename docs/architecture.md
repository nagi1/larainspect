# Architecture

## Purpose

`larainspect` is a read-only Go CLI that audits Linux VPS deployments running Laravel and adjacent services such as Nginx, PHP-FPM, queues, cron, Filament, and Livewire.

The tool must be safe on production systems, evidence-driven, and maintainable enough for open-source contributors to add new checks without rewriting core logic.

## Design Goals

- read-only by default
- no internet dependency during an audit run
- explicit separation between confirmed findings, heuristic findings, compromise indicators, and unknowns
- modular check system with stable public contracts
- fast execution on real VPS hosts using common Linux utilities
- graceful degradation when files, commands, or permissions are unavailable

## Non-Goals For v1

- no remediation or `--fix` mode
- no service reloads or config mutation
- no firewall changes
- no live network probing beyond local system inspection
- no runtime plugin loading

## Threat Model

Primary attacker and failure assumptions:

- remote attacker reaching Nginx, Laravel routes, Filament panels, Livewire endpoints, or exposed dashboards
- compromised web runtime attempting persistence, code execution, or credential access
- low-privilege local user abusing shared sockets, weak ACLs, or shared runtime identities
- operational mistakes such as root-run `artisan`, root-run `composer`, stale deploys, writable code, leaked backups, and exposed internal services

## Execution Model

The `audit` command should execute in this order:

1. preflight
2. discovery
3. direct subsystem checks
4. correlation checks
5. report rendering
6. exit code calculation

High-level flow:

```text
CLI -> preflight -> snapshot discovery -> checks -> correlators -> terminal/json report
```

## Package Layout

Suggested Go package structure:

- `cmd/larainspect`
- `internal/cli`
- `internal/model`
- `internal/runner`
- `internal/discovery`
- `internal/parsers`
- `internal/checks`
- `internal/correlators`
- `internal/report/terminal`
- `internal/report/json`
- `internal/testfixtures`

Rules:

- reporters must not contain detection logic
- checks must not execute shell commands directly
- discovery should normalize raw host data once, then share it with checks
- correlators should combine signals across checks without duplicating subsystem parsing

## Core Data Model

### Snapshot

The normalized snapshot is the shared discovered state for one audit run.

Suggested contents:

- host metadata
- discovered Laravel apps
- package/version metadata
- filesystem metadata for sensitive paths
- process and service inventory
- listener inventory
- Nginx config model
- PHP-FPM config model
- cron/systemd/supervisor definitions
- selected bounded log excerpts
- command run records
- unknown or denied evidence records

### Finding

Every finding should contain:

- `id`
- `class`
- `subsystem`
- `title`
- `severity`
- `confidence`
- `why_it_matters`
- `evidence`
- `affected`
- `remediation`
- `commands`

Taxonomy:

- severity: `Critical`, `High`, `Medium`, `Low`, `Informational`
- confidence: `confirmed`, `probable`, `possible`, `not_enough_evidence`
- class: `direct`, `heuristic`, `compromise_indicator`, `unknown`

### Check Contract

Each check should implement a stable interface equivalent to:

```go
type Check interface {
    ID() string
    Subsystem() string
    Run(ctx context.Context, snapshot *model.Snapshot) ([]model.Finding, []model.Unknown)
}
```

Use compile-time registration. Avoid Go plugin loading for portability and contributor simplicity.

## Safety Rules For Implementation

- no shell interpolation through `sh -c`
- explicit command allowlist in the runner
- per-command timeouts
- bounded stdout/stderr capture
- bounded file reads
- redact obvious secrets from excerpts
- treat permission failures as evidence, not crashes
- never claim certainty where only heuristics exist

## Checks By Subsystem

### 1. App Discovery And Validation

Goals:

- validate explicit app path
- discover Laravel apps from scan roots
- detect Laravel, Filament, Livewire, Horizon, and Octane
- detect multi-app overlap

Data sources:

- filesystem reads of `artisan`, `bootstrap/app.php`, `config/app.php`, `public/index.php`, `composer.json`, `composer.lock`
- `vendor/composer/installed.json` when present
- `find` for scan roots and multiple app discovery

### 2. Ownership And Permissions

Goals:

- inspect ownership and mode of root, code, writable, and sensitive files
- distinguish expected writable paths from unexpected ones
- detect writable plus executable combinations

Data sources:

- `stat`
- `find`
- `namei -l`
- `getfacl`
- symlink resolution via `readlink`

Primary targets:

- project root
- `app/`
- `bootstrap/`
- `bootstrap/cache/`
- `config/`
- `database/`
- `public/`
- `resources/`
- `routes/`
- `storage/`
- `vendor/`
- `composer.json`
- `composer.lock`
- `artisan`
- `.env`
- `.env.example`
- `public/index.php`

### 3. Secrets And Config Safety

Goals:

- inspect `.env`, backup files, config cache, debug flags, and public artifact exposure
- detect publicly reachable sensitive artifacts or broadly readable secrets

Data sources:

- direct file reads for `.env`, cached config, Laravel config files
- `find` for `.env.*`, swap files, archives, dumps, logs, and hidden VCS artifacts

### 4. Nginx Boundary Audit

Goals:

- validate docroot and front controller design
- inspect PHP execution scope, deny rules, hidden file handling, admin path exposure, and traversal hazards

Data sources:

- `nginx -T`
- fallback reads from common Nginx config paths
- process and listener correlation from `ps` and `ss`

### 5. PHP-FPM Audit

Goals:

- inspect pool identity, socket or TCP exposure, socket ACLs, shared pools, and risky settings

Data sources:

- `php-fpm -tt`
- versioned `php-fpm8.* -tt`
- fallback reads from common pool config directories
- `ps`
- `ss`

### 6. Writable Vs Executable Correlation

Goals:

- prove whether writable paths can influence PHP execution, routing, auth, or service behavior

Correlation inputs:

- Nginx served paths
- PHP-FPM execution paths
- runtime-writable paths
- queue and cron writable paths
- symlink targets under `public/`
- unit files and include directories

### 7. Laravel Heuristics

Goals:

- infer security posture for auth, sessions, CSRF, throttling, trusted proxies, trusted hosts, and admin/API separation

Data sources:

- `.env`
- `config/*.php`
- route files
- middleware/provider files when directly relevant

These findings must remain heuristic unless direct evidence proves misconfiguration.

### 8. Livewire Heuristics

Goals:

- detect uploads, temp upload exposure, risky public properties, likely missing `#[Locked]`, and likely missing authorization on mutations

Data sources:

- Composer metadata
- Livewire component source files
- config files
- route/provider files

Example heuristic patterns:

- `WithFileUploads`
- public properties such as `id`, `user_id`, `tenant_id`, `role_id`
- update/delete methods without obvious authorization calls

### 9. Filament Heuristics

Goals:

- detect panel path, auth middleware, guest exposure, policy signals, MFA signals, and tenant-access signals

Data sources:

- Composer metadata
- panel provider files
- resource classes
- auth-related config and middleware references

### 10. Queues, Horizon, Workers, Supervisor, Systemd

Goals:

- inspect worker identity, root execution, stale release paths, Horizon exposure, and permission drift across workers

Data sources:

- `ps`
- `systemctl`
- `systemctl cat`
- Supervisor config paths
- process command lines

### 11. Scheduler And Cron

Goals:

- detect duplicate schedulers, root execution, direct artisan jobs, and unsafe cron patterns

Data sources:

- `crontab -l`
- `/etc/crontab`
- `/etc/cron.d/*`
- spool locations where readable

### 12. Port And Network Exposure

Goals:

- map listeners to processes and classify public vs local exposure
- detect FPM over TCP, public Redis or databases, exposed admin tools, and accidental dev servers

Data sources:

- `ss -lntup`
- `ss -lxnp`
- `ip -brief addr`
- firewall summaries from `ufw`, `firewalld`, `nft`, `iptables` when available

### 13. Deployment And Release Model

Goals:

- detect in-place vs release-based deploys, stale writable releases, root-run deploy habits, `.git` exposure risk, and unsafe backups

Data sources:

- symlink and ownership inspection
- service definitions
- release directory layout
- Composer artifacts and deploy script traces where readable

### 14. Logs And Possible Compromise Indicators

Goals:

- surface suspicious recent files, shells, dumps, archives, strange symlinks, and unusual changes in writable paths

Data sources:

- bounded `tail` of Laravel, Nginx, PHP-FPM, auth, queue, and cron logs
- `find` constrained by mtime, type, and suspicious name patterns

This section must be explicitly separated from confirmed findings.

### 15. Multi-App And Lateral Movement

Goals:

- detect shared runtime users, shared FPM sockets, cross-app secret readability, cross-app write paths, and dangerous credential reuse hints

Data sources:

- app discovery results
- pool and socket mapping
- permissions and ACL data
- listener and service correlation

## Command And Evidence Sources

Preferred commands and inputs:

- `hostname`
- `uname -a`
- `/etc/os-release`
- `stat`
- `find`
- `namei -l`
- `getfacl`
- `ps -eo user,group,pid,ppid,comm,args`
- `ss -lntup`
- `ss -lxnp`
- `systemctl list-units --type=service --all`
- `systemctl show`
- `systemctl cat`
- `nginx -T`
- `php-fpm -tt`
- version-specific `php-fpmX.Y -tt`
- `crontab -l`
- bounded file reads from Laravel, Nginx, PHP-FPM, and service config files

If any command is missing, denied, or unsupported on the host, record an explicit unknown rather than failing the run.

## Reporting Contract

### Terminal Report Sections

- Summary
- Critical findings
- High findings
- Medium findings
- Low findings
- Informational notes
- Possible compromise indicators
- Unknown / could not inspect
- Recommended next actions

### JSON Report Shape

Top-level fields:

- `schema_version`
- `hostname`
- `timestamp`
- `app_path`
- `apps_detected`
- `detected_stack`
- `findings`
- `unknowns`
- `command_runs`
- `summary`
- `exit_code`

### Exit Codes

- `0`: no critical or high findings
- `1`: high findings present
- `2`: critical findings present
- `3`: runtime or inspection errors prevented reliable execution

## Sample Findings

### Direct Finding

- title: `Runtime user can modify executable code`
- severity: `Critical`
- confidence: `confirmed`
- evidence: `app/Providers/AppServiceProvider.php` owned by `www-data`, mode `664`; PHP-FPM pool user is `www-data`
- affected: application code tree and PHP-FPM pool
- remediation: move code ownership to deploy user, remove runtime write access from code paths

### Heuristic Finding

- title: `Filament admin panel appears publicly reachable on default path`
- severity: `High`
- confidence: `possible`
- evidence: Filament detected, panel path `/admin`, no obvious additional restriction in Nginx or panel provider
- affected: Filament admin surface
- remediation: add explicit production access restrictions, verify auth and MFA posture

### Compromise Indicator

- title: `Recent PHP file found under writable public storage`
- severity: `High`
- confidence: `probable`
- evidence: recent `.php` file under `public/storage/` with runtime ownership
- affected: public writable storage path
- remediation: investigate immediately, preserve evidence, remove executable handling from that path

## Contributor Extension Rules

- add new checks as isolated modules under `internal/checks`
- reuse normalized discovery data before adding new shell commands
- only add a new runner command when existing snapshot data is insufficient
- keep heuristics explicitly labeled
- add fixtures for parser edge cases and realistic bad configurations
- keep terminal and JSON output driven by the same finding model
