# Architecture

## Purpose

`larainspect` is a read-only Go CLI that audits Linux VPS deployments running Laravel and adjacent services such as Nginx, PHP-FPM, queues, cron, Filament, and Livewire.

The tool must be safe on production systems, evidence-driven, and maintainable enough for open-source contributors to add new checks without rewriting core logic.

Go is the right fit because this auditor needs to be fast, easy to distribute as a single binary, comfortable for operators to run, and capable of using safe concurrency to reduce audit time on real servers.

This document is the pre-implementation design artifact for v1. It defines the audit plan, subsystem checks, evidence sources, output schema, and representative findings. Code should follow this document, not invent scope ad hoc.

The audit baseline and hardened target state are further detailed in [docs/security-checklist.md](/Users/nagi/code/larainspect/docs/security-checklist.md). The implementation should treat that checklist as an explicit source of check coverage requirements.

## Design Goals

- read-only by default
- no internet dependency during an audit run
- explicit separation between confirmed findings, heuristic findings, compromise indicators, and unknowns
- modular check system with stable public contracts
- fast execution on real VPS hosts using common Linux utilities
- graceful degradation when files, commands, or permissions are unavailable
- Laravel-style operator UX with concise, high-signal terminal output
- beginner-friendly and accessible CLI behavior without sacrificing depth for expert operators
- configurable and interactive operator experience where it improves usability and safety
- explicit support for open-source contributor extension
- code structure that stays `DRY` without becoming abstract for its own sake
- simple, explicit design that follows `KISS`
- descriptive package, type, and method naming for maintainability
- pragmatic use of the Go ecosystem instead of rebuilding solved plumbing from scratch
- automated tests and fixtures that prove the audit behaves correctly under representative host states
- use Go's strengths deliberately: fast startup, simple deployment, strong tooling, and concurrency where it improves bounded host inspection

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

## Hardened Target State

The secure target state for the intended deployment model is:

- code owner is a deploy identity, not the web runtime
- code and config are not writable by the PHP or web runtime user
- only `storage/` and `bootstrap/cache/` are writable by the runtime user
- `.env` is not runtime-writable and is typically `600` or `640`
- Nginx docroot points to Laravel `public/`
- only the intended front controller should execute via PHP-FPM
- queue workers, scheduler, and PHP-FPM do not run as `root`
- sockets, service definitions, cron entries, and deploy boundaries are tightly scoped
- databases, Redis, and internal services are not exposed publicly without clear justification

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

Detailed stages:

1. `preflight`
   - validate flags
   - collect host identity
   - detect available commands
   - establish scan roots and time budgets
2. `discovery`
   - discover Laravel apps and shared runtime surfaces
   - parse service configs and process state into normalized models
   - collect bounded filesystem metadata and log excerpts
3. `direct checks`
   - run evidence-backed checks per subsystem
4. `correlation`
   - combine writable, served, executable, runtime, and listener signals into higher-risk findings
5. `report`
   - render terminal and JSON output from the same normalized findings
6. `exit`
   - map results to stable exit codes

## Package Layout

Suggested Go package structure:

- `cmd/larainspect`
- `internal/cli`
- `internal/ux`
- `internal/model`
- `internal/runner`
- `internal/discovery`
- `internal/parsers`
- `internal/checks`
- `internal/correlators`
- `internal/report/terminal`
- `internal/report/json`
- `internal/report/schema`
- `internal/testfixtures`

Recommended check grouping inside `internal/checks`:

- `app`
- `filesystem`
- `secrets`
- `nginx`
- `phpfpm`
- `laravel`
- `livewire`
- `filament`
- `queue`
- `cron`
- `network`
- `deploy`
- `forensics`
- `exposure`
- `multiapp`

Rules:

- reporters must not contain detection logic
- checks must not execute shell commands directly
- discovery should normalize raw host data once, then share it with checks
- correlators should combine signals across checks without duplicating subsystem parsing
- shared helpers should remove duplication, but avoid turning straightforward checks into opaque frameworks
- exported names and package responsibilities should be explicit enough for OSS contributors to navigate quickly
- UX helpers should remain separate from detection logic so accessibility and interactivity can evolve independently

## Go Version And Dependency Policy

- Choose the latest broadly compatible Go release line practical for OSS adoption and document it in the repository once implementation starts.
- Prefer the Go standard library where it keeps the code simple and maintainable.
- Use mature, actively maintained ecosystem packages when they clearly reduce maintenance cost, parsing risk, CLI complexity, or test burden.
- Avoid writing commodity infrastructure from scratch if the ecosystem already provides a clean, auditable solution.
- Keep dependencies minimal, justified, and easy for contributors to review.
- Follow Go conventions for naming, error propagation, package design, and standard tool usage.

## Performance And Concurrency Strategy

The tool should be fast by design, not by accident.

Performance principles:

- prefer linear-time parsing and bounded filesystem walks
- avoid repeated reads of the same host data when one normalized snapshot can serve many checks
- keep command execution bounded by timeouts and output limits
- use caching inside one audit run when it reduces repeated parsing or stat calls

Concurrency principles:

- use goroutines where independent discovery and parsing tasks can run safely in parallel
- keep concurrency bounded with explicit worker limits rather than spawning untracked goroutines
- propagate cancellation and time budgets with `context.Context`
- preserve deterministic outputs even when collection happens concurrently
- do not parallelize in ways that increase host risk, overload the server, or make findings harder to explain

Likely good candidates for controlled concurrency:

- filesystem metadata collection across independent path groups
- parsing of already-collected config artifacts
- independent subsystem checks once the shared snapshot is ready
- bounded log and listener correlation work

Likely poor candidates for aggressive concurrency:

- command fan-out that hammers production hosts unnecessarily
- any flow that would make evidence ordering or error handling unclear
- tiny workloads where concurrency would add complexity without measurable benefit

## Testing Strategy

The implementation should be validated at several layers:

1. `unit tests`
   - parser behavior
   - helper predicates
   - severity and confidence mapping
   - remediation and evidence formatting helpers
2. `fixture-driven subsystem tests`
   - Nginx parsing
   - PHP-FPM parsing
   - Composer metadata parsing
   - cron and systemd parsing
   - filesystem classification logic
3. `check tests`
   - positive and negative cases for each direct finding
   - heuristic checks validated against representative source patterns
   - correlation checks validated against multi-signal snapshots
4. `report tests`
   - terminal golden output
   - JSON schema stability
   - exit code mapping
5. `integration-style audit tests`
   - end-to-end audit runs against deterministic snapshots or fixtures without requiring a live VPS

Testing rules:

- use Go standard testing conventions and tooling
- prefer table-driven tests where inputs and outcomes fit naturally
- keep fixtures deterministic, reviewable, and safe for OSS CI
- avoid network dependencies and mutable host assumptions in automated tests
- ensure every new check or parser ships with representative tests unless explicitly documented otherwise

## Core Data Model

### Snapshot

The normalized snapshot is the shared discovered state for one audit run.

Suggested contents:

- host metadata
- tool availability matrix
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

Suggested major snapshot structures:

- `Host`
- `ToolAvailability`
- `LaravelApp`
- `FileRecord`
- `PathPermissionRecord`
- `ProcessRecord`
- `ListenerRecord`
- `NginxSite`
- `PHPFPMPool`
- `CronEntry`
- `UnitDefinition`
- `SupervisorProgram`
- `PackageRecord`
- `LogExcerpt`
- `EvidenceError`

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
- `heuristic_details`
- `remediation_priority`

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

Checks should receive normalized evidence only. They may request helper predicates and correlation helpers, but they should not parse raw command output themselves unless they are the dedicated parser for that subsystem.

## CLI Surface

Initial command shape:

```text
larainspect audit [--app-path PATH] [--json] [--json-file PATH] [--scan-root PATH] [--include-logs] [--max-findings N]
```

Initial flags:

- `--app-path`: explicit Laravel app root when known
- `--scan-root`: additional discovery roots for multi-app detection
- `--json`: emit JSON to stdout in addition to terminal output
- `--json-file`: write JSON report to a file path chosen by the operator
- `--include-logs`: include bounded log evidence where available
- `--max-findings`: cap report volume without suppressing summary counts
- `--no-color`: disable color for non-interactive terminals

UX and accessibility expectations:

- command help should explain audit behavior, safety limits, and common usage in plain language
- output should support color and non-color modes, quiet and verbose modes, and screen-reader-friendly text flow
- interactive prompts, if added, must be skippable and safe for automation
- interactive flows should be used for clarity and onboarding, not to hide required configuration
- operators should be able to request more detail, remediation guidance, and next-step hints without rerunning the entire audit unnecessarily

No fix or mutate mode exists in v1.

## Safety Rules For Implementation

- no shell interpolation through `sh -c`
- explicit command allowlist in the runner
- per-command timeouts
- bounded stdout/stderr capture
- bounded file reads
- redact obvious secrets from excerpts
- treat permission failures as evidence, not crashes
- never claim certainty where only heuristics exist

Runner behavior rules:

- preserve argv boundaries exactly
- record exit status and truncation state for every command
- classify missing command vs timeout vs permission failure separately
- support OS-specific fallback command sequences without leaking shell expansion
- expose redaction hooks for secrets discovered in stdout/stderr or file excerpts

Implementation style rules:

- keep methods and helper names descriptive; optimize for contributor comprehension over short names
- prefer explicit data flow over hidden mutation or magic registration side effects
- factor repeated logic into shared helpers only when the shared abstraction stays simpler than duplication

## Checks By Subsystem

### 1. App Discovery And Validation

Goals:

- validate explicit app path
- discover Laravel apps from scan roots
- detect Laravel, Filament, Livewire, Horizon, and Octane
- detect multi-app overlap
- detect ambiguous app roots and shared runtime identities
- identify Laravel version from Composer metadata when possible

Data sources:

- filesystem reads of `artisan`, `bootstrap/app.php`, `config/app.php`, `public/index.php`, `composer.json`, `composer.lock`
- `vendor/composer/installed.json` when present
- `find` for scan roots and multiple app discovery

Exact evidence and commands:

- direct file reads of required Laravel markers
- `find <scan-roots> -maxdepth 4 -type f \( -name artisan -o -path '*/bootstrap/app.php' \)`
- `stat` for candidate roots and key files
- parse `composer.json`, `composer.lock`, and `vendor/composer/installed.json`

Representative checks:

- provided path is not a Laravel app
- multiple Laravel apps exist on the host
- app path is ambiguous due to symlink indirection or nested releases
- multiple apps share the same runtime user, writable path, socket, or queue identity

### 2. Ownership And Permissions

Goals:

- inspect ownership and mode of root, code, writable, and sensitive files
- distinguish expected writable paths from unexpected ones
- detect writable plus executable combinations
- detect deploy drift caused by root-run `artisan` or `composer`
- detect world-readable sensitive files and unexpected SUID/SGID bits

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

Exact evidence and commands:

- `stat -c` or portable `stat -f` wrappers for owner, group, mode, inode type
- `find <app> \( -type d -perm -0002 -o -type f -perm -0002 \)` for world-writable paths
- `find <app> \( -type d -perm -2000 -o -type f -perm -4000 -o -type f -perm -2000 \)` for SGID/SUID surprises
- `namei -l <path>` for path traversal ownership chains
- `getfacl -p <path>` when available for suspicious ACLs
- `readlink -f <path>` for symlink target validation

Representative checks:

- code tree writable by runtime user
- `.env` owned or writable by runtime user
- `artisan`, `public/index.php`, `composer.*`, `config/`, `routes/`, `vendor/`, or `app/` writable by runtime user
- `777` directories, `666` files, or world-readable secrets
- group-writable code when the group includes the web runtime
- symlink from served paths into sensitive or writable locations

### 3. Secrets And Config Safety

Goals:

- inspect `.env`, backup files, config cache, debug flags, and public artifact exposure
- detect publicly reachable sensitive artifacts or broadly readable secrets
- validate `APP_KEY` structure and obvious production-mode flags
- detect backup and deployment leftovers inside or near docroot

Data sources:

- direct file reads for `.env`, cached config, Laravel config files
- `find` for `.env.*`, swap files, archives, dumps, logs, and hidden VCS artifacts

Exact evidence and commands:

- direct bounded reads of `.env`, `bootstrap/cache/*.php`, and selected `config/*.php`
- `find <app> -maxdepth 4 \( -name '.env*' -o -name '*.sql' -o -name '*.zip' -o -name '*.tar' -o -name '*.gz' -o -name '*.log' -o -name '.git' -o -name '.svn' \)`
- `stat` and `namei -l` for `.env` ownership and ancestor permissions

Representative checks:

- `.env` symlinked unexpectedly
- `.env` backup file inside web-accessible path
- `.env` writable by runtime user despite runtime not needing write access
- `APP_DEBUG=true` in apparent production deployment
- invalid or missing `APP_KEY`
- cached config broadly readable or ownership-drifted
- dangerous debug tooling present in production metadata

### 4. Nginx Boundary Audit

Goals:

- validate docroot and front controller design
- inspect PHP execution scope, deny rules, hidden file handling, admin path exposure, and traversal hazards
- inspect TLS, server token, rate-limit, and log handling signals when config is visible

Data sources:

- `nginx -T`
- fallback reads from common Nginx config paths
- process and listener correlation from `ps` and `ss`

Exact evidence and commands:

- `nginx -T`
- fallback reads from `/etc/nginx/nginx.conf`, `/etc/nginx/conf.d/*`, `/etc/nginx/sites-enabled/*`, `/usr/local/etc/nginx/*`
- `ps -eo user,group,pid,ppid,comm,args`
- `ss -lntup`

Representative checks:

- project root served instead of `public/`
- generic `\.php$` execution enabled instead of front-controller-only execution
- missing deny rules for `.env`, VCS paths, backups, or hidden files
- upload or storage path can execute PHP
- `autoindex on` in application site
- suspicious `alias` or `root` combinations creating traversal or exposure risk
- admin/login locations lack any visible extra protection where expected
- trusted proxy topology likely mismatched to reverse proxy layout

### 5. PHP-FPM Audit

Goals:

- inspect pool identity, socket or TCP exposure, socket ACLs, shared pools, and risky settings
- inspect session/upload temp paths and environment handling
- detect multiple apps sharing the same pool or socket

Data sources:

- `php-fpm -tt`
- versioned `php-fpm8.* -tt`
- fallback reads from common pool config directories
- `ps`
- `ss`

Exact evidence and commands:

- `php-fpm -tt`
- versioned fallbacks such as `php-fpm8.1 -tt`, `php-fpm8.2 -tt`, `php-fpm8.3 -tt`
- reads from `/etc/php*/fpm/pool.d/*`, `/etc/php-fpm.d/*`, `/usr/local/etc/php-fpm.d/*`
- `ps -eo user,group,pid,ppid,comm,args`
- `ss -lntup`
- `ss -lxnp`

Representative checks:

- PHP-FPM pool running as root
- pool socket world-accessible or overly broad via ACL
- FPM listening on TCP without visible network restriction
- shared pool used by multiple Laravel apps
- FPM runtime can write application code or config
- risky `clear_env`, temp path, or session path behavior

### 5A. PHP Runtime And Execution Boundary

Goals:

- verify that PHP execution is limited to intended entry points and not available in writable or upload paths
- detect dropped or arbitrary PHP execution opportunities in `public/`, `public/storage`, uploads, temp paths, and writable directories
- inspect PHP-relevant runtime hardening signals that materially affect Laravel attack surface

Representative checks:

- arbitrary `.php` files in served paths can execute
- writable upload or storage paths can execute PHP
- random dropped PHP files under `public/` would be routed to the interpreter
- PHP temp or session paths are insecurely exposed or writable beyond intended scope

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

Explicit questions this layer must answer:

- can the web runtime write anything that later changes code execution
- can the web runtime or worker alter request routing or authentication behavior
- can a writable served path become arbitrary PHP execution or file-disclosure surface
- can cron, queue, or service identities alter code or service definitions

Representative checks:

- writable `public/`, `app/`, `routes/`, `config/`, `vendor/`, `bootstrap/app.php`, `bootstrap/providers.php`, or `public/index.php`
- writable directory under `public/` containing `.php`
- writable symlink target exposed through `public/storage`
- writable Nginx include or PHP-FPM pool config path
- writable Supervisor or systemd unit files
- writable cron definition or script target influencing deploy/runtime behavior

### 7. Laravel Heuristics

Goals:

- infer security posture for auth, sessions, CSRF, throttling, trusted proxies, trusted hosts, and admin/API separation
- inspect session cookie safety, exposed admin/auth routes, and unexpected API/auth packages

Data sources:

- `.env`
- `config/*.php`
- route files
- middleware/provider files when directly relevant

Exact evidence and commands:

- direct reads of `config/app.php`, `config/session.php`, `config/sanctum.php`, `config/auth.php`, `config/cors.php`
- direct reads of `routes/web.php`, `routes/api.php`, and common route registration files
- parse `.env` values relevant to environment, session, cookie, proxy, and debug handling

These findings must remain heuristic unless direct evidence proves misconfiguration.

Representative checks:

- session cookie not marked secure in a production-like deployment
- CSRF bypass patterns appear overly broad
- obvious auth endpoints appear unthrottled
- trusted proxies or hosts appear dangerously broad for visible topology
- admin and public auth surfaces appear mixed without clear separation
- Sanctum, Passport, Telescope, Pulse, or similar surfaces appear enabled unexpectedly

### 8. Livewire Heuristics

Goals:

- detect uploads, temp upload exposure, risky public properties, likely missing `#[Locked]`, and likely missing authorization on mutations
- inspect package age and support-line signals where determinable from installed version metadata

Data sources:

- Composer metadata
- Livewire component source files
- config files
- route/provider files

Exact evidence and commands:

- parse Composer package metadata for Livewire presence and version
- direct bounded reads of Livewire component classes and related config files
- targeted `find <app>/app -type f \( -name '*.php' \)` with content scanning by the Go parser

Example heuristic patterns:

- `WithFileUploads`
- public properties such as `id`, `user_id`, `tenant_id`, `role_id`
- update/delete methods without obvious authorization calls

Representative checks:

- `WithFileUploads` used without nearby validation signals
- temporary upload storage appears public or served
- security-sensitive public properties lack obvious locking signals
- mutating component actions lack obvious authorization calls
- stale Livewire line appears likely out of support

### 9. Filament Heuristics

Goals:

- detect panel path, auth middleware, guest exposure, policy signals, MFA signals, and tenant-access signals
- inspect model exposure risks and production access hardening signals

Data sources:

- Composer metadata
- panel provider files
- resource classes
- auth-related config and middleware references

Exact evidence and commands:

- parse Composer metadata for Filament presence and version
- direct reads of panel providers, resources, pages, widgets, policies, and auth-related config files
- targeted content scanning of Filament-related PHP classes

Representative checks:

- Filament panel exposed on default public path without visible extra safeguards
- tenant-aware code lacks obvious tenant access checks
- resource/page/action classes show no visible policy enforcement signals
- MFA support absent on a sensitive admin surface where the version likely supports it
- hidden model attribute exposure risk via Filament or Livewire binding patterns

### 10. Queues, Horizon, Workers, Supervisor, Systemd

Goals:

- inspect worker identity, root execution, stale release paths, Horizon exposure, and permission drift across workers
- inspect logs, restart policy, env drift, and daemonized artisan leftovers

Data sources:

- `ps`
- `systemctl`
- `systemctl cat`
- Supervisor config paths
- process command lines

Exact evidence and commands:

- `ps -eo user,group,pid,ppid,comm,args`
- `systemctl list-units --type=service --all`
- `systemctl cat <unit>`
- `systemctl show <unit>`
- reads from Supervisor config paths such as `/etc/supervisor/conf.d/*` and `/etc/supervisord.d/*`
- direct reads of Horizon config and queue-related Laravel config files

Representative checks:

- queue worker or Horizon process running as root
- Horizon dashboard appears installed and exposed without visible protection
- worker still points at old release path
- worker and web runtime share unsafe permissions or broader-than-needed code access
- orphaned or duplicate artisan queue processes running outside managed service definitions

### 11. Scheduler And Cron

Goals:

- detect duplicate schedulers, root execution, direct artisan jobs, and unsafe cron patterns
- inspect backup jobs and maintenance scripts for public-path leakage

Data sources:

- `crontab -l`
- `/etc/crontab`
- `/etc/cron.d/*`
- spool locations where readable

Exact evidence and commands:

- `crontab -l` for readable users when applicable
- direct reads of `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.daily/*`, `/var/spool/cron/*` where accessible
- path and ownership inspection for referenced scripts

Representative checks:

- scheduler runs as root
- multiple scheduler entries cause conflicting execution
- custom cron calls `artisan` directly instead of going through the scheduler baseline
- cron output redirected into insecure or public locations
- backup scripts dump archives or SQL files into docroot or served paths

### 12. Port And Network Exposure

Goals:

- map listeners to processes and classify public vs local exposure
- detect FPM over TCP, public Redis or databases, exposed admin tools, and accidental dev servers

Data sources:

- `ss -lntup`
- `ss -lxnp`
- `ip -brief addr`
- firewall summaries from `ufw`, `firewalld`, `nft`, `iptables` when available

Exact evidence and commands:

- `ss -lntup`
- `ss -lxnp`
- `ip -brief addr`
- `ufw status`
- `firewall-cmd --state` and `firewall-cmd --list-all`
- `nft list ruleset`
- `iptables -S`

Representative checks:

- Redis, MySQL, or Postgres listening on public interfaces
- PHP-FPM over TCP reachable beyond local boundary
- Supervisor inet HTTP interface exposed
- Octane, Reverb, Soketi, dev servers, or debug dashboards bound to `0.0.0.0`
- internal-only services exposed without visible justification

### 12A. Database And Internal Service Hardening

Goals:

- inspect whether MySQL, Postgres, Redis, and adjacent internal services are bound and exposed safely
- detect public listeners, weak local boundaries, and risky reuse across apps

Representative checks:

- MySQL or Postgres publicly reachable without clear justification
- Redis exposed publicly or without visible access controls
- multiple apps share sensitive internal services in ways that increase lateral movement risk

### 13. Deployment And Release Model

Goals:

- detect in-place vs release-based deploys, stale writable releases, root-run deploy habits, `.git` exposure risk, and unsafe backups

Data sources:

- symlink and ownership inspection
- service definitions
- release directory layout
- Composer artifacts and deploy script traces where readable

Exact evidence and commands:

- `stat`, `readlink -f`, `namei -l`, and `find` across release/current/shared layout
- direct reads of deploy scripts, unit files, and shell history artifacts only when explicitly accessible and safe to inspect
- parse `composer.lock`, Composer install artifacts, and presence of `vendor/composer/installed.json`

Representative checks:

- release model leaves old releases writable
- shared `.env` or storage layout crosses app boundaries unsafely
- deploy user has overly broad sudo hints in visible config
- Composer or artisan cache commands appear to run as root
- `.git` present in production path
- production install does not appear to use `--no-dev`
- Composer audit support should be enabled in CI or deploy validation

### 13A. Backup, Restore, And Permission Drift

Goals:

- detect whether backup, restore, and deploy processes are likely to break the hardened ownership model
- surface permission drift after deploys, restores, root-run artisan, or root-run Composer usage

Representative checks:

- restored or deployed paths made the runtime user owner of code or `.env`
- backup artifacts or dumps land in served or broadly readable locations
- permission drift makes runtime-writable paths broader than intended

### 14. Logs And Possible Compromise Indicators

Goals:

- surface suspicious recent files, shells, dumps, archives, strange symlinks, and unusual changes in writable paths

Data sources:

- bounded `tail` of Laravel, Nginx, PHP-FPM, auth, queue, and cron logs
- `find` constrained by mtime, type, and suspicious name patterns

Exact evidence and commands:

- bounded reads and `tail -n` on selected logs when accessible
- `find <app> \( -path '*/public/*' -o -path '*/storage/*' -o -path '*/bootstrap/cache/*' \) -type f -mtime -30`
- `find <app> -type f \( -iname '*shell*' -o -iname '*cmd*' -o -iname '*alfa*' -o -iname '*wso*' -o -iname '*mailer*' -o -iname '*bypass*' \)`
- symlink inspection under served and writable paths

This section must be explicitly separated from confirmed findings.

Representative checks:

- recently modified PHP file under served writable path
- suspicious archive or dump created recently in app or public path
- suspicious symlink inserted into `public/` or `storage/`
- unexpected file under `bootstrap/cache/`
- possible webshell indicator by filename or location

### 14A. Linux, SSH, And Service Hardening Signals

Goals:

- inspect Linux host-level hardening signals that materially affect Laravel VPS risk
- inspect SSH, sudo, service privilege boundaries, and systemd hardening signals relevant to the app

Representative checks:

- direct root SSH access appears enabled where it should be disabled
- deploy user has overly broad sudo hints
- PHP-FPM or app-adjacent services appear more privileged than necessary
- service definitions do not constrain writable paths where practical

### 15. Multi-App And Lateral Movement

Goals:

- detect shared runtime users, shared FPM sockets, cross-app secret readability, cross-app write paths, and dangerous credential reuse hints

Data sources:

- app discovery results
- pool and socket mapping
- permissions and ACL data
- listener and service correlation

Exact evidence and commands:

- correlate previously collected app, pool, socket, listener, and permission records
- compare `.env` ownership, readability, and credential patterns only at a metadata level unless direct reads are already in-bounds for each discovered app

Representative checks:

- app A can read app B `.env`
- multiple apps share same FPM socket or runtime user
- one app can write another app storage or code path
- shared Redis or database credentials suggest easy lateral movement

## Exact Commands And Data Sources Summary

Preferred commands and sources by category:

- host identity: `hostname`, `uname -a`, `/etc/os-release`
- filesystem metadata: `stat`, `find`, `namei -l`, `readlink -f`, `getfacl`
- process inventory: `ps -eo user,group,pid,ppid,comm,args`
- listeners and sockets: `ss -lntup`, `ss -lxnp`
- network interfaces: `ip -brief addr`
- systemd: `systemctl list-units --type=service --all`, `systemctl show`, `systemctl cat`
- Nginx: `nginx -T` plus fallback reads of config directories
- PHP-FPM: `php-fpm -tt` plus versioned variants and pool config file reads
- cron: `crontab -l`, `/etc/crontab`, `/etc/cron.d/*`, readable spool files
- logs: bounded direct reads and `tail -n` on relevant logs
- Laravel metadata: `composer.json`, `composer.lock`, `vendor/composer/installed.json`, `config/*.php`, route files, selected source scans

If any command is missing, denied, or unsupported on the host, record an explicit unknown rather than failing the run.

## Output Design

### Terminal Report

The terminal report must render these sections in order:

1. Summary
2. Critical findings
3. High findings
4. Medium findings
5. Low findings
6. Informational notes
7. Possible compromise indicators
8. Unknown / could not inspect
9. Recommended next actions

Summary fields:

- hostname
- timestamp
- selected app path
- detected stack
- discovered apps count
- finding counts by severity and class
- exit code rationale

### JSON Schema Draft

```json
{
	"schema_version": "1.0.0",
	"hostname": "web-01",
	"timestamp": "2026-03-12T12:00:00Z",
	"app_path": "/var/www/example/current",
	"detected_stack": {
		"laravel": { "present": true, "version": "11.9.0" },
		"filament": { "present": true, "version": "3.2.95" },
		"livewire": { "present": true, "version": "3.5.0" },
		"horizon": { "present": false },
		"octane": { "present": false },
		"nginx": { "present": true },
		"php_fpm": { "present": true },
		"redis": { "present": true },
		"mysql": { "present": false },
		"postgres": { "present": false }
	},
	"summary": {
		"critical": 1,
		"high": 3,
		"medium": 4,
		"low": 2,
		"informational": 6,
		"unknown": 5,
		"compromise_indicators": 2,
		"exit_code": 2
	},
	"findings": [
		{
			"id": "fs.runtime_writable_code",
			"class": "direct",
			"subsystem": "filesystem",
			"title": "Runtime user can write application code",
			"severity": "Critical",
			"confidence": "confirmed",
			"why_it_matters": "A compromised web runtime can persist code execution by modifying application files.",
			"evidence": ["path /var/www/app/current/routes/web.php owned by deploy:www-data mode 664", "php-fpm pool user is www-data"],
			"affected": [
				{ "type": "path", "value": "/var/www/app/current/routes/web.php" },
				{ "type": "process", "value": "php-fpm:www-data" }
			],
			"remediation": "Make code paths owned by the deploy user and non-writable to the PHP runtime. Limit runtime write access to storage/ and bootstrap/cache/.",
			"remediation_priority": "immediate",
			"commands": [
				{ "argv": ["stat", "-c", "%U %G %a %n", "/var/www/app/current/routes/web.php"], "status": 0 },
				{ "argv": ["ps", "-eo", "user,group,pid,ppid,comm,args"], "status": 0 }
			],
			"heuristic_details": null
		}
	],
	"unknowns": [
		{
			"subsystem": "nginx",
			"target": "/etc/nginx/sites-enabled/app.conf",
			"reason": "permission_denied"
		}
	],
	"command_runs": [
		{
			"argv": ["nginx", "-T"],
			"status": 1,
			"stderr_excerpt": "permission denied",
			"truncated": false
		}
	]
}
```

### Exit Codes

- `0`: no critical or high findings
- `1`: one or more high findings, no critical findings
- `2`: one or more critical findings
- `3`: runtime or inspection errors prevented trustworthy completion

## Sample Findings

### Confirmed Critical

- Title: `Project root is served as Nginx docroot`
- Why it matters: exposes non-public Laravel files and makes direct source or secret disclosure more likely
- Evidence: Nginx `root` points at `/var/www/app/current` instead of `/var/www/app/current/public`
- Affected: Nginx vhost config and application root
- Remediation: point docroot to `public/` and block direct access to sensitive files
- Confidence: `confirmed`

### Confirmed High

- Title: `Filament admin panel exposed on default public path without visible extra controls`
- Why it matters: admin surfaces attract brute-force and credential-stuffing attacks and deserve stricter hardening than ordinary app routes
- Evidence: Filament panel provider path `/admin`; no visible IP restriction, extra auth middleware, or MFA signals
- Affected: Filament panel route group
- Remediation: add explicit access restrictions, strong auth controls, MFA where supported, and rate limiting
- Confidence: `probable`

### Heuristic Medium

- Title: `Livewire component mutates model state without obvious authorization check`
- Why it matters: security-sensitive component actions can become privilege escalation or tenant breakout paths
- Evidence: component uses public property `tenant_id`; `save()` mutates records; no obvious `authorize()` or policy call in the method body
- Affected: specific Livewire component file
- Remediation: verify authorization and locking strategy, add policy enforcement, and review property locking
- Confidence: `possible`

### Compromise Indicator

- Title: `Suspicious recently modified PHP file under public uploads path`
- Why it matters: dropped PHP files in served writable paths can indicate attempted persistence or active webshell placement
- Evidence: `/var/www/app/current/public/uploads/alfa.php` created within the last 7 days
- Affected: served writable directory
- Remediation: investigate immediately, preserve evidence, and remove only through incident-response workflow
- Confidence: `probable`

## Laravel/Filament/Livewire Security Heuristics That Are Not Provable From VPS Inspection Alone

These checks must be reported as heuristics unless direct evidence exists:

- missing policies on Filament resources, pages, or actions
- weak tenant authorization or tenant ID guessing risk
- Livewire property tampering risk due to missing locking
- missing file upload validation or dangerous file type acceptance
- dangerous mass assignment assumptions inferred from component patterns
- guest panel exposure caused by intentional but weak Filament configuration
- missing throttling on custom login or admin routes
- missing MFA on sensitive admin surfaces where the version likely supports it
- hidden model attributes not actually hidden in Filament or Livewire bindings

The report should explicitly explain that these are code-level security signals inferred from static patterns and deployment context, not proven vulnerabilities.

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
