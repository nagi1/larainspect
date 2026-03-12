# Project Prompt

## Project

Build `larainspect`, an open-source, read-only Laravel Linux VPS security auditor CLI written in Go.

Go is a deliberate product choice here: the tool should be fast, portable, simple to install, easy to operate, and able to use concurrency safely when that materially improves audit performance.

## Mission

Audit production Laravel VPS environments safely and deeply enough to identify dangerous conditions, weak boundaries, permission drift, exposed attack surfaces, and likely paths to RCE, privilege escalation, credential leakage, lateral movement, or persistence.

Operate like a paranoid senior Linux security engineer and Laravel security auditor. Assume the target server may already contain bad deploy habits, writable code paths, dropped webshells, exposed admin routes, unsafe storage symlinks, permission drift, stale packages, and over-privileged workers.

Assume the intended hardened deployment model is strict:

- the application never writes `.env` at runtime
- code and config are read-only to the runtime user
- only `storage/` and `bootstrap/cache/` are runtime-writable
- Nginx serves only `public/`
- only the intended Laravel front controller should execute through PHP-FPM

## Target Stack

- Laravel
- Nginx
- PHP-FPM
- systemd
- cron
- queues / Horizon / Supervisor when present
- Filament admin panels
- Livewire components
- optional Redis / MySQL / Postgres

The CLI should follow Laravel-style UX expectations where practical:

- clear subcommands and flags
- readable terminal sections under pressure
- opinionated but evidence-backed output
- remediation guidance phrased for operators and deploy workflows
- helpful, informative, beginner-friendly explanations without watering down technical accuracy
- accessible output and interaction patterns that work well for both new operators and experienced engineers
- configurable behavior for output format, verbosity, scan scope, and operator preferences
- interactive guidance where it improves safety, comprehension, or audit usability

## Non-Negotiable Product Constraints

- Read-only by default.
- No mutation of files, permissions, ownership, services, firewall rules, or application code.
- Safe to run on production systems.
- No internet dependency during an audit run.
- Graceful degradation when commands, files, or privileges are unavailable.
- Explicit distinction between confirmed findings, heuristic findings, and unknowns.
- No internet access required during an audit run.
- No hidden side effects, temporary edits, or best-effort fixes.
- Open-source maintainability is a product requirement, not a nice-to-have.
- Implementation should follow `DRY`, `KISS`, and descriptive naming by default.
- The project should target the latest broadly compatible Go release practical for OSS adoption.
- The project should embrace the Go ecosystem and avoid rebuilding commodity infrastructure from scratch.
- The implementation should take advantage of what makes Go valuable for this tool: speed, portability, strong standard tooling, mature ecosystem packages, and pragmatic concurrency when useful.
- The implementation must be tested enough to demonstrate that the auditor actually works in practice.
- Testing should follow Go best practices and conventions and should be suitable for OSS CI.

## Product Outcomes

The tool must answer:

- what is dangerous
- what is weak
- what is misconfigured
- what is unexpectedly writable
- what can lead to RCE, privilege escalation, credential leakage, lateral movement, or persistence
- what specifically affects Laravel, Filament, Livewire, Nginx, PHP-FPM, queues, cron, deployment safety, and multi-app boundaries

The audit must also answer a decisive correlation question:

- can the web runtime, queue worker, scheduler, or shared runtime identity write anything that later changes code execution, request routing, authentication, secret access, or server behavior

## Output Contract

The CLI must produce:

- a human-readable terminal report
- optional JSON output
- severity-classified findings
- evidence-backed remediation guidance
- reliable exit codes

Every finding must contain:

- title
- severity
- why it matters
- exact evidence found
- affected path/process/config
- suggested remediation
- confidence level

The report must separate:

- direct findings
- heuristic findings
- possible compromise indicators
- unknown or could-not-inspect items

## Design Direction

`larainspect` should behave like a small framework:

- thin CLI entrypoint
- modular discovery layer
- modular subsystem checks
- correlation layer for multi-signal risks
- structured finding model
- pluggable reporters
- fixture-driven tests
- contributor-friendly check registration and subsystem boundaries
- a strong operator UX layer for accessibility, guidance, and configuration

Testing direction:

- use standard Go testing conventions and tooling
- prefer table-driven tests for parsers, check logic, severity mapping, and report rendering
- use deterministic fixtures and golden tests for representative host states and report output
- add integration-style tests for the discovery and audit pipeline where practical without needing a live production server
- verify the CLI and report contracts with automated tests before considering a phase complete
- validate beginner-friendly help text, interactive flows, and output ergonomics with CLI-focused regression tests

Implementation direction:

- build as a standalone Go binary
- prefer standard library plus a minimal, justified dependency set
- keep shell execution behind one safe command-runner
- use compile-time check registration rather than runtime plugins
- make new checks easy to add without touching reporters or core execution flow
- keep subsystem parsers and correlation logic separate so open-source contributors can add checks safely
- treat security-sensitive heuristics as first-class, but never overstate their certainty
- prefer mature ecosystem packages when they materially improve parsing, CLI ergonomics, testing, or portability
- avoid custom infrastructure where established Go packages already solve the problem cleanly and reviewably
- keep package, type, and method names explicit enough that contributors can understand intent without chat history
- use concurrency intentionally for bounded discovery, parsing, and correlation workloads where it improves speed without harming determinism, safety, or debuggability

## Required Audit Scope

The design and eventual implementation must cover:

- app discovery and framework validation
- ownership and permission audit
- `.env`, secrets, and config safety
- Nginx boundary audit
- PHP-FPM audit
- PHP runtime and PHP execution boundary hardening
- writable-paths vs executable-paths correlation
- Livewire-specific heuristics
- Filament-specific heuristics
- Laravel auth, sessions, CSRF, throttling, and proxy handling
- queue, Horizon, worker, Supervisor, and systemd surfaces
- scheduler and cron
- port and network exposure
- MySQL, Postgres, Redis, and internal service exposure
- Linux host hardening signals relevant to Laravel VPS deployments
- SSH, sudo, deploy-user, backup, restore, and permission-drift risks
- deployment and release model
- logs, error handling, and forensic clues
- dangerous package and tool exposure
- multi-app and lateral movement risks

The audit baseline should track the actionable checklist in [docs/security-checklist.md](/Users/nagi/code/larainspect/docs/security-checklist.md).

## Delivery Rule

Before any implementation work, the project must first produce:

1. an architecture plan for the script
2. the list of checks grouped by subsystem
3. the exact commands and data sources for each check
4. the output schema
5. sample findings

Do not write the audit code until those design artifacts are complete and accepted.

## v1 Delivery Sequence

1. Project-management docs and operating rules
2. Architecture and audit inventory signoff
3. Core CLI and finding/report model
4. CLI UX, accessibility, interactivity, and configuration surface
5. Discovery and command-runner infrastructure
6. Foundational checks: app discovery, ownership/perms, secrets, Nginx, PHP-FPM
7. Correlation checks: writable vs executable, runtime identities, multi-app overlap
8. Framework-specific heuristics: Laravel, Livewire, Filament
9. Operational checks: queues, cron, network exposure, deployment model, logs/forensics
10. Report polishing, JSON schema stabilization, fixtures, regression tests, release docs
