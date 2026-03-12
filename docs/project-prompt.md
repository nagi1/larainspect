# Project Prompt

## Project

Build `larainspect`, an open-source, read-only Laravel Linux VPS security auditor CLI written in Go.

## Mission

Audit production Laravel VPS environments safely and deeply enough to identify dangerous conditions, weak boundaries, permission drift, exposed attack surfaces, and likely paths to RCE, privilege escalation, credential leakage, lateral movement, or persistence.

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

## Non-Negotiable Product Constraints

- Read-only by default.
- No mutation of files, permissions, ownership, services, firewall rules, or application code.
- Safe to run on production systems.
- No internet dependency during an audit run.
- Graceful degradation when commands, files, or privileges are unavailable.
- Explicit distinction between confirmed findings, heuristic findings, and unknowns.

## Product Outcomes

The tool must answer:

- what is dangerous
- what is weak
- what is misconfigured
- what is unexpectedly writable
- what can lead to RCE, privilege escalation, credential leakage, lateral movement, or persistence
- what specifically affects Laravel, Filament, Livewire, Nginx, PHP-FPM, queues, cron, deployment safety, and multi-app boundaries

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

## Design Direction

`larainspect` should behave like a small framework:

- thin CLI entrypoint
- modular discovery layer
- modular subsystem checks
- correlation layer for multi-signal risks
- structured finding model
- pluggable reporters
- fixture-driven tests

Implementation direction:

- build as a standalone Go binary
- prefer standard library plus a minimal dependency set
- keep shell execution behind one safe command-runner
- use compile-time check registration rather than runtime plugins
- make new checks easy to add without touching reporters or core execution flow

## v1 Delivery Sequence

1. Project-management docs and operating rules
2. Core CLI and finding/report model
3. Discovery and command-runner infrastructure
4. Foundational checks: app discovery, ownership/perms, secrets, Nginx, PHP-FPM
5. Correlation checks: writable vs executable, runtime identities, multi-app overlap
6. Framework-specific heuristics: Laravel, Livewire, Filament
7. Operational checks: queues, cron, network exposure, deployment model, logs/forensics
8. Report polishing, JSON schema stabilization, fixtures, regression tests, release docs
