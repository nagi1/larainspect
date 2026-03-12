# Long-Term Memory

This file stores stable project decisions, assumptions, and constraints that should persist across implementation phases.

## Stable Decisions

- Project name: `larainspect`
- Binary name: `larainspect`
- Product type: standalone CLI auditor for Laravel VPS environments
- Operating mode: read-only by default
- Primary audience: operators, security engineers, Laravel teams, incident responders, and auditors
- Style target: Laravel-like CLI UX without requiring installation inside a Laravel application
- Implementation language: Go
- Distribution model: standalone static-ish Go binary, no internet dependency during audit runs
- Open-source extensibility is a core product requirement
- Initial deliverable is design documentation, not code
- Implementation style should favor `DRY`, `KISS`, and descriptive naming
- The codebase should target the latest broadly compatible Go release line practical for OSS contributors
- The project should use the Go ecosystem pragmatically instead of rebuilding commodity infrastructure from scratch
- The project is expected to be tested enough to prove behavior, not just compile cleanly
- CLI UX is a first-class requirement: helpful, informative, configurable, interactive where useful, accessible, and beginner-friendly
- Go is a deliberate choice for speed, portability, simple distribution, and safe concurrency where it helps audit performance
- The hardened Laravel VPS baseline is tracked explicitly in `docs/security-checklist.md`
- Foundation currently targets Go `1.23` as the minimum supported contributor toolchain
- Foundation intentionally uses the Go standard library only; dependency additions must be justified in later phases
- The public JSON report draft version is `v0alpha1`
- Foundation keeps execution sequential but carries a `WorkerLimit` through the execution context for later bounded concurrency
- Golden report tests live alongside reporter packages and shared deterministic fixtures live in `internal/testfixtures`
- Foundation exit codes are severity-based: `0`, `2`, `10`, `20`, `30`, `40`, and `50`
- JSON severity summaries keep all severity buckets present, including zero counts, for machine-readable stability

## Architecture Direction

- Build the tool as a modular standalone Go CLI application.
- Keep system inspection command usage behind one safe command runner.
- Keep findings in a normalized schema shared by terminal and JSON reporters.
- Separate discovery, checks, correlation, and reporting.
- Use compile-time registration for checks instead of runtime plugin loading.
- Treat the discovered host/app state as a normalized snapshot consumed by checks.
- Keep subsystem parsers reusable so many checks can share one normalized source of truth.
- Keep reporters free of detection and correlation logic.
- Keep package boundaries and identifiers explicit so contributors can extend checks safely.
- Prefer simple, maintainable abstractions over highly generic internal frameworks.
- Use Go-standard testing patterns with deterministic fixtures, table-driven tests, and regression coverage for public contracts.
- Use bounded, context-aware concurrency where it materially improves audit speed without hurting determinism or maintainability.

## Detection Policy

- Prefer direct evidence from system state over inference.
- Label heuristics clearly and lower confidence when code-level certainty is not possible.
- Treat writable-plus-served-plus-executable combinations as a first-class correlation risk.
- Treat multi-app overlap and runtime identity sharing as first-class lateral movement risks.
- Treat possible compromise indicators as their own output class, separate from confirmed findings.
- Audit Laravel-specific operational surfaces including Filament, Livewire, Horizon, cron, and deployment patterns.
- Cover the checklist baseline across Laravel, PHP, Nginx, MySQL/Postgres/Redis exposure, Linux host signals, SSH, backups, restores, and permission drift.

## Safety Policy

- No write operations in v1.
- No permission changes, file edits on target hosts, service reloads, or firewall changes.
- No network access required during an audit run.
- The design must assume partial compromise and partial visibility.

## UX Policy

- Terminal output must be easy to scan under pressure.
- JSON output must be stable and machine-readable.
- Exit codes must reflect audit severity and runtime failure distinctly.
- Findings must always include why it matters, evidence, affected target, remediation, and confidence.
- Unknowns must be rendered explicitly rather than silently omitted.

## Open Questions

- Exact package/dependency footprint for the standalone Go CLI, within the policy of using mature justified packages only
- Whether v1 ships as raw source only or also as prebuilt release binaries
- Whether to support check filtering and profiles in the first release
- Whether to ship SARIF or other machine-readable output beyond JSON in a later phase

## Update Rule

Add entries here when a decision affects architecture, public interfaces, testing strategy, or long-term contributor expectations.
