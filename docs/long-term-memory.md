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
- The explicit JSON schema draft lives in `internal/report/schema/report.schema.json` and is exposed by the schema package for tooling
- CLI verbosity levels are `quiet`, `normal`, and `verbose`
- CLI scan scopes are `auto`, `host`, and `app`
- Discovery now supports explicit `--app-path` inspection plus repeatable `--scan-root` inputs for Laravel app detection
- User-provided discovery input must never fail silently; invalid requested app paths should become explicit unknowns with evidence instead of disappearing from the report
- Guided UX is opt-in through `--interactive`; prompts go to stderr so JSON stdout stays clean
- Foundation CLI output remains plain ASCII without ANSI colors and exposes `--screen-reader` and color preferences as stable operator options
- CLI orchestration should stay split into small steps: parse config, resolve guided input, build execution context, run audit, and render output
- Output-format normalization and config validation should stay centralized in the model layer instead of being reimplemented ad hoc in CLI handlers
- Repeated failure-to-unknown mapping and repeated terminal-only rendering branches should be extracted into helpers early instead of duplicated across execution paths
- Favor descriptive helper names and early returns when adding new CLI or runner behavior; do not let one function accumulate parsing, validation, execution, and rendering concerns at once
- Task-3 foundation starts from normalized per-app path metadata, limited environment indicators, and bounded artifact scans collected during discovery; direct checks should consume that snapshot data instead of reading files ad hoc
- Task-5 operational checks should consume normalized Supervisor, systemd, cron, and listener snapshot records rather than reparsing raw config or command output inside checks
- Task-5 forensic indicators must stay high-signal: expected Laravel cache artifacts such as `bootstrap/cache/config.php` and compiled view files are not compromise indicators by themselves
- Task-5 host-only collectors such as SSH, sudo, and firewall inspection must stay scope-gated to `host` scans; app and auto scans should not inherit host-level unknowns or noise when no host audit was requested
- Task-5 network exposure checks currently define "broad" binds narrowly as wildcard listener addresses such as `0.0.0.0`, `::`, or `*`; private RFC1918 binds are not treated as broadly exposed by default without stronger evidence
- Timeout classification in discovery must use `errors.Is(err, context.DeadlineExceeded)` instead of string matching alone so wrapped command timeouts stay stable across Go and OS variations
- Hardened Laravel fixtures must use realistic secure defaults: valid `APP_KEY` format, non-world-readable `.env`, and non-world-readable `bootstrap/cache/config.php`, or the tests will accidentally normalize insecure deployments
- Discovery tests must isolate host-specific Nginx and PHP-FPM search patterns so OSS CI stays deterministic and does not inherit the local machine's service config state
- Temporary-path fixtures should resolve symlinks before asserting ambiguous-root behavior, because macOS temp directories may route through `/private` and create false-positive path-indirection findings
- Task-3 checks should only mark findings as `confirmed` when the normalized snapshot contains direct path or config evidence; if config visibility is partial or depends on runtime cache state, prefer `probable`
- Task-3 checklist coverage must stay tied to direct snapshot evidence for Laravel and PHP boundaries: `.env` exposure, public secret artifacts, Nginx docroot and PHP execution scope, deny rules, upload execution, and PHP-FPM root/TCP/socket/shared-pool risks should remain explicit confirmed checks
- Host and distro layout assumptions must stay configurable: discovery should read a small profile file for non-standard Nginx, PHP-FPM, Supervisor, systemd, and app-root paths instead of baking Ubuntu-style paths into checks or CLI flow
- Operator config files must fail fast on unknown keys and unsupported distro identifiers; silent acceptance of typos is not acceptable for a security-focused CLI
- Prefer operator-facing config names like `server`, `laravel`, and `services` over internal model terms; default examples should feel familiar to Laravel-on-Ubuntu users and only expose advanced knobs when needed
- Framework heuristics must only emit risky package exposure findings for packages discovery actually records in Composer metadata, and `composer.json`-only declarations must stay lower-confidence than `composer.lock` or installed-package evidence
- Framework heuristics that compare a risky signal against a missing counter-signal must scope that comparison to the same file or resource when the signal is local; one safe Livewire component or Filament resource must not suppress another risky one elsewhere in the app
- Repository test coverage should stay at or above 90% overall, with new heuristic and discovery code carrying positive and negative tests instead of relying on aggregate package coverage to hide gaps

## Architecture Direction

- Build the tool as a modular standalone Go CLI application.
- Keep system inspection command usage behind one safe command runner.
- Keep findings in a normalized schema shared by terminal and JSON reporters.
- Separate discovery, checks, correlation, and reporting.
- Use compile-time registration for checks instead of runtime plugin loading.
- Treat the discovered host/app state as a normalized snapshot consumed by checks.
- Keep subsystem parsers reusable so many checks can share one normalized source of truth.
- App discovery records resolved Laravel roots, marker files, and relevant Composer package metadata so later checks can reason over one normalized app snapshot.
- Negative-path coverage is a release gate for discovery changes: missing paths, non-Laravel roots, parse failures, permission failures, and cancellation should all be regression-tested
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
