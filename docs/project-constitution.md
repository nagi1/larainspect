# Project Constitution

## 1. Safety Before Coverage

`larainspect` is an auditor, not a remediation tool.

- Default behavior must be strictly read-only.
- New features must not introduce hidden mutation.
- If a check cannot be executed safely, it must report an unknown or reduced-confidence result instead of taking risk.
- Future remediation support, if ever added, must be opt-in and isolated from the read-only audit engine.

## 2. Evidence Over Assumptions

- Findings must be grounded in filesystem state, process state, service config, listeners, Laravel project files, or logs.
- Confidence must match the evidence.
- Heuristics must never be presented as confirmed vulnerabilities.
- Unknowns are acceptable; fabricated certainty is not.
- Sample output and docs must use the same taxonomy as the implementation.

## 3. Laravel-Specific, Not Generic Noise

- Prioritize Laravel, Filament, Livewire, Nginx, PHP-FPM, queues, cron, and deployment boundaries.
- Avoid generic VPS hardening checks unless they materially affect Laravel application risk.
- Focus on exploitability and operational consequences, not checkbox compliance.
- Treat writable-plus-served-plus-executable correlation as a first-class Laravel risk, not a side note.

## 4. Modular by Default

- Discovery, checks, correlators, and reporters must remain separate.
- New checks should be addable without editing unrelated core logic.
- Output rendering must not contain detection logic.
- Shared utilities must be stable and minimal.
- Parser modules should normalize subsystem data once and make it reusable across many checks.
- Prefer `DRY` through reusable helpers, but do not hide simple logic behind unnecessary abstraction.
- Prefer `KISS`: simple, explicit code beats generic frameworks inside the codebase.
- Method, type, package, and variable names should be descriptive enough for outside contributors to follow quickly.

## 5. Production Reality Wins

- Assume permission drift, compromised files, root-run deploy commands, stale releases, and partial access.
- Prefer commands and evidence available on real VPS hosts over idealized lab assumptions.
- Degrade gracefully across distributions and missing tools.
- Do not assume Ubuntu-only layouts, service names, or file paths.

## 6. Stable Public Contracts

The following interfaces must be treated as versioned project contracts:

- CLI flags and exit codes
- finding schema
- JSON report structure
- severity and confidence taxonomy
- check registration and execution contract
- subsystem snapshot contracts used by checks and correlators

## 7. Open Source Maintainability

- Small modules with explicit ownership and purpose
- docs kept current as decisions stabilize
- deterministic fixtures for parser and report testing
- contributor guidance for adding checks and evidence safely
- check implementations should be easy to review in isolation
- target a latest broadly compatible Go version and document the minimum supported version clearly
- use the Go ecosystem pragmatically; avoid reimplementing commodity capabilities without a clear reason
- keep dependency choices reviewable, justified, and limited to packages that materially improve maintainability or safety
- implementation quality must be demonstrated through automated tests, not assumed from code structure alone

## 8. Default Taxonomy

Severity levels:

- Critical
- High
- Medium
- Low
- Informational

Confidence / certainty levels:

- confirmed
- probable
- possible
- not_enough_evidence

Finding classes:

- direct finding
- heuristic finding
- possible compromise indicator
- unknown / could not inspect

## 9. Command Safety

- All shell command execution must pass through one audited runner.
- Allowed commands and arguments must be explicit and reviewable.
- Commands must use bounded output capture and timeouts.
- Permission-denied results are evidence, not crashes.
- No `sh -c` style shell interpolation.

## 10. Documentation Before Implementation

- Major audit subsystems must have documented scope, data sources, and sample findings before implementation starts.
- Task files should map to implementation phases that contributors can pick up independently.
- Architecture docs should stay specific enough that contributors can add checks without reverse-engineering intent from chat history.
- The hardened audit baseline in [docs/security-checklist.md](/Users/nagi/code/larainspect/docs/security-checklist.md) should remain aligned with implementation coverage.

## 11. Go Implementation Policy

- Use the latest broadly compatible Go release practical for an OSS CLI and document that version in the repository.
- Prefer the standard library first, then mature ecosystem packages where they clearly reduce maintenance burden.
- Avoid writing parsers, CLI plumbing, test harnesses, or utility layers from scratch when established Go solutions already fit the need.
- Keep interfaces and package boundaries clear enough that contributors can extend the tool without understanding the whole codebase first.
- Follow Go conventions for package design, naming, error handling, testing style, and standard tool usage.
- Use Go concurrency when it materially improves audit speed or responsiveness, but keep it bounded, explicit, and easy to reason about.
- Prefer deterministic worker patterns, context-aware cancellation, and controlled parallelism over ad hoc goroutine sprawl.

## 12. Testing And Verification Policy

- A feature is not complete until it has appropriate automated test coverage or a documented reason why automation is not practical.
- Parser, correlator, and reporter behavior should be covered by deterministic tests and fixtures.
- Risk checks should be validated with representative positive and negative cases so findings are not based on untested assumptions.
- CLI behavior, JSON schema stability, and exit-code rules should be regression tested.
- Tests should be safe for OSS CI, avoid internet dependencies, and avoid requiring a real production VPS.
