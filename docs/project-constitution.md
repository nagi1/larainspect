# Project Constitution

## 1. Safety Before Coverage

`larainspect` is an auditor, not a remediation tool.

- Default behavior must be strictly read-only.
- New features must not introduce hidden mutation.
- If a check cannot be executed safely, it must report an unknown or reduced-confidence result instead of taking risk.

## 2. Evidence Over Assumptions

- Findings must be grounded in filesystem state, process state, service config, listeners, Laravel project files, or logs.
- Confidence must match the evidence.
- Heuristics must never be presented as confirmed vulnerabilities.
- Unknowns are acceptable; fabricated certainty is not.

## 3. Laravel-Specific, Not Generic Noise

- Prioritize Laravel, Filament, Livewire, Nginx, PHP-FPM, queues, cron, and deployment boundaries.
- Avoid generic VPS hardening checks unless they materially affect Laravel application risk.
- Focus on exploitability and operational consequences, not checkbox compliance.

## 4. Modular by Default

- Discovery, checks, correlators, and reporters must remain separate.
- New checks should be addable without editing unrelated core logic.
- Output rendering must not contain detection logic.
- Shared utilities must be stable and minimal.

## 5. Production Reality Wins

- Assume permission drift, compromised files, root-run deploy commands, stale releases, and partial access.
- Prefer commands and evidence available on real VPS hosts over idealized lab assumptions.
- Degrade gracefully across distributions and missing tools.

## 6. Stable Public Contracts

The following interfaces must be treated as versioned project contracts:

- CLI flags and exit codes
- finding schema
- JSON report structure
- severity and confidence taxonomy
- check registration and execution contract

## 7. Open Source Maintainability

- Small modules with explicit ownership and purpose
- docs kept current as decisions stabilize
- deterministic fixtures for parser and report testing
- contributor guidance for adding checks and evidence safely

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
