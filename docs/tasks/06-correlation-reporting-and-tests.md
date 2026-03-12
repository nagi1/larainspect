# 06 Correlation Reporting And Tests

## Goal

Implement the cross-signal correlators, final report rendering, exit-code behavior, and regression tests that turn subsystem evidence into a trustworthy Laravel VPS security audit.

## Tasks

- Implement writable-versus-served-versus-executable correlation checks.
- Implement multi-app and lateral movement correlation checks.
- Implement runtime identity overlap checks across web, queue, scheduler, and deploy actors.
- Render terminal output sections in the documented order.
- Finalize JSON schema and schema versioning.
- Implement exit code rules for clean, high, critical, and runtime-error outcomes.
- Build regression fixtures and golden outputs for terminal and JSON reporting.
- Document contributor workflows for adding checks, parsers, and correlators.
- Keep correlation helpers small, explicit, and reusable instead of building opaque rule engines.
- Document test and fixture conventions clearly enough that outside contributors can add coverage without tribal knowledge.
- Enforce that new public contracts and correlators ship with regression tests before the phase is considered complete.

## Deliverables

- correlation layer for execution, persistence, and lateral movement risks
- stable terminal and JSON reporters
- exit code mapping tests
- contributor-facing extension guidance

## Blockers To Watch

- Hiding critical context in summary-only output
- Duplicating subsystem detection logic inside correlators
- Unstable JSON fields that would break downstream tooling
- Reporting abstractions becoming harder to maintain than the checks themselves
- Test coverage falling behind public contract changes or output format changes
