# 06 Correlation Reporting And Tests

## Goal

Make results trustworthy, consumable, and sustainable for open-source contributors.

## Tasks

- Finalize correlation rules across permissions, listeners, runtime users, and served paths.
- Implement terminal report sections: summary, severity groups, informational, unknowns, compromise indicators, next actions.
- Finalize JSON schema and schema versioning.
- Implement exit-code calculation rules.
- Add fixture-driven tests for parsers, checks, correlators, and reporters.
- Add regression fixtures for common Laravel VPS failure modes.
- Write contributor docs for adding checks, writing evidence, and testing safely.

## Deliverables

- stable reporting contracts
- stable test harness
- contributor-facing extension guidance

## Blockers To Watch

- Reporting drift between terminal and JSON
- Unstable JSON shape before first public release
- Lack of regression fixtures for real-world bad configurations
