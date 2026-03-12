# 01 Foundation

## Goal

Create the maintainable project skeleton and the stable public contracts.

## Tasks

- Initialize the standalone Go CLI project structure for `larainspect`.
- Define the CLI entrypoint and command surface for `audit`.
- Implement the finding model, severity taxonomy, confidence taxonomy, and unknown/error model.
- Implement reporter interfaces for terminal and JSON output.
- Implement the safe command-runner abstraction with timeout, capture, exit status, and command allowlisting.
- Define the shared execution context passed into discovery and checks.
- Define check registration/loading so new checks do not require core rewrites.
- Create the first test fixtures and golden-output harness.
- Lock the package boundaries for `runner`, `discovery`, `checks`, `correlators`, and `reporters`.

## Deliverables

- runnable Go CLI skeleton
- stable finding schema
- stable JSON schema draft
- contributor-safe extension pattern

## Blockers To Watch

- Over-coupling reporters to detection logic
- Letting checks run ad hoc shell commands outside the runner
- Mixing heuristics with confirmed findings in one code path
