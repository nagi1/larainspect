# 04 Framework Heuristics

## Goal

Implement Laravel, Livewire, and Filament heuristics with clear lower-confidence labeling and evidence phrasing that avoids false certainty.

## Tasks

- Implement Laravel heuristics for auth, sessions, CSRF, throttling, trusted proxies, trusted hosts, and admin/API separation.
- Implement Livewire heuristics for uploads, temporary upload exposure, risky public properties, likely missing locking, and likely missing authorization.
- Implement Filament heuristics for panel exposure, auth middleware, policy signals, tenant access controls, MFA signals, and model exposure risks.
- Add package/tool exposure checks for Telescope, debugbar, Clockwork, Ignition, Adminer, phpMyAdmin, `phpinfo`, and similar risky surfaces.
- Define wording conventions for heuristic findings and confidence levels.
- Reuse shared source-scanning and package-metadata helpers instead of building framework-specific scanners from scratch for each subsystem.
- Keep heuristic function names explicit about what they infer so contributors can tell direct checks from heuristic checks immediately.
- Add fixture-backed heuristic tests that prove the tool can distinguish likely risk patterns from clearly safe cases.

## Deliverables

- heuristic checks grouped by framework and admin surface
- fixture coverage for representative Livewire and Filament patterns
- contributor guide examples for adding a new heuristic safely

## Contributor Pattern

When adding a new heuristic in this phase:

- extend bounded discovery source signals first; do not let checks read files directly
- prefer one explicit rule ID per inferred signal so evidence phrasing stays stable across terminal and JSON output
- only emit a heuristic finding when the snapshot contains a concrete positive signal; represent missing counter-signals in the evidence wording instead of inventing certainty
- when the signal is component-local or resource-local, compare the missing counter-signal in the same file instead of suppressing the finding app-wide
- keep helper names descriptive enough that contributors can tell framework-specific inference from direct checks immediately
- add at least one positive and one negative test so the heuristic does not become noisy by default

Example shape:

1. discovery adds a bounded source match such as `filament.panel.auth_middleware`
2. the check combines that positive signal with the absence of another signal and emits a `heuristic_finding`
3. the finding evidence says `no obvious ... signal was found in the scanned ... files` instead of claiming the control is definitely missing

## Blockers To Watch

- Treating static code smells as confirmed vulnerabilities
- Missing version-detection edge cases when Composer metadata is incomplete
- Excessive source scanning that materially slows the audit on large apps
- Heuristic code paths becoming too abstract to review safely
- Heuristic findings producing untested noisy output that erodes trust in the tool
