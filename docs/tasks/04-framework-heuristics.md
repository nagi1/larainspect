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

## Blockers To Watch

- Treating static code smells as confirmed vulnerabilities
- Missing version-detection edge cases when Composer metadata is incomplete
- Excessive source scanning that materially slows the audit on large apps
- Heuristic code paths becoming too abstract to review safely
- Heuristic findings producing untested noisy output that erodes trust in the tool
