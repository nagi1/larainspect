# 04 Framework Heuristics

## Goal

Add Laravel-, Livewire-, and Filament-specific heuristics without overstating certainty.

## Tasks

- Laravel auth/session/CSRF/rate-limit/trusted-proxy heuristic checks.
- Livewire checks for uploads, temp upload storage, risky public properties, likely missing `#[Locked]`, and obvious missing authorization near mutators.
- Filament checks for panel path exposure, auth middleware, policy presence, tenant access controls, and MFA/config hints if directly inferable.
- Distinguish direct evidence from inferred code-level risk in the output model.
- Add references and remediation guidance tailored to Laravel ecosystems.

## Deliverables

- framework-specific heuristic findings with lower confidence bands
- explicit section for code-level risks not provable from VPS inspection alone

## Blockers To Watch

- Escalating heuristics to confirmed findings
- Scanning too broadly and producing high-noise results
- Inferring framework behavior from package presence alone
