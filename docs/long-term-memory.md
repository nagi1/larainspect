# Long-Term Memory

This file stores stable project decisions, assumptions, and constraints that should persist across implementation phases.

## Stable Decisions

- Project name: `larainspect`
- Binary name: `larainspect`
- Product type: standalone CLI auditor for Laravel VPS environments
- Operating mode: read-only by default
- Primary audience: operators, security engineers, Laravel teams, incident responders, and auditors
- Style target: Laravel-like CLI UX without requiring installation inside a Laravel application

## Architecture Direction

- Build the tool as a modular standalone PHP CLI application.
- Keep system inspection command usage behind one safe command runner.
- Keep findings in a normalized schema shared by terminal and JSON reporters.
- Separate discovery, checks, correlation, and reporting.

## Detection Policy

- Prefer direct evidence from system state over inference.
- Label heuristics clearly and lower confidence when code-level certainty is not possible.
- Treat writable-plus-served-plus-executable combinations as a first-class correlation risk.
- Treat multi-app overlap and runtime identity sharing as first-class lateral movement risks.

## Safety Policy

- No write operations in v1.
- No permission changes, file edits on target hosts, service reloads, or firewall changes.
- No network access required during an audit run.

## UX Policy

- Terminal output must be easy to scan under pressure.
- JSON output must be stable and machine-readable.
- Exit codes must reflect audit severity and runtime failure distinctly.

## Open Questions

- Exact package/dependency footprint for the standalone PHP CLI
- Whether v1 ships as raw source only or also as PHAR
- Whether to support check filtering and profiles in the first release

## Update Rule

Add entries here when a decision affects architecture, public interfaces, testing strategy, or long-term contributor expectations.
