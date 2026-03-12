# 03 Core Risk Checks

## Goal

Implement the highest-signal confirmed checks that directly affect exploitability.

## Tasks

- Ownership and permission audit for root, code, writable, and sensitive paths.
- `.env`, backups, secrets, config cache, and debug-surface audit.
- Nginx boundary audit for docroot, PHP execution, deny rules, traversal risk, and admin-path exposure.
- PHP-FPM pool and socket audit for root execution, socket/TCP exposure, pool sharing, and permissive ACLs.
- Writable vs executable correlation audit.
- Multi-app overlap audit for runtime user, sockets, writable paths, and secret readability.
- Dangerous package and public-tool exposure audit.

## Deliverables

- critical/high-confidence findings for the core RCE and secret-exposure paths
- explicit answer to whether runtime users can influence code execution or request handling

## Blockers To Watch

- Over-reporting generic write access without proving runtime identity
- Missing symlink traversal and storage exposure relationships
- Treating package presence as exposure without route or web-surface evidence
