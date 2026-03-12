# 05 Operational Surface Checks

## Goal

Implement the operational and host-level checks that affect Laravel production security: queues, Horizon, workers, scheduler, cron, network exposure, database and internal service exposure, deployment model, backup and restore drift, Linux and SSH hardening signals, logs, and compromise indicators.

## Tasks

- Implement queue, Horizon, worker, Supervisor, and systemd checks.
- Implement scheduler and cron checks, including duplicate schedulers and root-run jobs.
- Implement port and network exposure checks for Redis, MySQL, Postgres, PHP-FPM over TCP, debug tools, accidental dev servers, and firewall-summary signals where available.
- Implement database and internal service hardening checks for MySQL, Postgres, Redis, Supervisor HTTP, and other internal-only listeners.
- Implement deployment and release model checks for release trees, shared paths, stale writable releases, `.git`, root-run deploy habits, and production Composer usage.
- Implement backup, restore, and permission-drift checks tied to deploy workflows, restore workflows, and root-run maintenance commands.
- Implement Linux, SSH, sudo, and service-hardening checks where they materially affect the Laravel app boundary.
- Implement bounded forensic checks for suspicious recent files, symlinks, archives, dumps, and likely webshell indicators.
- Keep compromise indicators distinct from direct findings.
- Reuse shared process, unit-file, listener, and path-analysis helpers rather than duplicating operational inspection logic.
- Keep subsystem naming and evidence models descriptive so OSS contributors can extend worker or network checks independently.
- Add tests for worker, cron, listener, and deployment-model findings using deterministic service and listener fixtures.
- Ensure implementation coverage tracks the actionable baseline in [docs/security-checklist.md](/Users/nagi/code/larainspect/docs/security-checklist.md), especially Linux, SSH, service hardening, backup, restore, and permission-drift items.

## Deliverables

- operational subsystem checks with evidence-backed findings
- compromise indicator section support
- fixture coverage for systemd, Supervisor, cron, deployment layouts, and representative network or service-hardening states

## Blockers To Watch

- Conflating suspicious indicators with confirmed compromise
- Relying on distro-specific service names or file locations
- Producing noisy low-value findings that distract from exploitability
- Copy-pasted worker, cron, and network logic drifting out of sync
- Operational checks landing without fixtures that prove cross-distro graceful degradation
