# 05 Operational Surface Checks

## Goal

Audit the long-running and network-exposed operational surfaces around the app.

## Tasks

- Queue, Horizon, worker, systemd, and Supervisor audit.
- Scheduler and cron audit, including duplicate schedulers and direct artisan jobs.
- Port and network exposure audit with listener-to-process mapping.
- Deployment and release-model audit.
- Log safety and possible compromise indicators audit.
- Detection of stale release paths, orphan workers, root-owned runtime artifacts, and leaked backups.

## Deliverables

- findings covering queue identities, scheduler identities, listener exposure, deploy drift, and compromise signals

## Blockers To Watch

- Reading too much log data instead of bounded evidence extraction
- Confusing local-only listeners with public exposure
- Missing old-release and stale-worker path mismatches
