# 03 Core Risk Checks

## Goal

Implement the highest-signal confirmed checks around Laravel app validation, permissions, secrets, Nginx, PHP-FPM, and PHP execution boundaries.

## Tasks

- Implement app discovery validation and ambiguous-root detection.
- Implement ownership and permission checks for required Laravel paths.
- Implement `.env`, backup artifact, config cache, and debug-mode checks.
- Implement Nginx docroot, PHP execution scope, deny rules, hidden files, and upload execution checks.
- Implement PHP-FPM pool identity, socket/TCP exposure, socket ACL, and shared-pool checks.
- Implement direct checks for PHP execution boundaries in served, writable, upload, and storage-adjacent paths.
- Implement severity and confidence assignment rules for these subsystems.
- Implement evidence excerpts and remediation text templates for direct findings.
- Share common check helpers for permission evaluation, path classification, and remediation text where that reduces duplication.
- Favor straightforward, descriptive check implementations over generic meta-check frameworks.
- Add positive and negative tests for each core direct finding so critical and high-risk checks are validated against representative snapshots.

## Deliverables

- direct subsystem checks for app, filesystem, secrets, Nginx, PHP-FPM, and PHP execution boundaries
- golden tests for representative critical and high findings
- stable remediation phrasing for the first critical findings

## Blockers To Watch

- Under-classifying writable code or exposed secrets
- Overstating certainty when config visibility is partial
- Failing to distinguish expected writable paths from dangerous writable paths
- Duplicated logic across app, filesystem, secrets, Nginx, and PHP-FPM checks
- Core risk checks shipping without regression coverage for severity, evidence, and remediation output