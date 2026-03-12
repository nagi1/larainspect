# 02 Discovery And Evidence

## Goal

Build the normalized snapshot pipeline that discovers Laravel apps, service boundaries, runtime identities, listeners, and key filesystem evidence without embedding detection logic in reporters.

## Tasks

- Implement host and tool-availability discovery.
- Implement Laravel app discovery for explicit app paths and scan roots.
- Parse Composer metadata to detect Laravel, Filament, Livewire, Horizon, and Octane presence and versions where possible.
- Implement bounded filesystem metadata collection for sensitive paths and permission chains.
- Implement Nginx config capture and parsing from `nginx -T` plus fallback file reads.
- Implement PHP-FPM pool discovery and parsing from `php-fpm -tt` plus fallback file reads.
- Implement process, socket, listener, and unit-definition discovery.
- Implement cron and scheduler evidence collection.
- Implement bounded log excerpt collection with redaction hooks.
- Normalize permission-denied, missing-command, timeout, and parse-failure states into explicit unknown records.
- Reuse shared filesystem, command, and parsing helpers instead of duplicating collectors per subsystem.
- Keep discovery APIs and parser names descriptive so contributors can add new evidence sources without guessing intent.
- Add parser and discovery tests for successful, partial, denied, and missing-tool scenarios.
- Use controlled concurrency for independent discovery work where it improves speed on real hosts without overloading the server.

## Deliverables

- snapshot models populated from safe discovery collectors
- parser test fixtures for Nginx, PHP-FPM, systemd, cron, and Composer metadata
- command availability and fallback strategy matrix
- explicit unknown/error capture model

## Blockers To Watch

- Raw command output leaking into checks without normalization
- Discovery code becoming coupled to report formatting
- Excessive filesystem scans that hurt production safety or runtime predictability
- Secret leakage in captured command output or log excerpts
- Premature abstractions that make simple evidence collection harder to follow
- Discovery code landing without deterministic fixtures proving parser behavior
- Unbounded parallel discovery causing noisy host load or non-deterministic evidence handling