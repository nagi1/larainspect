# 02 Discovery And Evidence

## Goal

Build the shared discovery layer that gathers trustworthy facts once and exposes them to checks.

## Tasks

- Implement Laravel app discovery by explicit path and filesystem scan roots.
- Validate Laravel app structure via `artisan`, `bootstrap/app.php`, `config/app.php`, `public/index.php`, and `composer.json`.
- Extract Laravel, Filament, Livewire, Horizon, and Octane presence/version from Composer metadata where possible.
- Implement process discovery for Nginx, PHP-FPM, queue workers, Horizon, cron, and related service users.
- Implement Nginx config collection from `nginx -T` and fallback config paths.
- Implement PHP-FPM config collection from `php-fpm -tt` and common pool paths.
- Implement listener discovery from `ss` and process correlation.
- Implement permission and ownership evidence helpers around `stat`, `find`, `namei`, and `getfacl`.
- Implement cron/systemd/supervisor definition discovery.
- Implement graceful partial-permission handling so missing access becomes explicit unknown evidence.

## Deliverables

- normalized discovered app model
- normalized service/process/listener model
- reusable evidence records with command excerpts

## Blockers To Watch

- Parsing distro-specific config layouts too rigidly
- Re-running expensive commands in multiple checks
- Assuming root-level visibility on production servers
