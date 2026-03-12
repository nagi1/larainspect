# Laravel VPS Security Checklist

This checklist is the hardened deployment baseline for `larainspect`.

It is intentionally strict and assumes the application does not write `.env` at runtime. The audit design should cover these controls directly or through correlated evidence.

## 1. Users And Responsibility Split

- [ ] Create a dedicated deploy user for code deployment.
- [ ] Run Nginx as its normal web user such as `www-data` or `nginx`.
- [ ] Run PHP-FPM as a dedicated app user where practical, or at least a non-root runtime user.
- [ ] Never run the Laravel app, queue workers, or scheduler as `root`.
- [ ] Do not use the web server user as owner of the whole project.
- [ ] Keep `root` for system administration and provisioning only.

## 2. Project Ownership

- [ ] Make the Laravel project owned by the deploy user, not the runtime user.
- [ ] Use a group that allows the runtime user to read what it needs.
- [ ] Ensure application code is not writable by the web or PHP runtime user.
- [ ] Ensure `app/`, `bootstrap/`, `config/`, `database/`, `resources/`, `routes/`, `vendor/`, `public/index.php`, `composer.json`, and `composer.lock` are not runtime-writable.

Recommended default model:

- [ ] owner is `deploy`
- [ ] group is the runtime web group such as `www-data`
- [ ] runtime identities can read what they need
- [ ] runtime identities can write only to explicitly allowed directories

## 3. Directory And File Permissions

General app tree:

- [ ] Normal directories are `750`.
- [ ] Normal files are `640`.
- [ ] Avoid world-readable permissions without a specific reason.
- [ ] Avoid world-writable permissions completely.

Writable Laravel directories:

- [ ] `storage/` is writable by the runtime user.
- [ ] `bootstrap/cache/` is writable by the runtime user.
- [ ] Writable directories are typically `770`.
- [ ] Writable files inside them are typically `660`.

Never-do list:

- [ ] Do not use `chmod -R 777`.
- [ ] Do not use blanket `chmod -R 775` across the whole project.
- [ ] Do not `chown -R www-data:www-data /var/www/app`.

## 4. `.env` Protection

Because the app never edits `.env` at runtime:

- [ ] `.env` is not owned by the runtime user.
- [ ] `.env` is writable only by `deploy` or `root`.
- [ ] `.env` mode is `640` or `600`.
- [ ] Preferred model is `.env` owner `deploy`, group `www-data`, mode `640`.
- [ ] Stricter model is `.env` owner `root`, group `www-data`, mode `640`.
- [ ] `.env` is never world-readable.
- [ ] `.env` is never inside a web-accessible path.
- [ ] PHP-FPM and the web user cannot modify `.env`.
- [ ] Backup copies such as `.env.bak`, `.env.old`, swaps, and deployment leftovers are not publicly exposed.

## 5. Web Root And Public Exposure

- [ ] Nginx `root` points to Laravel `public/` only.
- [ ] Nginx never points to the project root.
- [ ] `.env`, `composer.json`, `composer.lock`, `artisan`, `bootstrap`, `storage`, dumps, and VCS directories are not directly web-accessible.
- [ ] Only `public/` is served publicly.
- [ ] There are no accidental symlinks exposing private paths.

## 6. PHP Execution Rules

- [ ] Only the intended front controller is executed through PHP-FPM.
- [ ] Arbitrary `.php` execution is blocked.
- [ ] Uploaded files cannot become executable PHP.
- [ ] Writable directories are never treated as executable by Nginx or PHP-FPM.
- [ ] `storage/`, `public/storage`, and upload paths cannot execute PHP.
- [ ] Random dropped `.php` files in `public/` are not executable.

## 7. PHP-FPM Pool Isolation

- [ ] Use a dedicated PHP-FPM pool per app when multiple apps are hosted.
- [ ] Prefer a dedicated Unix user per app where practical.
- [ ] PHP-FPM never runs as `root`.
- [ ] Pool socket permissions are restricted.
- [ ] Only Nginx can access the PHP-FPM socket.
- [ ] Unrelated apps do not share weakly isolated runtime identities without reason.

## 8. PHP-FPM Socket Permissions

- [ ] Prefer a Unix socket over TCP unless there is a reason not to.
- [ ] Socket mode is typically `660`.
- [ ] Socket mode is never `666`.
- [ ] Socket owner and group are limited to what Nginx needs.
- [ ] Random local users cannot connect to the socket.

## 9. Writable Paths Audit

- [ ] Audit every path the runtime user can write to.
- [ ] Verify only `storage/` and `bootstrap/cache/` are writable by the runtime user unless a well-justified exception exists.
- [ ] Verify the runtime user cannot write to `app/`, `config/`, `routes/`, `vendor/`, `.env`, systemd configs, Supervisor configs, Nginx configs, or cron files.
- [ ] Ask the hard question: can the PHP runtime modify anything that later changes code execution or configuration?

## 10. `storage/` And `bootstrap/cache/` Handling

- [ ] `storage/` is writable.
- [ ] `bootstrap/cache/` is writable.
- [ ] Both remain outside direct PHP execution paths.
- [ ] Their contents are audited regularly.
- [ ] Suspicious `.php` files and symlinks inside writable directories are investigated.
- [ ] Logs, sessions, caches, and compiled files are not publicly exposed.

## 11. `public/storage` And Uploads

- [ ] `php artisan storage:link` exposure is understood precisely.
- [ ] Uploaded files cannot execute as PHP.
- [ ] Dangerous extensions are restricted.
- [ ] MIME type and extension are validated.
- [ ] SVG and HTML uploads are treated carefully.
- [ ] Public upload paths are scanned for unexpected `.php` files.

## 12. Deploy Flow Safety

- [ ] Deploy commands run as `deploy`, not `root`.
- [ ] Composer runs as `deploy`, not `root`.
- [ ] Deploy does not grant unrestricted sudo unless absolutely necessary.
- [ ] If sudo is needed, it is limited to exact commands.
- [ ] Ownership and permissions are verified after every deploy.
- [ ] New releases preserve the same security model.
- [ ] CI or deployment tooling does not reset ownership to the runtime user.

## 13. Release Structure

- [ ] Prefer a release-based structure over mutating one live directory in place.
- [ ] Keep releases immutable after deployment.
- [ ] Separate shared writable paths from release code.
- [ ] Shared `.env` and shared `storage/` are handled intentionally if a release-based model is used.
- [ ] Deploys switch a symlink to a new release rather than mutating code in place.

## 14. Scheduler, Queue, And Artisan Commands

- [ ] `queue:work` runs under the intended app runtime user.
- [ ] `schedule:run` runs under the intended app user.
- [ ] Artisan commands do not run as `root` unless strictly necessary.
- [ ] Artisan-generated files keep expected ownership and mode.
- [ ] Mixed execution identities do not create permission drift.

## 15. Logs And Sensitive Runtime Files

- [ ] `storage/logs` is not world-readable.
- [ ] Logs are not web-accessible.
- [ ] Logs are treated as sensitive data.
- [ ] Log rotation preserves secure ownership and mode.
- [ ] Production error handling does not leak secrets, stack traces, or debug output.

## 16. Backups And Restores

- [ ] Backup and restore procedures preserve secure ownership.
- [ ] Restores do not make the runtime user owner of code or `.env`.
- [ ] Restores do not weaken `.env` permissions.
- [ ] Symlinks restore correctly.
- [ ] Writable directories remain only the intended ones after restore.

## 17. SSH And Server Access

- [ ] Direct root SSH login is disabled where practical.
- [ ] SSH keys are used instead of passwords.
- [ ] Access to the deploy user is restricted.
- [ ] `~/.ssh` is `700`, private keys are `600`, and `authorized_keys` is `600`.
- [ ] Unused users are removed.
- [ ] Sudo access is reviewed regularly.

## 18. Service Hardening

- [ ] PHP-FPM is not more privileged than necessary.
- [ ] systemd hardening is used where practical.
- [ ] Writable paths are restricted at the service level when feasible.
- [ ] Most of the filesystem is effectively read-only to the PHP service where practical.
- [ ] Only required paths are writable.

## 19. MySQL, Postgres, Redis, And Internal Services

- [ ] MySQL, Postgres, and Redis are not exposed publicly without a clear reason.
- [ ] Internal-only services are not bound broadly to `0.0.0.0` without justification.
- [ ] PHP-FPM over TCP is restricted if used.
- [ ] Shared internal services across apps do not create obvious lateral movement paths.

## 20. Permission Drift Checks After Every Deploy

- [ ] Project owner and group remain correct.
- [ ] Runtime user still cannot write code.
- [ ] `.env` is still not writable by runtime.
- [ ] `storage/` and `bootstrap/cache/` are still writable.
- [ ] `public/` has no unexpected PHP files.
- [ ] No directory became `777`.
- [ ] No file became `666`.
- [ ] No deploy, restore, or artisan step changed ownership unexpectedly.

## 21. Red Flags Checklist

- [ ] Whole project owned by `www-data` or the runtime user.
- [ ] `.env` owned by `www-data` or another runtime identity.
- [ ] `.env` is broadly writable.
- [ ] Project root is Nginx docroot.
- [ ] Runtime user can write to `app/`, `config/`, `routes/`, or `vendor/`.
- [ ] Queue workers or scheduler run as `root`.
- [ ] Any `777` exists in the app tree.
- [ ] Arbitrary `.php` files in `public/` can execute.
- [ ] Writable upload paths can execute PHP.
- [ ] Multiple apps share one weakly isolated runtime user without a strong reason.

## 22. Hardened Target State For This Project

- [ ] Code owner is `deploy`.
- [ ] Code group is the runtime web group such as `www-data`.
- [ ] Normal directories are `750`.
- [ ] Normal files are `640`.
- [ ] `storage/` directories are `770` and files are `660`.
- [ ] `bootstrap/cache/` directories are `770` and files are `660`.
- [ ] `.env` owner is `deploy` or `root`.
- [ ] `.env` group is the runtime web group only if read access is needed.
- [ ] `.env` mode is `640` or `600`.
- [ ] Nginx docroot is `/path/to/app/public`.
- [ ] Only the intended front controller executes.
- [ ] Runtime user cannot modify code.
- [ ] Runtime user cannot modify `.env`.
- [ ] `php artisan optimize` and related cache actions are run intentionally by the deploy identity after `.env` edits.

## 23. Important Correction

- [ ] Laravel does not need write access to the whole app.
- [ ] Laravel normally needs write access only to a very small subset of the filesystem.
- [ ] Everything else should be treated as read-only code or configuration from the perspective of the web runtime.
