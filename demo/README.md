## Larainspect Demo

This Laravel app is intentionally vulnerable.

It exists to demonstrate the kinds of findings larainspect already detects across:

- Laravel source patterns
- Laravel config and secret exposure
- public artifact leakage
- filesystem permission drift
- Nginx and PHP-FPM boundary mistakes
- Supervisor and root-run operational mistakes

What is intentionally wrong here:

- admin and login routes with no obvious auth or throttling
- `loginUsingId()` from request input
- mass assignment via empty `$guarded`
- executable and risky upload rules
- `phpinfo()`, `dump()`, and `dd()` in reachable code
- raw SQL fragments, direct SQL concatenation, `shell_exec()`, `eval()`, and `unserialize()`
- hardcoded DB, mail, Slack, and broadcasting secrets
- wildcard CORS with credentials
- debug-on config and unsafe session cookie settings
- public `.env` backups, extra public PHP files, and executable uploads
- insecure Docker examples for Nginx, PHP-FPM, and Supervisor

Useful paths:

- `routes/api.php`
- `app/Http/Controllers/`
- `app/Models/`
- `config/`
- `public/`
- `docker-compose.yml`
- `docker/normal/`
- `docker/vulnerable/`
- `larainspect.yaml`

## What You Get

Each Docker image includes:

- the vulnerable or normal Laravel demo app at `/var/www/html`
- the `larainspect` binary at `/usr/local/bin/larainspect`
- a ready-to-use config file at `/etc/larainspect/config.yaml`
- the same config file inside the app at `/var/www/html/larainspect.yaml`
- an Ubuntu-based, package-managed Nginx + PHP-FPM + Supervisor stack with UFW installed but disabled for a more familiar VPS-like layout

The images use Ubuntu 25.04 so the demo can stay on distro-packaged PHP 8.4, Nginx, and Supervisor while still matching the locked Laravel dependencies in this fixture. The `larainspect` binary is installed during `docker build` using the same public one-line installer shown in the main project README.

## Prerequisites

1. Install Docker Desktop or another Docker engine with `docker compose` support.
2. Start Docker.
3. Open this repository root in a terminal.

## Quick Setup

1. Move into the demo directory.

```bash
cd demo
```

2. Build both images.

```bash
docker compose build
```

This step installs larainspect in the image using:

```bash
curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh
```

It also installs the web stack from Ubuntu packages and leaves UFW disabled in the image so the environment feels closer to a default VPS layout.

3. Start the intentionally vulnerable stack.

```bash
docker compose up -d vulnerable
```

4. Confirm the app and the audit tool exist in the container.

```bash
docker compose exec vulnerable larainspect version
docker compose exec vulnerable sh -lc 'ls /etc/larainspect && ls /var/www/html'
```

5. Run the full larainspect demo audit.

```bash
docker compose exec vulnerable larainspect audit --config /etc/larainspect/config.yaml
```

6. Run a tighter app-only scan if you want a shorter video segment.

```bash
docker compose exec vulnerable larainspect audit --scope app --app-path /var/www/html
```

## Compare Vulnerable vs Normal

1. Start the normal stack too.

```bash
docker compose up -d normal
```

2. Audit the normal container.

```bash
docker compose exec normal larainspect audit --config /etc/larainspect/config.yaml
```

3. Use the difference in findings to explain what larainspect catches at the source layer versus the infrastructure boundary layer.

## Useful Demo Commands

Show the vulnerable web app:

```bash
open http://localhost:8081
curl http://localhost:8081/info.php
curl http://localhost:8081/.env.bak
curl http://localhost:8081/backups/prod.sql
```

Show the normal web app:

```bash
open http://localhost:8082
curl -I http://localhost:8082/info.php
```

Export a JSON report for editing or on-screen zoom-ins:

```bash
docker compose exec vulnerable larainspect audit \
	--config /etc/larainspect/config.yaml \
	--format json
```

Export a Markdown report:

```bash
docker compose exec vulnerable larainspect audit \
	--config /etc/larainspect/config.yaml \
	--report-markdown-path /tmp/larainspect-demo-report.md
```

Inspect the bundled config:

```bash
docker compose exec vulnerable cat /etc/larainspect/config.yaml
```

## Presenter Notes (for anyone wants to demo the tool)

Suggested flow for a YouTube demo:

1. Build the images.
2. Start the vulnerable container.
3. Show that `info.php`, public backups, and public environment backups are reachable.
4. Run `larainspect audit --config /etc/larainspect/config.yaml`.
5. Walk through source findings first, then Nginx, PHP-FPM, Supervisor, and filesystem findings.
6. Point out that the images use Ubuntu package paths and a disabled UFW state so the environment looks familiar before you compare normal versus vulnerable findings.
7. Start the normal container and run the same audit to show the contrast.

## Stop And Clean Up

Stop the containers:

```bash
docker compose down
```

Stop and delete images too:

```bash
docker compose down --rmi local
```

If you want larainspect to inspect the source-heavy parts locally without Docker, point it at this app path from the repo root:

```bash
go run ./cmd/larainspect audit --scope app --app-path ./demo
```
