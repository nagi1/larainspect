# Configuration

`larainspect` uses one optional JSON config file to answer a simple question:

How does this server differ from the usual Laravel-on-Ubuntu layout?

If your host is close to a normal Laravel VPS, the defaults are already sensible. Most people only need to change:

- `server.os`
- `laravel.app_path`
- `laravel.scan_roots`
- `services.nginx.paths`
- `services.php_fpm.paths`

## Why JSON

- no extra Go dependencies
- easy to ship with automation and config management
- strict parsing catches typos early

Unknown keys fail fast. Unsupported OS names fail fast.

## Load Order

1. built-in defaults
2. one config file source:
   - `--config PATH` when provided
   - otherwise the first file found from `larainspect.json`, `.larainspect.json`, or `/etc/larainspect/config.json`
3. CLI flags
4. interactive prompts

CLI flags always win.

## Preferred Shape

The preferred config shape is:

```json
{
  "version": 1,
  "server": {
    "name": "shop-production",
    "os": "ubuntu"
  },
  "laravel": {
    "scope": "auto",
    "app_path": "/var/www/shop/current",
    "scan_roots": ["/var/www", "/srv/www"]
  },
  "services": {
    "use_default_paths": true,
    "nginx": {
      "enabled": true,
      "paths": []
    },
    "php_fpm": {
      "enabled": true,
      "paths": []
    },
    "supervisor": {
      "enabled": true,
      "paths": []
    },
    "systemd": {
      "enabled": true,
      "paths": []
    }
  },
  "output": {
    "format": "terminal",
    "verbosity": "normal",
    "interactive": false,
    "color": "auto",
    "screen_reader": false
  },
  "advanced": {
    "command_timeout": "2s",
    "max_output_bytes": 65536,
    "worker_limit": 4
  }
}
```

## Sensible Defaults

- `server.os`:
  - use `ubuntu` for the common Laravel VPS case
  - use `fedora`, `rhel`, `centos`, `rocky`, or `almalinux` for RHEL-family hosts
  - use `custom` with `services.use_default_paths=false` when you want fully explicit paths
- `services.use_default_paths=true` keeps familiar built-in service paths and lets you add custom ones
- leave service `paths` empty when the defaults are enough
- set a service `enabled` flag to `false` if that host does not use it

## Full Example

The ready-to-use example lives in [larainspect.example.json](/Users/nagi/code/larainspect/larainspect.example.json).

It is written as a familiar Laravel-on-Ubuntu config that power users can extend from there.

## Power User Notes

- `services.nginx.paths` means Nginx config file paths or globs
- `services.php_fpm.paths` means PHP-FPM pool config file paths or globs
- `services.supervisor.paths` and `services.systemd.paths` are kept stable now so later discovery can reuse the same config surface
- the older `audit`, `profile`, `paths`, and `switches` sections are still accepted for backward compatibility, but new configs should use the simpler shape above
