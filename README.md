# nginx_to_ols.py

Single-file Python script to migrate nginx configuration to OpenLiteSpeed (OLS).

## Requirements

- Python 3.6+ (stdlib only, no dependencies)
- nginx config directory must exist (default: `/etc/nginx`)
- OpenLiteSpeed must be installed before using `--apply`

## What It Does

- Parses nginx config from file or directory, including `nginx.conf`, `conf.d`, `sites-enabled`, and `sites-available`
- Generates/patches OLS global config at `/usr/local/lsws/conf/httpd_config.conf`
- Generates per-vhost config under `/usr/local/lsws/conf/vhosts/<site>/vhconf.conf`
- Converts listeners, virtual hosts, rewrite rules, PHP handlers, SSL, ACLs, and proxy_pass
- Preview mode by default — live write only with `--apply`

## Options

### Essential Options

| Option | Default | Description |
|---|---|---|
| `--nginx <path>` | `/etc/nginx` | nginx config file or directory to parse |
| `--ols-httpd <path>` | `/usr/local/lsws/conf/httpd_config.conf` | Path to OLS global config file |
| `--ols-vhosts-root <dir>` | `/usr/local/lsws/conf/vhosts` | OLS vhosts root directory |
| `--output <dir>` | `ols_migration_conf_preview` | Directory to write preview output |
| `--apply` | _(off)_ | Write patched config to real OLS paths |

### Advanced Options

| Option | Description |
|---|---|
| `--extra-include <path\|dir\|glob>` | Additional nginx config sources to parse (repeatable) |
| `--only-public-sites` | Only include sites listening on ports 80/443 |
| `--use-nginx-user-group` | Patch global OLS user/group from nginx; on `--apply` also reinstalls OLS and restarts lsws |
| `--disable-htaccess` | Disable `autoLoadHtaccess` in generated vhconf |

### Control Options

| Option | Description |
|---|---|
| `-y`, `--yes` | Assume yes for all confirmation prompts |
| `-q`, `--quiet` | Reduce console output to a minimal one-line summary |
| `-v`, `--verbose` | Show verbose/debug progress details |
| `--no-color` | Disable ANSI color output |
| `-H`, `--help` | Show help message and exit |

## Usage

### Preview (dry run)
```
python3 nginx_to_ols.py
```

### Apply to live OLS config
```
python3 nginx_to_ols.py --apply
```

### Apply and patch OLS user/group to match nginx
```
python3 nginx_to_ols.py --use-nginx-user-group --apply
```

### Non-interactive apply
```
python3 nginx_to_ols.py --use-nginx-user-group --apply -y
```

### Apply only public sites (ports 80/443), patch OLS user/group, non-interactive
```
python3 nginx_to_ols.py --use-nginx-user-group --only-public-sites --apply -y
```

## Notes

- Without `--apply`, nothing is written to live OLS paths — only preview files are generated.
- With `--apply`, existing config files are backed up before being overwritten.
- `--use-nginx-user-group` with `--apply` will:
  - Patch global OLS `user` / `group` to match nginx
  - Reinstall OpenLiteSpeed
  - Remove `/tmp/lshttpd/`
  - Restart lsws

## Contributing

Pull requests are welcome. For bug reports or feature requests, please [open an issue](../../issues).
