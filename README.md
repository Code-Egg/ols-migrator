# nginx_to_ols.py
Single-file Python script to migrate nginx config into OpenLiteSpeed config.

## What it does
- Reads nginx config from `/etc/nginx` by default
- Generates/patches OLS global config:
  - `/usr/local/lsws/conf/httpd_config.conf`
- Generates per-vhost config under:
  - `/usr/local/lsws/conf/vhosts/<site>/vhconf.conf`

## Defaults
- `--nginx /etc/nginx`
- `--ols-httpd /usr/local/lsws/conf/httpd_config.conf`
- `--ols-vhosts-root /usr/local/lsws/conf/vhosts`
- `--output ols_migration_conf_preview`

## Usage
### Preview only
```bash
python3 nginx_to_ols.py
```

### Apply to real OLS config
```
python3 nginx_to_ols.py --apply
```

### Apply and patch OLS user/group from nginx
```
python3 nginx_to_ols.py --use-nginx-user-group --apply
```

### Non-interactive apply
```
python3 nginx_to_ols.py --use-nginx-user-group --apply -y
```

## Notes
  - Without `--apply`, the script only writes preview output.
  - With `--apply`, it backs up and writes real OLS config files.
  - `--use-nginx-user-group --apply` also:
    - patches global OLS user / group
    - reinstalls OpenLiteSpeed
    - removes /tmp/lshttpd/
    - restarts lsws
