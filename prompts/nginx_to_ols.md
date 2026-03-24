You are editing my current single-file Python script `nginx_to_ols.py`.

Important rules:
- Use my current script as the source of truth.
- Do NOT rewrite the whole script unless I explicitly ask.
- Make only minimal targeted changes.
- Keep it single-file and stdlib-only.
- Preserve current behavior unless I explicitly ask to change it.

Project purpose:
This script migrates nginx config to OpenLiteSpeed (OLS) config for this real OLS layout:
- global config: /usr/local/lsws/conf/httpd_config.conf
- vhosts root: /usr/local/lsws/conf/vhosts
- per-vhost config: /usr/local/lsws/conf/vhosts/<site>/vhconf.conf

Important current behavior:
- parse nginx from file/dir, including nginx.conf, conf.d, sites-enabled, sites-available
- inline-expand nginx include directives in parent context
- dedupe symlinked nginx configs by real file identity/inode
- create/update OLS listeners and inject managed map lines
- create managed OLS virtualhost blocks
- create global extprocessor lsphpXX blocks
- create vhost scripthandler
- create vhost vhssl
- create rewrite rules and safe contexts where possible
- preview by default, live write only on --apply
- if nginx upstream has multiple backends, only first backend is used and warning is emitted
- if nginx has expires directives, only set enableExpires 1
- patch top-level OLS user/group when --use-nginx-user-group is used
- do NOT patch extprocessor extUser/extGroup
- with --use-nginx-user-group --apply: confirm, reinstall OpenLiteSpeed, remove /tmp/lshttpd/, restart lsws

Important conversion rules:
- use vhssl per vhost
- use default secure listener cert paths:
  /usr/local/lsws/admin/conf/webadmin.key
  /usr/local/lsws/admin/conf/webadmin.crt
- keep aliases on the same listener map line, not as fake separate vhosts
- warn/skip unsupported or risky cases instead of inventing behavior
- skip named locations like @foo
- skip inline response body returns
- skip unsafe/broad WAF/SQLi regex contexts

Important current fixes that must not regress:
1. OLS context accessControl allow list must render on ONE comma-separated line.
   Example:
   allow                 122.248.245.244/32, 54.217.201.243/32

2. Front-controller rewrite generated from:
   try_files $uri $uri/ /index.php?$args;
   must render AFTER more specific rewrites.

Current rewrite ordering model:
- site.rewrite_rules = specific rewrites
- site.front_controller_rules = generic try_files -> /index.php rewrites
- final render order = rewrite_rules first, front_controller_rules last

Development style:
- patch only the necessary functions/parts
- avoid unrelated refactors
- preserve CLI and formatting unless I explicitly ask to change them
- if you give me a full script, it must be my current script with only the requested edits applied