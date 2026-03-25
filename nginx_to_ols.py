#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

DEFAULT_NGINX = "/etc/nginx"
DEFAULT_OLS_HTTPD = "/usr/local/lsws/conf/httpd_config.conf"
DEFAULT_OLS_VHOSTS_ROOT = "/usr/local/lsws/conf/vhosts"
DEFAULT_OUTPUT = "ols_migration_conf_preview"

DEFAULT_SECURE_LISTENER_KEY = "/usr/local/lsws/admin/conf/webadmin.key"
DEFAULT_SECURE_LISTENER_CERT = "/usr/local/lsws/admin/conf/webadmin.crt"

LISTENER_MAP_BEGIN = "# BEGIN NGINX_TO_OLS MAPS"
LISTENER_MAP_END = "# END NGINX_TO_OLS MAPS"
GLOBAL_MANAGED_BEGIN = "# BEGIN NGINX_TO_OLS MANAGED"
GLOBAL_MANAGED_END = "# END NGINX_TO_OLS MANAGED"
VHCONF_MANAGED_MARKER = "# MANAGED_BY NGINX_TO_OLS"

# ============================================================
# Terminal / output helpers
# ============================================================

class Terminal:
    ANSI_RESET = "\033[0m"
    ANSI_BOLD = "\033[1m"
    ANSI_DIM = "\033[2m"

    ANSI_COLORS = {
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "white": "\033[37m",
        "gray": "\033[90m",
    }

    def __init__(self, quiet: bool = False, verbose: bool = False, no_color: bool = False):
        self.quiet = quiet
        self.verbose = verbose
        self.color_enabled = (
            sys.stdout.isatty()
            and not no_color
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM", "") not in ("", "dumb")
        )

    def colorize(self, text: str, color: Optional[str] = None, bold: bool = False, dim: bool = False) -> str:
        if not self.color_enabled:
            return text
        parts = []
        if bold:
            parts.append(self.ANSI_BOLD)
        if dim:
            parts.append(self.ANSI_DIM)
        if color and color in self.ANSI_COLORS:
            parts.append(self.ANSI_COLORS[color])
        parts.append(text)
        parts.append(self.ANSI_RESET)
        return "".join(parts)

    def _status(self, tag: str, message: str):
        tag_upper = tag.upper()
        if self.quiet and tag_upper in ("INFO", "OK", "NOTE", "DEBUG"):
            return

        color = {
            "INFO": "cyan",
            "OK": "green",
            "WARN": "yellow",
            "ERROR": "red",
            "NOTE": "magenta",
            "DEBUG": "gray",
        }.get(tag_upper, "white")
        tag_label = f"[{tag_upper}]"
        tag_label = f"{tag_label:<7}"
        print(f"{self.colorize(tag_label, color, bold=True)} {message}")

    def info(self, message: str):
        self._status("INFO", message)

    def ok(self, message: str):
        self._status("OK", message)

    def warn(self, message: str):
        self._status("WARN", message)

    def error(self, message: str):
        self._status("ERROR", message)

    def note(self, message: str):
        self._status("NOTE", message)

    def debug(self, message: str):
        if self.verbose and not self.quiet:
            self._status("DEBUG", message)

    def info_kv(self, key: str, value: str = ""):
        if self.quiet:
            return
        if value:
            self._status("INFO", f"{key} {value}")
        else:
            self._status("INFO", key)

    def title(self, title: str):
        if self.quiet:
            return
        line = "=" * 72
        print(self.colorize(line, "cyan", bold=True))
        print(self.colorize(title, "cyan", bold=True))
        print(self.colorize(line, "cyan", bold=True))

    def kv(self, key: str, value: str, value_color: Optional[str] = None):
        if self.quiet:
            return
        label = f"{key:<26}"
        print(f"{self.colorize(label, 'blue', bold=True)} {self.colorize(str(value), value_color)}")

    def warning_count_color(self, count: int) -> str:
        if count <= 0:
            return "green"
        return "yellow"

    def print_warning_summary(self, warnings: List["WarningEntry"], limit: int = 8):
        if self.quiet or not warnings:
            return
        effective_limit = None if (self.verbose or limit <= 0) else limit
        counts = Counter(w.message for w in warnings).most_common(effective_limit)
        label = "All warning types" if effective_limit is None else f"Top warning types"
        self.warn(f"{label} ({len(counts)} shown):")
        for msg, count in counts:
            tag = "Skip" if "skip" in msg.lower() else "Warn"
            tag_color = "white" if tag == "Skip" else "yellow"
            tag_str = self.colorize(f"[{tag}]", tag_color, bold=True)
            print(f"{tag_str} {self.colorize(str(count), 'yellow', bold=True)} x {msg}")

TERM = Terminal()

# ============================================================
# Data classes
# ============================================================

@dataclass
class WarningEntry:
    message: str
    source: str = ""
    line: int = 0
    site: str = ""

@dataclass
class Node:
    name: str
    args: List[str] = field(default_factory=list)
    children: List["Node"] = field(default_factory=list)
    line: int = 0
    source: str = ""

@dataclass(eq=True, frozen=True)
class ListenSpec:
    port: int
    secure: bool = False
    default_server: bool = False
    family: str = "ipv4"

@dataclass
class NginxLocation:
    path: str
    match_type: str  # exact, prefix, prefix_no_regex, regex
    source: str
    line: int
    regex_case_insensitive: bool = False
    root: Optional[str] = None
    alias: Optional[str] = None
    index: List[str] = field(default_factory=list)
    try_files: List[str] = field(default_factory=list)
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    fastcgi_pass: Optional[str] = None
    proxy_pass: Optional[str] = None
    proxy_address: Optional[str] = None  # resolved host:port for OLS extprocessor
    rewrite_directives: List[List[str]] = field(default_factory=list)
    return_args: List[str] = field(default_factory=list)
    add_headers: List[List[str]] = field(default_factory=list)
    more_set_headers: List[str] = field(default_factory=list)
    expires: Optional[str] = None
    access_log_off: bool = False
    log_not_found_off: bool = False
    limit_req: List[str] = field(default_factory=list)
    children: List["NginxLocation"] = field(default_factory=list)

@dataclass
class NginxServer:
    source: str
    line: int
    raw_server_names: List[str] = field(default_factory=list)
    primary_host: str = "default"
    aliases: List[str] = field(default_factory=list)
    root: Optional[str] = None
    index: List[str] = field(default_factory=list)
    access_log: Optional[str] = None
    error_log: Optional[str] = None
    listens: List[ListenSpec] = field(default_factory=list)
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_trusted_cert: Optional[str] = None
    ssl_stapling: bool = False
    enable_expires: bool = False
    php_app: Optional[str] = None
    locations: List[NginxLocation] = field(default_factory=list)

@dataclass
class ContextSpec:
    uri: str
    location: str
    allow_browse: int = 1
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    rewrite_rules: List[str] = field(default_factory=list)
    source: str = ""
    line: int = 0

@dataclass
class ProxySpec:
    name: str
    address: str
    uri: str
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    source: str = ""
    line: int = 0

@dataclass
class Site:
    name: str
    primary_host: str
    aliases: List[str] = field(default_factory=list)
    source_refs: List[str] = field(default_factory=list)
    root: Optional[str] = None
    index: List[str] = field(default_factory=list)
    access_log: Optional[str] = None
    error_log: Optional[str] = None
    listens: List[ListenSpec] = field(default_factory=list)
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_trusted_cert: Optional[str] = None
    ssl_stapling: bool = False
    php_app: Optional[str] = None
    enable_expires: bool = False
    contexts: List[ContextSpec] = field(default_factory=list)
    rewrite_rules: List[str] = field(default_factory=list)
    front_controller_rules: List[str] = field(default_factory=list)
    proxy_specs: List[ProxySpec] = field(default_factory=list)

@dataclass
class ListenerBlockInfo:
    name: str
    start: int
    brace_pos: int
    end: int
    body: str
    port: Optional[int]
    secure: bool
    family: str

# ============================================================
# Small helpers
# ============================================================

def add_warning(warnings: List[WarningEntry], message: str, source: str = "", line: int = 0, site: str = ""):
    warnings.append(WarningEntry(message=message, source=source, line=line, site=site))

def dedupe_preserve(items: List[str]) -> List[str]:
    out = []
    seen = set()
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def dedupe_listens(items: List[ListenSpec]) -> List[ListenSpec]:
    seen = set()
    out = []
    for x in items:
        key = (x.port, x.secure, x.default_server, x.family)
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out

def normalize_space(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def path_has_scheme(path: Optional[str]) -> bool:
    return bool(path and "://" in path)

def root_score(root: Optional[str]) -> int:
    if not root:
        return 0
    r = root.rstrip("/")
    if r == "/var/www/html":
        return 10
    score = 20 + min(len(r), 200)
    for token in ("/htdocs", "/public_html", "/public", "/html"):
        if token in r:
            score += 20
    if "://" in r:
        score -= 200
    if "/.well-known" in r:
        score -= 50
    return score

def choose_better_root(current: Optional[str], new: Optional[str]) -> Optional[str]:
    if not current:
        return new
    if not new:
        return current
    if root_score(new) > root_score(current):
        return new
    return current

def prefer_index(current: List[str], new: List[str]) -> List[str]:
    if not current:
        return new
    if len(new) > len(current):
        return new
    return current

def sanitize_site_name(name: str) -> str:
    if not name:
        return "default"
    if name in ("_", "localhost") or name.startswith("127.") or name.isdigit():
        return "default"
    n = name.lower().strip()
    if n.startswith("*."):
        n = "wildcard-" + n[2:]
    n = n.replace("*", "wildcard")
    n = re.sub(r"[^a-z0-9._-]+", "-", n)
    n = n.strip(".-")
    return n or "default"

def site_group_name_for_server(srv: NginxServer) -> str:
    base = sanitize_site_name(srv.primary_host)

    if base != "default":
        return base

    ports = sorted({l.port for l in srv.listens if l.port})
    for port in ports:
        if port not in (80, 443):
            return f"default-{port}"

    return base

def is_invalid_server_name(name: str) -> bool:
    if not name:
        return True
    if name in ("_", "localhost"):
        return True
    if name.startswith("127."):
        return True
    if name in ("::1", "[::1]"):
        return True
    if name.isdigit():
        return True
    if name.startswith("~"):
        return True
    return False

def first_non_wildcard_name(names: List[str]) -> Optional[str]:
    for n in names:
        if n and not n.startswith("*.") and not is_invalid_server_name(n):
            return n
    return None

def backup_file(path: Path):
    if not path.exists():
        return
    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    bak = path.with_name(path.name + f".bak.{ts}")
    shutil.copy2(path, bak)

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def slurp(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")

def spit(path: Path, data: str):
    ensure_dir(path.parent)
    path.write_text(data, encoding="utf-8")

def inode_identity(path: Path) -> Optional[Tuple[int, int]]:
    try:
        st = path.stat()
        return (st.st_dev, st.st_ino)
    except Exception:
        return None

def sanitize_proxy_name(path: str) -> str:
    p = path.lstrip("^")
    p = p.strip("/")
    p = re.sub(r"[^a-zA-Z0-9]+", "_", p)
    p = re.sub(r"_+", "_", p)
    p = p.strip("_")
    if not p:
        p = "root"
    return p + "_proxy"

def extract_proxy_address(raw: str, upstreams: Dict[str, List[str]]) -> Optional[str]:
    s = raw.strip()
    for scheme in ("https://", "http://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
            break
    # nginx unix socket format: unix:/path/to/sock: (trailing colon is nginx separator)
    # convert to OLS uds:// format
    if s.startswith("unix:"):
        sock_path = s[len("unix:"):].rstrip(":").lstrip("/")
        return ("uds://" + sock_path) or None
    host_port = s.split("/")[0]
    if host_port in upstreams and upstreams[host_port]:
        backend = upstreams[host_port][0].strip()
        for scheme in ("https://", "http://"):
            if backend.startswith(scheme):
                backend = backend[len(scheme):]
                break
        if backend.startswith("unix:"):
            sock_path = backend[len("unix:"):].rstrip(":").lstrip("/")
            return ("uds://" + sock_path) or None
        host_port = backend.split("/")[0]
    return host_port or None

def is_named_location_path(path: str) -> bool:
    return path.strip().startswith("@")

def safe_int(s: str, default: int = 0) -> int:
    try:
        return int(s)
    except Exception:
        return default

# ============================================================
# Tokenizer / parser
# ============================================================

def tokenize_nginx(text: str) -> List[Tuple[str, int]]:
    tokens: List[Tuple[str, int]] = []
    i = 0
    line = 1
    n = len(text)

    while i < n:
        c = text[i]

        if c in " \t\r":
            i += 1
            continue

        if c == "\n":
            line += 1
            i += 1
            continue

        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue

        if c in "{};":
            tokens.append((c, line))
            i += 1
            continue

        if c in ("'", '"'):
            q = c
            start_line = line
            i += 1
            buf = []
            while i < n:
                ch = text[i]
                if ch == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if ch == q:
                    i += 1
                    break
                if ch == "\n":
                    line += 1
                buf.append(ch)
                i += 1
            tokens.append(("".join(buf), start_line))
            continue

        start = i
        while i < n and text[i] not in " \t\r\n{};#":
            i += 1
        tokens.append((text[start:i], line))

    return tokens

def parse_nginx_tokens(tokens: List[Tuple[str, int]], source: str, start_idx: int = 0) -> Tuple[List[Node], int]:
    nodes: List[Node] = []
    i = start_idx
    total = len(tokens)

    while i < total:
        tok, line = tokens[i]

        if tok == "}":
            return nodes, i + 1

        if tok in ("{", ";"):
            i += 1
            continue

        name = tok
        args: List[str] = []
        i += 1

        while i < total:
            tok2, _ = tokens[i]

            if tok2 == ";":
                nodes.append(Node(name=name, args=args, children=[], line=line, source=source))
                i += 1
                break

            if tok2 == "{":
                children, i = parse_nginx_tokens(tokens, source, i + 1)
                nodes.append(Node(name=name, args=args, children=children, line=line, source=source))
                break

            if tok2 == "}":
                nodes.append(Node(name=name, args=args, children=[], line=line, source=source))
                return nodes, i

            args.append(tok2)
            i += 1

    return nodes, i

def parse_nginx_text(text: str, source: str) -> List[Node]:
    tokens = tokenize_nginx(text)
    nodes, _ = parse_nginx_tokens(tokens, source, 0)
    return nodes

def iter_nodes(nodes: List[Node]):
    for n in nodes:
        yield n
        if n.children:
            yield from iter_nodes(n.children)

# ============================================================
# Include expansion / discovery
# ============================================================

def resolve_include_pattern(pattern: str, current_file: Path, nginx_base: Path) -> List[Path]:
    patterns = []
    if os.path.isabs(pattern):
        patterns.append(pattern)
    else:
        patterns.append(str(current_file.parent / pattern))
        patterns.append(str(nginx_base / pattern))

    seen = set()
    out = []
    for pat in patterns:
        matches = sorted(glob.glob(pat))
        for m in matches:
            p = Path(m)
            if p.is_file():
                rp = p.resolve()
                if rp not in seen:
                    seen.add(rp)
                    out.append(rp)
    return out

def expand_nodes(nodes: List[Node], current_file: Path, ctx: dict, stack: List[Path]) -> List[Node]:
    out: List[Node] = []
    for node in nodes:
        if node.name == "include" and not node.children and node.args:
            pattern = node.args[0]
            include_files = resolve_include_pattern(pattern, current_file, ctx["nginx_base"])

            if not include_files:
                add_warning(ctx["warnings"], f"Included file/glob not found: {pattern}", source=str(current_file), line=node.line)

            for inc in include_files:
                if inc in stack:
                    add_warning(ctx["warnings"], f"Include cycle detected, skipping: {inc}", source=str(current_file), line=node.line)
                    continue
                TERM.debug(f"Expanding include: {pattern} -> {inc}")
                out.extend(parse_nginx_file_expanded(inc, ctx, stack + [inc], is_include=True))
            continue

        new_children = expand_nodes(node.children, current_file, ctx, stack) if node.children else []
        new_node = copy.deepcopy(node)
        new_node.children = new_children
        out.append(new_node)
    return out

def parse_nginx_file_expanded(path: Path, ctx: dict, stack: Optional[List[Path]] = None, is_include: bool = False) -> List[Node]:
    if stack is None:
        stack = [path.resolve()]
    real = path.resolve()
    if str(real) in ctx["parsed_files"]:
        TERM.debug(f"Skipping already-parsed nginx file: {real}")
        return []
    # Only track top-level source files in parsed_files.
    # Include files must NOT be added here — the same common/*.conf may be
    # legitimately included by multiple vhost configs and must expand in each.
    if not is_include:
        ctx["parsed_files"].add(str(real))
    TERM.debug(f"Parsing nginx file: {real}")
    try:
        text = slurp(real)
    except Exception as e:
        add_warning(ctx["warnings"], f"Could not read nginx file: {real} ({e})", source=str(real))
        return []
    nodes = parse_nginx_text(text, str(real))
    return expand_nodes(nodes, real, ctx, stack)

def collect_source_files(nginx_path: Path) -> List[Path]:
    nginx_path = nginx_path.resolve()
    out: List[Path] = []
    seen_ids: Set[Tuple[int, int]] = set()

    def maybe_add(p: Path):
        try:
            if not p.is_file():
                return
        except Exception:
            return
        ident = inode_identity(p)
        if ident and ident in seen_ids:
            return
        if ident:
            seen_ids.add(ident)
        out.append(p.resolve())

    if nginx_path.is_file():
        maybe_add(nginx_path)
        return out

    if not nginx_path.is_dir():
        return out

    special_found = False

    nginx_conf = nginx_path / "nginx.conf"
    if nginx_conf.exists():
        special_found = True
        maybe_add(nginx_conf)

    for sub in ("conf.d", "sites-enabled", "sites-available"):
        d = nginx_path / sub
        if d.is_dir():
            special_found = True
            for root, _, files in os.walk(d):
                for fn in files:
                    maybe_add(Path(root) / fn)

    if not special_found:
        for root, _, files in os.walk(nginx_path):
            for fn in files:
                maybe_add(Path(root) / fn)

    return out

def expand_extra_include_inputs(items: List[str]) -> List[Path]:
    out: List[Path] = []
    seen_ids: Set[Tuple[int, int]] = set()
    seen_paths: Set[Path] = set()

    def maybe_add(p: Path):
        try:
            if not p.is_file():
                return
        except Exception:
            return

        rp = p.resolve()
        ident = inode_identity(rp)

        if ident and ident in seen_ids:
            return
        if rp in seen_paths:
            return

        if ident:
            seen_ids.add(ident)
        seen_paths.add(rp)
        out.append(rp)

    for item in items or []:
        if not item:
            continue

        if any(ch in item for ch in "*?[]"):
            for m in sorted(glob.glob(item)):
                maybe_add(Path(m))
            continue

        p = Path(item)
        if p.is_file():
            maybe_add(p)
        elif p.is_dir():
            for root, _, files in os.walk(p):
                for fn in files:
                    maybe_add(Path(root) / fn)
        else:
            for m in sorted(glob.glob(item)):
                maybe_add(Path(m))

    return out

def parse_nginx_sources(nginx_path: Path, extra_include_globs: List[str], warnings: List[WarningEntry]) -> Tuple[List[Node], dict]:
    ctx = {
        "nginx_base": nginx_path.resolve() if nginx_path.is_dir() else nginx_path.resolve().parent,
        "warnings": warnings,
        "parsed_files": set(),
        "extra_include_globs": extra_include_globs[:],
    }

    source_files = collect_source_files(nginx_path)
    TERM.debug(f"Initial nginx source files: {len(source_files)}")
    all_nodes: List[Node] = []

    for src in source_files:
        all_nodes.extend(parse_nginx_file_expanded(src, ctx, [src.resolve()]))

    for p in expand_extra_include_inputs(extra_include_globs):
        TERM.debug(f"Parsing extra include source: {p}")
        all_nodes.extend(parse_nginx_file_expanded(p.resolve(), ctx, [p.resolve()]))

    return all_nodes, ctx

# ============================================================
# Nginx interpretation
# ============================================================

def detect_nginx_user_group(all_nodes: List[Node]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    for node in iter_nodes(all_nodes):
        if node.name == "user" and not node.children and node.args:
            user = node.args[0]
            group = node.args[1] if len(node.args) > 1 else node.args[0]
            return user, group, f"{node.source}:{node.line}"
    return None, None, None

_UPSTREAM_REF_DIRECTIVES = frozenset((
    "fastcgi_pass", "proxy_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "memcached_pass",
))

def _collect_referenced_upstream_names(all_nodes: List[Node]) -> Set[str]:
    """Return upstream names actually referenced by any nginx pass directive."""
    names: Set[str] = set()
    for node in iter_nodes(all_nodes):
        if node.name not in _UPSTREAM_REF_DIRECTIVES or not node.args:
            continue
        raw = node.args[0].strip()
        for scheme in ("grpcs://", "grpc://", "https://", "http://", "uwsgi://", "scgi://"):
            if raw.startswith(scheme):
                raw = raw[len(scheme):]
                break
        names.add(raw.split("/")[0])
    return names

def collect_upstreams(all_nodes: List[Node], warnings: List[WarningEntry]) -> Dict[str, List[str]]:
    upstreams: Dict[str, List[str]] = {}
    referenced = _collect_referenced_upstream_names(all_nodes)

    for node in iter_nodes(all_nodes):
        if node.name != "upstream" or not node.children or not node.args:
            continue
        name = node.args[0]
        backends = []
        for ch in node.children:
            if ch.name == "server" and not ch.children and ch.args:
                backends.append(ch.args[0])
        if len(backends) > 1 and name in referenced:
            add_warning(
                warnings,
                f"Upstream '{name}' has multiple backends; only the first one may be used where needed: {backends[0]}",
                source=node.source,
                line=node.line,
            )
        upstreams[name] = backends

    return upstreams

def parse_listen(args: List[str]) -> ListenSpec:
    port = None
    secure = False
    default_server = False
    family = "ipv4"

    for a in args:
        la = a.lower()

        if la == "ssl":
            secure = True
            continue

        if la == "default_server":
            default_server = True
            continue

        if la in ("quic", "http2", "reuseport", "proxy_protocol", "backlog", "fastopen", "so_keepalive", "bind", "deferred", "ipv6only=on", "ipv6only=off"):
            continue

        if "[" in a and "]" in a:
            family = "ipv6"

        if re.fullmatch(r"\d+", a):
            port = int(a)
            continue

        m = re.search(r":(\d+)$", a)
        if m:
            port = int(m.group(1))
            continue

    if port is None:
        port = 80

    return ListenSpec(port=port, secure=secure, default_server=default_server, family=family)

def infer_lsphp_app(target: str, upstreams: Dict[str, List[str]]) -> Optional[str]:
    if not target:
        return None

    candidates = [target]
    if target in upstreams and upstreams[target]:
        candidates.append(upstreams[target][0])

    for item in candidates:
        s = item.strip()

        m = re.search(r"php(\d+)\.(\d+)", s)
        if m:
            return f"lsphp{m.group(1)}{m.group(2)}"

        m = re.search(r"php(\d)(\d)", s)
        if m:
            return f"lsphp{m.group(1)}{m.group(2)}"

        m = re.search(r"(lsphp\d+)", s)
        if m:
            return m.group(1)

    return None

def parse_location(node: Node, upstreams: Dict[str, List[str]], warnings: List[WarningEntry]) -> NginxLocation:
    args = node.args[:]
    match_type = "prefix"
    path = "/"
    regex_case_insensitive = False

    if args:
        if args[0] == "=" and len(args) >= 2:
            match_type = "exact"
            path = " ".join(args[1:])
        elif args[0] == "~" and len(args) >= 2:
            match_type = "regex"
            path = " ".join(args[1:])
        elif args[0] == "~*" and len(args) >= 2:
            match_type = "regex"
            path = " ".join(args[1:])
            regex_case_insensitive = True
        elif args[0] == "^~" and len(args) >= 2:
            match_type = "prefix_no_regex"
            path = " ".join(args[1:])
        else:
            match_type = "prefix"
            path = " ".join(args)

    loc = NginxLocation(
        path=path,
        match_type=match_type,
        source=node.source,
        line=node.line,
        regex_case_insensitive=regex_case_insensitive,
    )

    for ch in node.children:
        if ch.name == "location" and ch.children:
            loc.children.append(parse_location(ch, upstreams, warnings))
            continue

        if ch.name == "if":
            add_warning(warnings, "Unsupported nginx 'if' inside location; skipped", source=ch.source, line=ch.line)
            continue

        if ch.name == "root" and ch.args and not loc.root:
            loc.root = " ".join(ch.args)
            continue

        if ch.name == "alias" and ch.args and not loc.alias:
            loc.alias = " ".join(ch.args)
            continue

        if ch.name == "index" and ch.args and not loc.index:
            loc.index = ch.args[:]
            continue

        if ch.name == "try_files" and ch.args:
            loc.try_files = ch.args[:]
            continue

        if ch.name == "allow" and ch.args:
            loc.allow.append(ch.args[0])
            continue

        if ch.name == "deny" and ch.args:
            loc.deny.append(ch.args[0])
            continue

        if ch.name == "fastcgi_pass" and ch.args and not loc.fastcgi_pass:
            loc.fastcgi_pass = " ".join(ch.args)
            continue

        if ch.name == "proxy_pass" and ch.args and not loc.proxy_pass:
            loc.proxy_pass = " ".join(ch.args)
            loc.proxy_address = extract_proxy_address(loc.proxy_pass, upstreams)
            continue

        if ch.name == "rewrite" and ch.args:
            loc.rewrite_directives.append(ch.args[:])
            continue

        if ch.name == "return" and ch.args and not loc.return_args:
            loc.return_args = ch.args[:]
            continue

        if ch.name == "add_header" and ch.args:
            loc.add_headers.append(ch.args[:])
            continue

        if ch.name == "more_set_headers" and ch.args:
            loc.more_set_headers.append(" ".join(ch.args))
            continue

        if ch.name == "expires" and ch.args and not loc.expires:
            loc.expires = " ".join(ch.args)
            continue

        if ch.name == "access_log" and ch.args and ch.args[0] == "off":
            loc.access_log_off = True
            continue

        if ch.name == "log_not_found" and ch.args and ch.args[0] == "off":
            loc.log_not_found_off = True
            continue

        if ch.name == "limit_req" and ch.args:
            loc.limit_req.append(" ".join(ch.args))
            continue

    return loc

def choose_server_identity(server_names: List[str], listens: List[ListenSpec], warnings: List[WarningEntry], source: str, line: int) -> Tuple[str, List[str]]:
    raw = [x for x in server_names if x]
    valid = []
    wildcard = []
    invalid = []

    for n in raw:
        if n.startswith("*."):
            wildcard.append(n)
        elif is_invalid_server_name(n):
            invalid.append(n)
        else:
            valid.append(n)

    for n in invalid:
        add_warning(warnings, f"Invalid/default-like server_name '{n}' treated as default/ignored", source=source, line=line)

    primary = first_non_wildcard_name(valid)
    aliases = []

    if primary:
        aliases = [x for x in valid if x != primary] + wildcard
        return primary, dedupe_preserve(aliases)

    if wildcard:
        aliases = wildcard[:]
        return "default", dedupe_preserve(aliases)

    if any(l.default_server for l in listens):
        return "default", []

    return "default", []

def promote_server_root_index(server: NginxServer, warnings: List[WarningEntry]):
    for loc in server.locations:
        if loc.path == "/" and loc.match_type in ("prefix", "prefix_no_regex", "exact"):
            if not server.root and loc.root:
                server.root = loc.root
            if not server.index and loc.index:
                server.index = loc.index[:]
            if loc.expires:
                server.enable_expires = True

    if path_has_scheme(server.root):
        add_warning(
            warnings,
            f"Suspicious root path contains '://': {server.root}",
            source=server.source,
            line=server.line,
            site=server.primary_host,
        )

def infer_server_php_app(server: NginxServer, upstreams: Dict[str, List[str]]) -> Optional[str]:
    for loc in server.locations:
        if loc.fastcgi_pass:
            app = infer_lsphp_app(loc.fastcgi_pass, upstreams)
            if app:
                return app
    return None

def parse_server(node: Node, upstreams: Dict[str, List[str]], warnings: List[WarningEntry]) -> NginxServer:
    server = NginxServer(source=node.source, line=node.line)

    for ch in node.children:
        if ch.name == "location" and ch.children:
            server.locations.append(parse_location(ch, upstreams, warnings))
            continue

        if ch.name == "server_name" and ch.args:
            server.raw_server_names.extend(ch.args[:])
            continue

        if ch.name == "listen" and ch.args:
            server.listens.append(parse_listen(ch.args))
            continue

        if ch.name == "root" and ch.args and not server.root:
            server.root = " ".join(ch.args)
            continue

        if ch.name == "index" and ch.args and not server.index:
            server.index = ch.args[:]
            continue

        if ch.name == "access_log" and ch.args and not server.access_log and ch.args[0] != "off":
            server.access_log = ch.args[0]
            continue

        if ch.name == "error_log" and ch.args and not server.error_log and ch.args[0] != "off":
            server.error_log = ch.args[0]
            continue

        if ch.name == "ssl_certificate" and ch.args and not server.ssl_cert:
            server.ssl_cert = ch.args[0]
            continue

        if ch.name == "ssl_certificate_key" and ch.args and not server.ssl_key:
            server.ssl_key = ch.args[0]
            continue

        if ch.name == "ssl_trusted_certificate" and ch.args and not server.ssl_trusted_cert:
            server.ssl_trusted_cert = ch.args[0]
            continue

        if ch.name in ("ssl_stapling", "ssl_stapling_verify") and ch.args:
            if ch.args[0].lower() == "on":
                server.ssl_stapling = True
            continue

        if ch.name == "expires" and ch.args:
            server.enable_expires = True
            continue

        if ch.name == "error_page":
            add_warning(warnings, f"Unsupported nginx error_page skipped: {' '.join(ch.args)}", source=ch.source, line=ch.line)
            continue

        if ch.name == "if":
            add_warning(warnings, "Unsupported nginx 'if' inside server; skipped", source=ch.source, line=ch.line)
            continue

        if ch.name == "add_header" and ch.args:
            header_line = " ".join(ch.args)
            if "$" in header_line:
                add_warning(warnings, f"Variable-based add_header skipped: {header_line}", source=ch.source, line=ch.line)
            continue

        if ch.name == "more_set_headers" and ch.args:
            header_line = " ".join(ch.args)
            if "$" in header_line:
                add_warning(warnings, f"Variable-based more_set_headers skipped: {header_line}", source=ch.source, line=ch.line)
            continue

    if not server.listens:
        server.listens = [ListenSpec(port=80, secure=False, default_server=False, family="ipv4")]

    if (server.ssl_cert or server.ssl_key) and any(l.port == 443 for l in server.listens):
        new_listens = []
        for l in server.listens:
            if l.port == 443:
                new_listens.append(ListenSpec(port=l.port, secure=True, default_server=l.default_server, family=l.family))
            else:
                new_listens.append(l)
        server.listens = new_listens

    primary, aliases = choose_server_identity(server.raw_server_names, server.listens, warnings, node.source, node.line)
    server.primary_host = primary
    server.aliases = aliases
    promote_server_root_index(server, warnings)
    server.php_app = infer_server_php_app(server, upstreams)

    return server

def collect_servers(all_nodes: List[Node], upstreams: Dict[str, List[str]], warnings: List[WarningEntry]) -> List[NginxServer]:
    servers = []
    seen = set()

    for node in iter_nodes(all_nodes):
        if node.name != "server" or not node.children:
            continue

        ident = (node.source, node.line)
        if ident in seen:
            continue
        seen.add(ident)

        servers.append(parse_server(node, upstreams, warnings))

    return servers

# ============================================================
# Site merge / location conversion
# ============================================================

def compute_context_location(site_root: str, loc: NginxLocation) -> Optional[str]:
    if loc.alias:
        return loc.alias

    base = loc.root or site_root
    if not base:
        return None

    if loc.path == "/":
        return base

    rel = loc.path.lstrip("/")
    joined = str((Path(base) / rel).as_posix())

    if loc.path.endswith("/"):
        return joined.rstrip("/") + "/"
    return joined

def loc_has_deny_all(loc: NginxLocation) -> bool:
    return any(x.lower() == "all" for x in loc.deny)

def loc_specific_denies(loc: NginxLocation) -> List[str]:
    return [x for x in loc.deny if x.lower() != "all"]

def is_simple_acl_candidate(loc: NginxLocation) -> bool:
    if loc.match_type not in ("exact", "prefix", "prefix_no_regex"):
        return False
    if loc.proxy_pass:
        return False
    if loc.try_files:
        return False
    if loc.return_args:
        return False
    if loc.rewrite_directives:
        return False
    if loc_specific_denies(loc):
        return False
    if loc_has_deny_all(loc):
        return True
    return False

def is_inline_body_return(loc: NginxLocation) -> bool:
    if not loc.return_args:
        return False
    if not loc.return_args[0].isdigit():
        return False
    if len(loc.return_args) < 2:
        return False

    code = safe_int(loc.return_args[0], 0)
    target = loc.return_args[1]

    if code < 200 or code >= 300:
        return False

    if target.startswith("/") or target.startswith("http://") or target.startswith("https://") or target.startswith("$scheme"):
        return False

    return True

def is_simple_regex_deny_only(loc: NginxLocation) -> bool:
    if loc.match_type != "regex":
        return False
    if not loc_has_deny_all(loc):
        return False
    if loc.allow:
        return False
    if loc_specific_denies(loc):
        return False
    if loc.proxy_pass:
        return False
    if loc.try_files:
        return False
    if loc.return_args:
        return False
    if loc.rewrite_directives:
        return False
    return True

def is_simple_regex_allow_deny(loc: NginxLocation) -> bool:
    if loc.match_type != "regex":
        return False
    if not loc.allow:
        return False
    if not loc_has_deny_all(loc):
        return False
    if loc_specific_denies(loc):
        return False
    if loc.proxy_pass:
        return False
    if loc.try_files:
        return False
    if loc.return_args:
        return False
    if loc.rewrite_directives:
        return False
    return True

def is_safe_regex_for_ols_context(pattern: str) -> bool:
    p = pattern.strip()
    low = p.lower()

    if not p:
        return False

    if p.startswith("@"):
        return False

    unsafe_fragments = [
        "'",
        '"',
        "%27",
        "%22",
        r"\'",
        r"\"",
        "`",
        r"\x",
        r"\u",
        r"\b",
        r"\s",
        r"\d",
        r"\w",
        "drop|insert|md5|select|union",
        "concat(",
        "benchmark(",
        "sleep(",
        "load_file",
        "outfile",
        "base64",
        "globals",
        "eval(",
        "request_uri",
        "query_string",
        "cookie",
        "$arg_",
        "$query_string",
        "$request_uri",
        "../",
        "<",
        ">",
    ]
    if any(tok in low for tok in unsafe_fragments):
        return False

    # reject advanced PCRE except (?:...)
    if re.search(r"\(\?[^:]", p):
        return False

    if "/" not in p:
        return False

    if re.search(r"[^A-Za-z0-9/_\-\.\*\+\?\^\$\(\)\[\]\{\}\|:\\]", p):
        return False

    safe_hints = (
        "/uploads",
        "/files",
        "/wp-admin",
        "/wp-includes",
        "/xmlrpc",
        "/.well-known",
        "/cache",
        "/tmp",
        "/logs",
        ".php",
        ".txt",
        ".log",
        ".bak",
        ".ini",
        ".conf",
    )

    if p.startswith("^.*") or p.startswith(".*"):
        if not any(h in low for h in safe_hints):
            return False

    return True

def is_redundant_exact_or_prefix(loc: NginxLocation, site_root: Optional[str]) -> bool:
    if loc.path == "/":
        return False

    if loc.allow or loc.deny:
        return False

    if loc.alias:
        return False

    if is_named_location_path(loc.path):
        return False

    if loc.root and site_root and normalize_space(loc.root.rstrip("/")) != normalize_space(site_root.rstrip("/")):
        return False

    if loc.return_args or loc.rewrite_directives:
        return False

    if loc.proxy_pass:
        return False

    if loc.try_files:
        return False

    return True

def try_files_to_rewrite(loc: NginxLocation) -> List[str]:
    if not loc.try_files:
        return []
    last = loc.try_files[-1]

    if last.startswith("/index.php"):
        flags = "L"
        if "$args" in last or "$query_string" in last or "$is_args" in last:
            flags = "QSA,L"
        target = "/index.php"
        return [
            "RewriteCond %{REQUEST_FILENAME} !-f",
            "RewriteCond %{REQUEST_FILENAME} !-d",
            f"RewriteRule ^(.*)$ {target} [{flags}]",
        ]
    return []

def normalize_regex_for_ols(pattern: str) -> str:
    p = pattern.strip()
    p = p.replace("(?:", "(")
    if p.startswith("^"):
        return p
    return "^.*" + p

def nginx_regex_to_exp(regex: str) -> str:
    return "exp:" + normalize_regex_for_ols(regex)

def rewrite_flag_to_ols(flag: str) -> str:
    f = flag.lower()
    if f == "permanent":
        return "R=301,L"
    if f == "redirect":
        return "R=302,L"
    if f in ("last", "break"):
        return "L"
    return "L"

def location_regex_to_rewrite(loc: NginxLocation, context_scoped: bool = False) -> List[str]:
    rules = []
    pattern = normalize_regex_for_ols(loc.path)

    if loc.return_args:
        if len(loc.return_args) >= 2 and loc.return_args[0].isdigit():
            code = loc.return_args[0]
            target = loc.return_args[1]
            rules.append(f"RewriteRule {pattern} {target} [R={code},L]")
            return rules
        return rules

    for rw in loc.rewrite_directives:
        if len(rw) == 2:
            flag_guess = rw[1].lower()
            if flag_guess in ("permanent", "redirect", "last", "break"):
                repl = rw[0]
                flag = rewrite_flag_to_ols(flag_guess)
                if context_scoped:
                    rules.append(f"RewriteRule ^.*$ {repl} [{flag}]")
                else:
                    rules.append(f"RewriteRule {pattern} {repl} [{flag}]")
            else:
                src = normalize_regex_for_ols(rw[0])
                repl = rw[1]
                rules.append(f"RewriteRule {src} {repl} [L]")
        elif len(rw) >= 3:
            src = normalize_regex_for_ols(rw[0])
            repl = rw[1]
            flag = rewrite_flag_to_ols(rw[2])
            rules.append(f"RewriteRule {src} {repl} [{flag}]")
    return rules

def render_acl_context(uri: str, location: str, allow: List[str], deny_all: bool, source: str, line: int) -> ContextSpec:
    if allow and deny_all:
        return ContextSpec(
            uri=uri,
            location=location,
            allow_browse=1,
            allow=allow[:],
            deny=["ALL"],
            source=source,
            line=line,
        )

    if deny_all:
        return ContextSpec(
            uri=uri,
            location=location,
            allow_browse=0,
            allow=[],
            deny=[],
            source=source,
            line=line,
        )

    return ContextSpec(
        uri=uri,
        location=location,
        allow_browse=1,
        allow=allow[:],
        deny=[],
        source=source,
        line=line,
    )

def convert_location(site: Site, loc: NginxLocation, warnings: List[WarningEntry]):
    if is_named_location_path(loc.path):
        add_warning(
            warnings,
            f"Named location skipped as unsupported: {loc.path}",
            source=loc.source,
            line=loc.line,
            site=site.name,
        )
        return

    if loc.children:
        add_warning(
            warnings,
            f"Nested location inside '{loc.path}' skipped as complex/unreliable",
            source=loc.source,
            line=loc.line,
            site=site.name,
        )

    if loc.expires:
        site.enable_expires = True

    if is_inline_body_return(loc):
        add_warning(
            warnings,
            f"Inline return body skipped as unsupported: {' '.join(loc.return_args)}",
            source=loc.source,
            line=loc.line,
            site=site.name,
        )
        return

    if loc.path == "/" and loc.match_type in ("prefix", "prefix_no_regex", "exact"):
        if loc.try_files:
            last = loc.try_files[-1]
            if last.startswith("@"):
                add_warning(
                    warnings,
                    f"try_files fallback to named location '{last}' not supported in OLS; skipped",
                    source=loc.source,
                    line=loc.line,
                    site=site.name,
                )
        rules = try_files_to_rewrite(loc)
        for r in rules:
            if r not in site.front_controller_rules:
                site.front_controller_rules.append(r)
        return

    if is_simple_regex_deny_only(loc):
        if not is_safe_regex_for_ols_context(loc.path):
            add_warning(
                warnings,
                f"Regex deny location skipped as unsafe/too complex for OLS context: {loc.path}",
                source=loc.source,
                line=loc.line,
                site=site.name,
            )
            return

        if loc.regex_case_insensitive:
            add_warning(
                warnings,
                f"Case-insensitive nginx regex (~*) converted approximately to OLS exp context: {loc.path}",
                source=loc.source,
                line=loc.line,
                site=site.name,
            )

        site.contexts.append(
            ContextSpec(
                uri=nginx_regex_to_exp(loc.path),
                location="$DOC_ROOT/$0",
                allow_browse=0,
                source=loc.source,
                line=loc.line,
            )
        )
        return

    if is_simple_regex_allow_deny(loc):
        if not is_safe_regex_for_ols_context(loc.path):
            add_warning(
                warnings,
                f"Regex ACL location skipped as unsafe/too complex for OLS context: {loc.path}",
                source=loc.source,
                line=loc.line,
                site=site.name,
            )
            return

        if loc.regex_case_insensitive:
            add_warning(
                warnings,
                f"Case-insensitive nginx regex (~*) converted approximately to OLS exp ACL context: {loc.path}",
                source=loc.source,
                line=loc.line,
                site=site.name,
            )

        site.contexts.append(
            ContextSpec(
                uri=nginx_regex_to_exp(loc.path),
                location="$DOC_ROOT/$0",
                allow_browse=1,
                allow=loc.allow[:],
                deny=["ALL"],
                source=loc.source,
                line=loc.line,
            )
        )
        return

    if loc.match_type == "regex" and loc.rewrite_directives and not loc.return_args:
        if not is_safe_regex_for_ols_context(loc.path):
            add_warning(
                warnings,
                f"Regex rewrite location skipped as unsafe/too complex for OLS context: {loc.path}",
                source=loc.source,
                line=loc.line,
                site=site.name,
            )
        else:
            rules = location_regex_to_rewrite(loc, context_scoped=True)
            if rules:
                site.contexts.append(
                    ContextSpec(
                        uri=nginx_regex_to_exp(loc.path),
                        location="$DOC_ROOT/$0",
                        allow_browse=1,
                        rewrite_rules=rules,
                        source=loc.source,
                        line=loc.line,
                    )
                )
                return

    if loc.match_type == "regex" and (loc.return_args or loc.rewrite_directives):
        rules = location_regex_to_rewrite(loc)
        if rules:
            for r in rules:
                if r not in site.rewrite_rules:
                    site.rewrite_rules.append(r)
            return

    if loc.match_type == "regex":
        add_warning(
            warnings,
            f"Regex location skipped as unsupported/complex: {loc.path}",
            source=loc.source,
            line=loc.line,
            site=site.name,
        )
        return

    if is_simple_acl_candidate(loc):
        ctx_loc = compute_context_location(site.root or "/var/www/html", loc)
        if ctx_loc:
            site.contexts.append(
                render_acl_context(
                    uri=loc.path,
                    location=ctx_loc,
                    allow=loc.allow,
                    deny_all=loc_has_deny_all(loc),
                    source=loc.source,
                    line=loc.line,
                )
            )
            return

    if loc.alias or (loc.root and site.root and normalize_space(loc.root.rstrip("/")) != normalize_space(site.root.rstrip("/"))):
        ctx_loc = compute_context_location(site.root or "/var/www/html", loc)
        if ctx_loc:
            site.contexts.append(
                ContextSpec(
                    uri=loc.path,
                    location=ctx_loc,
                    allow_browse=1,
                    source=loc.source,
                    line=loc.line,
                )
            )
            return

    if loc.return_args:
        if len(loc.return_args) >= 2 and loc.return_args[0].isdigit():
            code = loc.return_args[0]
            target = loc.return_args[1]
            if target.startswith("/") or target.startswith("http://") or target.startswith("https://"):
                pattern = "^" + re.escape(loc.path.rstrip("/")) + "/?$" if loc.path != "/" else "^/$"
                site.rewrite_rules.append(f"RewriteRule {pattern} {target} [R={code},L]")
                return
            else:
                add_warning(
                    warnings,
                    f"Inline/non-URL return skipped as unsupported: {' '.join(loc.return_args)}",
                    source=loc.source,
                    line=loc.line,
                    site=site.name,
                )
                return

    if loc.rewrite_directives:
        added = False
        for rw in loc.rewrite_directives:
            if len(rw) == 2:
                src = normalize_regex_for_ols(rw[0])
                repl = rw[1]
                site.rewrite_rules.append(f"RewriteRule {src} {repl} [L]")
                added = True
                continue
            if len(rw) >= 3:
                src = normalize_regex_for_ols(rw[0])
                repl = rw[1]
                flag = rewrite_flag_to_ols(rw[2])
                site.rewrite_rules.append(f"RewriteRule {src} {repl} [{flag}]")
                added = True
                continue
        if added:
            return

    if loc.proxy_pass:
        if not loc.proxy_address:
            add_warning(
                warnings,
                f"proxy_pass '{loc.proxy_pass}' could not be resolved for location '{loc.path}'; skipped",
                source=loc.source,
                line=loc.line,
                site=site.name,
            )
            return
        _raw = loc.proxy_pass.strip()
        for _scheme in ("https://", "http://"):
            if _raw.startswith(_scheme):
                _raw = _raw[len(_scheme):]
                break
        if not _raw.startswith("unix:"):
            _slash = _raw.find("/")
            if _slash >= 0 and _raw[_slash:] not in ("", "/"):
                add_warning(
                    warnings,
                    f"proxy_pass path '{_raw[_slash:]}' stripped; OLS only supports host:port in proxy address, original request URI will be used",
                    source=loc.source,
                    line=loc.line,
                    site=site.name,
                )

        name = sanitize_proxy_name(loc.path)
        used_names = {p.name for p in site.proxy_specs}
        if name in used_names:
            add_warning(
                warnings,
                f"proxy extprocessor name '{name}' already used in this vhost; location '{loc.path}' skipped",
                source=loc.source,
                line=loc.line,
                site=site.name,
            )
            return
        site.proxy_specs.append(ProxySpec(
            name=name,
            address=loc.proxy_address,
            uri=loc.path,
            allow=loc.allow[:],
            deny=loc.deny[:],
            source=loc.source,
            line=loc.line,
        ))
        return

    if is_redundant_exact_or_prefix(loc, site.root):
        return

    add_warning(
        warnings,
        f"Location skipped as unsupported/complex: {loc.path}",
        source=loc.source,
        line=loc.line,
        site=site.name,
    )

def merge_servers_to_sites(servers: List[NginxServer], warnings: List[WarningEntry]) -> List[Site]:
    grouped: Dict[str, List[NginxServer]] = defaultdict(list)
    for srv in servers:
        grouped[site_group_name_for_server(srv)].append(srv)

    sites: List[Site] = []

    for site_name, items in grouped.items():
        primary_host = "default"
        aliases: List[str] = []
        root = None
        index: List[str] = []
        access_log = None
        error_log = None
        listens: List[ListenSpec] = []
        ssl_cert = None
        ssl_key = None
        ssl_trusted = None
        ssl_stapling = False
        php_app = None
        enable_expires = False
        source_refs: List[str] = []
        all_locations: List[NginxLocation] = []

        for srv in items:
            if primary_host == "default" and srv.primary_host != "default":
                primary_host = srv.primary_host

            aliases.extend(srv.aliases)
            root = choose_better_root(root, srv.root)
            index = prefer_index(index, srv.index)
            if not access_log and srv.access_log:
                access_log = srv.access_log
            if not error_log and srv.error_log:
                error_log = srv.error_log
            listens.extend(srv.listens)
            if not ssl_cert and srv.ssl_cert:
                ssl_cert = srv.ssl_cert
            if not ssl_key and srv.ssl_key:
                ssl_key = srv.ssl_key
            if not ssl_trusted and srv.ssl_trusted_cert:
                ssl_trusted = srv.ssl_trusted_cert
            ssl_stapling = ssl_stapling or srv.ssl_stapling
            if not php_app and srv.php_app:
                php_app = srv.php_app
            enable_expires = enable_expires or srv.enable_expires
            source_refs.append(f"{srv.source}:{srv.line}")
            all_locations.extend(srv.locations)

        if not root:
            root = "/var/www/html"
            add_warning(warnings, f"Could not determine docRoot for site '{site_name}', using fallback {root}", site=site_name)

        if path_has_scheme(root):
            add_warning(warnings, f"Suspicious root path contains '://': {root}", site=site_name)

        if not index:
            index = ["index.php", "index.html", "index.htm"]

        listens = dedupe_listens(listens)
        aliases = dedupe_preserve([a for a in aliases if a and a != primary_host])

        site = Site(
            name=site_name,
            primary_host=primary_host if primary_host else "default",
            aliases=aliases,
            source_refs=dedupe_preserve(source_refs),
            root=root,
            index=index,
            access_log=access_log,
            error_log=error_log,
            listens=listens,
            ssl_cert=ssl_cert,
            ssl_key=ssl_key,
            ssl_trusted_cert=ssl_trusted,
            ssl_stapling=ssl_stapling,
            php_app=php_app,
            enable_expires=enable_expires,
        )

        for loc in all_locations:
            convert_location(site, loc, warnings)

        cseen = set()
        deduped_contexts = []
        for c in site.contexts:
            key = (c.uri, c.location, c.allow_browse, tuple(c.allow), tuple(c.deny), tuple(c.rewrite_rules))
            if key not in cseen:
                cseen.add(key)
                deduped_contexts.append(c)
        site.contexts = deduped_contexts
        site.rewrite_rules = dedupe_preserve(site.rewrite_rules)
        site.front_controller_rules = dedupe_preserve(site.front_controller_rules)

        if not site.php_app:
            site.php_app = "lsphp"

        sites.append(site)

    sites.sort(key=lambda s: (s.name != "default", s.name))
    return sites

def filter_public_sites(sites: List[Site], warnings: List[WarningEntry]) -> List[Site]:
    public_ports = {80, 443}
    out: List[Site] = []

    for site in sites:
        public_listens = [l for l in site.listens if l.port in public_ports]
        non_public_ports = sorted({l.port for l in site.listens if l.port not in public_ports})

        if not public_listens:
            if non_public_ports:
                add_warning(
                    warnings,
                    f"Site skipped due to non-public listen ports: {', '.join(str(p) for p in non_public_ports)}",
                    site=site.name,
                )
            continue

        if non_public_ports:
            add_warning(
                warnings,
                f"Non-public listen ports skipped: {', '.join(str(p) for p in non_public_ports)}",
                site=site.name,
            )

        site.listens = dedupe_listens(public_listens)
        out.append(site)

    return out

# ============================================================
# OLS rendering
# ============================================================

def render_accesslog(path: str) -> str:
    return (
        f"accesslog {path} {{\n"
        f"  useServer               0\n"
        f"  logFormat               \"%h %l %u %t \\\"%r\\\" %>s %b\"\n"
        f"}}\n"
    )

def render_errorlog(path: str) -> str:
    return (
        f"errorlog {path} {{\n"
        f"  useServer               0\n"
        f"  logLevel                WARN\n"
        f"}}\n"
    )

def render_context(ctx: ContextSpec, auto_htaccess: bool = True) -> str:
    effective_allow_browse = 1 if ctx.allow else ctx.allow_browse

    lines = [
        f"context {ctx.uri} {{",
        f"  type                    static",
        f"  location                {ctx.location}",
        f"  allowBrowse             {effective_allow_browse}",
    ]

    if ctx.allow or ctx.deny:
        lines.append("  accessControl  {")
        if ctx.allow:
            lines.append(f"    allow                 {', '.join(ctx.allow)}")
        for item in ctx.deny:
            lines.append(f"    deny                  {item}")
        lines.append("  }")

    if ctx.rewrite_rules:
        lines.extend(render_rewrite_block_lines(ctx.rewrite_rules, auto_htaccess, indent="  "))

    lines.append("}")
    return "\n".join(lines) + "\n"

def render_rewrite_block_lines(rules: List[str], auto_htaccess: bool, indent: str = "") -> List[str]:
    lines = [
        f"{indent}rewrite  {{",
        f"{indent}  enable                  1",
        f"{indent}  autoLoadHtaccess        {0 if not auto_htaccess else 1}",
    ]
    if rules:
        lines.append(f"{indent}  rules                   <<<END_rules")
        lines.extend(rules)
        lines.append("END_rules")
    lines.append(f"{indent}}}")
    return lines

def render_rewrite_block(rules: List[str], auto_htaccess: bool) -> str:
    return "\n".join(render_rewrite_block_lines(rules, auto_htaccess, indent="")) + "\n"

def render_vhssl(site: Site) -> str:
    if not site.ssl_cert or not site.ssl_key:
        return ""
    lines = [
        "vhssl  {",
        f"  keyFile                 {site.ssl_key}",
        f"  certFile                {site.ssl_cert}",
        "  certChain               1",
    ]
    if site.ssl_stapling:
        lines.append("  enableStapling          1")
    lines.append("}")
    return "\n".join(lines) + "\n"

def render_scripthandler(site: Site) -> str:
    app = site.php_app or "lsphp"
    return (
        "scripthandler  {\n"
        f"  add                     lsapi:{app} php\n"
        "}\n"
    )

def render_site_vhconf(site: Site, auto_htaccess: bool = True) -> str:
    parts = []

    parts.append(f"{VHCONF_MANAGED_MARKER}\n")
    parts.append(f"docRoot                   {site.root}\n")

    if site.enable_expires:
        parts.append("enableExpires             1\n")

    parts.append(
        "index  {\n"
        "  useServer               0\n"
        f"  indexFiles              {', '.join(site.index)}\n"
        "}\n"
    )

    if site.access_log:
        parts.append(render_accesslog(site.access_log))

    if site.error_log:
        parts.append(render_errorlog(site.error_log))

    for ps in site.proxy_specs:
        parts.append(render_proxy_extprocessor(ps))

    for c in site.contexts:
        parts.append(render_context(c, auto_htaccess=auto_htaccess))

    for ps in site.proxy_specs:
        parts.append(render_proxy_context(ps))

    all_rewrite_rules = site.rewrite_rules + site.front_controller_rules
    parts.append(render_rewrite_block(all_rewrite_rules, auto_htaccess))
    parts.append(render_scripthandler(site))

    ssl_block = render_vhssl(site)
    if ssl_block:
        parts.append(ssl_block)

    return "\n".join(p.rstrip() for p in parts if p).rstrip() + "\n"

def render_proxy_extprocessor(ps: ProxySpec) -> str:
    return (
        f"extprocessor {ps.name} {{\n"
        f"  type                    proxy\n"
        f"  address                 {ps.address}\n"
        f"  maxConns                100\n"
        f"  initTimeout             60\n"
        f"  retryTimeout            60\n"
        f"  respBuffer              0\n"
        f"}}\n"
    )

def render_proxy_context(ps: ProxySpec) -> str:
    lines = [
        f"context {ps.uri} {{",
        f"  type                    proxy",
        f"  handler                 {ps.name}",
        f"  addDefaultCharset       off",
    ]
    if ps.allow or ps.deny:
        lines.append("  accessControl  {")
        if ps.allow:
            lines.append(f"    allow                 {', '.join(ps.allow)}")
        for item in ps.deny:
            lines.append(f"    deny                  {item}")
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"

def render_php_extprocessor(app: str) -> str:
    app = app or "lsphp"
    php_bin = f"/usr/local/lsws/{app}/bin/lsphp"
    if app == "lsphp":
        php_bin = "/usr/local/lsws/lsphp/bin/lsphp"

    return (
        f"extprocessor {app} {{\n"
        f"  type                    lsapi\n"
        f"  address                 uds://tmp/lshttpd/{app}.sock\n"
        f"  maxConns                35\n"
        f"  env                     PHP_LSAPI_CHILDREN=35\n"
        f"  initTimeout             60\n"
        f"  retryTimeout            0\n"
        f"  persistConn             1\n"
        f"  pcKeepAliveTimeout      1\n"
        f"  respBuffer              0\n"
        f"  autoStart               1\n"
        f"  path                    {php_bin}\n"
        f"  backlog                 100\n"
        f"  instances               1\n"
        f"  extMaxIdleTime          300\n"
        f"  priority                0\n"
        f"  memSoftLimit            2047M\n"
        f"  memHardLimit            2047M\n"
        f"  procSoftLimit           1400\n"
        f"  procHardLimit           1500\n"
        f"}}\n"
    )

def map_hosts_for_site(site: Site) -> str:
    hosts = []
    if site.primary_host and site.primary_host != "default":
        hosts.append(site.primary_host)
    hosts.extend(site.aliases)
    hosts = dedupe_preserve([h for h in hosts if h])

    if not hosts:
        hosts = ["default"]

    return ", ".join(hosts)

def render_map_line(site: Site) -> str:
    return f"map                     {site.name} {map_hosts_for_site(site)}"

def render_virtualhost_block(site: Site, vhosts_root: Path) -> str:
    vh_root = (vhosts_root / site.name).as_posix()
    conf_file = (vhosts_root / site.name / "vhconf.conf").as_posix()

    return (
        f"virtualhost {site.name} {{\n"
        f"  vhRoot                  {vh_root}/\n"
        f"  configFile              {conf_file}\n"
        f"  allowSymbolLink         1\n"
        f"  enableScript            1\n"
        f"  restrained              1\n"
        f"  setUIDMode              2\n"
        f"}}\n"
    )

def render_listener_block(name: str, port: int, secure: bool, family: str, map_lines: List[str]) -> str:
    lines = [
        f"listener {name} {{",
        f"  address                 {'[ANY]' if family == 'ipv6' else '*'}:{port}",
        f"  secure                  {1 if secure else 0}",
    ]
    if secure:
        lines.extend([
            f"  keyFile                 {DEFAULT_SECURE_LISTENER_KEY}",
            f"  certFile                {DEFAULT_SECURE_LISTENER_CERT}",
            f"  certChain               1",
        ])
    lines.append(f"  {LISTENER_MAP_BEGIN}")
    lines.extend([f"  {x}" for x in map_lines])
    lines.append(f"  {LISTENER_MAP_END}")
    lines.append("}")
    return "\n".join(lines) + "\n"

# ============================================================
# OLS httpd patching
# ============================================================

def find_matching_brace(text: str, open_brace_pos: int) -> int:
    depth = 0
    i = open_brace_pos
    n = len(text)
    quote = None

    while i < n:
        c = text[i]

        if quote:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue

        if c in ("'", '"'):
            quote = c
            i += 1
            continue

        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue

        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return -1

def parse_listener_blocks(httpd_text: str) -> List[ListenerBlockInfo]:
    blocks: List[ListenerBlockInfo] = []
    for m in re.finditer(r"(?m)^\s*listener\s+([A-Za-z0-9._:-]+)\s*\{", httpd_text):
        name = m.group(1)
        brace_pos = httpd_text.find("{", m.start())
        end = find_matching_brace(httpd_text, brace_pos)
        if end < 0:
            continue
        body = httpd_text[brace_pos + 1:end]

        port = None
        secure = False
        family = "ipv4"

        m_addr = re.search(r"(?m)^\s*address\s+(\S+)", body)
        if m_addr:
            addr = m_addr.group(1)
            if "[" in addr and "]" in addr:
                family = "ipv6"
            m_port = re.search(r":(\d+)$", addr)
            if m_port:
                port = int(m_port.group(1))
            elif re.fullmatch(r"\d+", addr):
                port = int(addr)

        m_secure = re.search(r"(?m)^\s*secure\s+(\d+)", body)
        if m_secure:
            secure = m_secure.group(1) == "1"

        blocks.append(
            ListenerBlockInfo(
                name=name,
                start=m.start(),
                brace_pos=brace_pos,
                end=end,
                body=body,
                port=port,
                secure=secure,
                family=family,
            )
        )
    return blocks

def upsert_managed_subblock(body: str, begin_marker: str, end_marker: str, content_lines: List[str], indent: str = "  ") -> str:
    block = []
    block.append(f"{indent}{begin_marker}")
    for line in content_lines:
        block.append(f"{indent}{line}")
    block.append(f"{indent}{end_marker}")
    new_chunk = "\n".join(block)

    pattern = re.compile(re.escape(begin_marker) + r".*?" + re.escape(end_marker), re.S)
    if pattern.search(body):
        return pattern.sub(new_chunk, body)

    body = body.rstrip()
    if body and not body.endswith("\n"):
        body += "\n"
    return body + new_chunk + "\n"

def find_global_managed_span(text: str) -> Optional[Tuple[int, int]]:
    start = text.find(GLOBAL_MANAGED_BEGIN)
    if start < 0:
        return None
    end = text.find(GLOBAL_MANAGED_END, start)  # search only after BEGIN
    if end < 0:
        return None
    return (start, end + len(GLOBAL_MANAGED_END))

def _strip_orphaned_managed_end(text: str) -> str:
    """Remove any END markers that appear before the first BEGIN (left by OLS WebAdmin restructuring)."""
    while True:
        begin_pos = text.find(GLOBAL_MANAGED_BEGIN)
        end_pos = text.find(GLOBAL_MANAGED_END)
        if end_pos < 0:
            break
        if begin_pos >= 0 and end_pos >= begin_pos:
            break  # END is after (or at) BEGIN — not orphaned
        # Remove the orphaned END line
        line_start = text.rfind("\n", 0, end_pos) + 1
        line_end = text.find("\n", end_pos)
        line_end = line_end + 1 if line_end >= 0 else len(text)
        text = text[:line_start] + text[line_end:]
    return text

def upsert_global_managed_block(text: str, block_content: str) -> str:
    text = _strip_orphaned_managed_end(text)
    wrapped = f"{GLOBAL_MANAGED_BEGIN}\n{block_content.rstrip()}\n{GLOBAL_MANAGED_END}\n"
    span = find_global_managed_span(text)
    if span:
        return text[:span[0]] + wrapped + text[span[1]:]
    if text and not text.endswith("\n"):
        text += "\n"
    return text + "\n" + wrapped

def collect_external_vhost_names(httpd_text: str, ols_vhosts_root: Optional[str] = None) -> Set[str]:
    """Return virtualhost names defined outside the managed block.

    If ols_vhosts_root is given, vhosts whose configFile is under that root are
    excluded — they were placed there by our script (or OLS WebAdmin for the same
    site) and should not be treated as foreign conflicts.
    """
    managed_span = find_global_managed_span(httpd_text)
    if managed_span:
        search_text = httpd_text[:managed_span[0]] + httpd_text[managed_span[1]:]
    else:
        search_text = httpd_text
    vhroot_prefix = ols_vhosts_root.rstrip("/") + "/" if ols_vhosts_root else None
    names: Set[str] = set()
    for m in re.finditer(r"(?m)^\s*virtualhost\s+([A-Za-z0-9._:-]+)\s*\{", search_text):
        name = m.group(1)
        if vhroot_prefix:
            brace_pos = search_text.find("{", m.start())
            if brace_pos >= 0:
                # Look for configFile within the next 1500 chars (well within any vhost block)
                snippet = search_text[brace_pos:brace_pos + 1500]
                cf = re.search(r"configFile\s+(\S+)", snippet)
                if cf and cf.group(1).startswith(vhroot_prefix):
                    continue  # configFile is under our vhosts root — not a foreign vhost
        names.add(name)
    return names

def patch_top_level_user_group(httpd_text: str, user: Optional[str], group: Optional[str]) -> str:
    text = httpd_text

    if user:
        text, n = re.subn(r"(?m)^\s*user\s+\S+\s*$", f"user                             {user}", text, count=1)
        if n == 0:
            text = f"user                             {user}\n" + text

    if group:
        text, n = re.subn(r"(?m)^\s*group\s+\S+\s*$", f"group                            {group}", text, count=1)
        if n == 0:
            if text.startswith("user"):
                parts = text.splitlines(True)
                inserted = False
                out = []
                for line in parts:
                    out.append(line)
                    if line.lstrip().startswith("user") and not inserted:
                        out.append(f"group                            {group}\n")
                        inserted = True
                text = "".join(out)
            else:
                text = f"group                            {group}\n" + text

    return text

def _strip_maps_outside_listener_maps_block(body: str) -> str:
    """Remove map lines from a listener body that are outside the managed MAPS subblock.

    Called only when the MAPS block already existed (OLS WebAdmin may have extracted
    map lines out of it, leaving duplicates).
    """
    begin_pos = body.find(LISTENER_MAP_BEGIN)
    end_pos = body.find(LISTENER_MAP_END)
    if begin_pos < 0 or end_pos < 0 or end_pos < begin_pos:
        return body
    managed_end = end_pos + len(LISTENER_MAP_END)
    before = re.sub(r"(?m)^\s*map\s+.*\n?", "", body[:begin_pos])
    after = re.sub(r"(?m)^\s*map\s+.*\n?", "", body[managed_end:])
    return before + body[begin_pos:managed_end] + after

def patch_httpd_config(
    existing_httpd: str,
    sites: List[Site],
    ols_vhosts_root: Path,
    nginx_user: Optional[str] = None,
    nginx_group: Optional[str] = None,
    use_nginx_user_group: bool = False,
) -> str:
    text = existing_httpd or ""

    if use_nginx_user_group:
        text = patch_top_level_user_group(text, nginx_user, nginx_group)

    desired_listener_maps: Dict[Tuple[int, bool, str], List[str]] = defaultdict(list)

    for site in sites:
        if site.listens:
            for l in site.listens:
                desired_listener_maps[(l.port, l.secure, l.family)].append(render_map_line(site))
        else:
            desired_listener_maps[(80, False, "ipv4")].append(render_map_line(site))

    for k in list(desired_listener_maps.keys()):
        desired_listener_maps[k] = dedupe_preserve(sorted(desired_listener_maps[k]))

    listener_blocks = parse_listener_blocks(text)
    managed_span = find_global_managed_span(text)
    external_listener_keys: Set[Tuple[int, bool, str]] = set()
    for lb in listener_blocks:
        if lb.port is None:
            continue
        key = (lb.port, lb.secure, lb.family)
        if managed_span and managed_span[0] <= lb.start < managed_span[1]:
            continue
        external_listener_keys.add(key)

    replacements = []
    used_existing_keys = set()

    for lb in listener_blocks:
        if lb.port is None:
            continue
        key = (lb.port, lb.secure, lb.family)
        if key not in desired_listener_maps:
            continue

        old_block = text[lb.start:lb.end + 1]
        open_idx = old_block.find("{")
        body = old_block[open_idx + 1:-1]
        had_maps_block = LISTENER_MAP_BEGIN in body
        new_body = upsert_managed_subblock(body, LISTENER_MAP_BEGIN, LISTENER_MAP_END, desired_listener_maps[key], indent="  ")
        if had_maps_block:
            # OLS WebAdmin may have extracted map lines outside our subblock — strip duplicates
            new_body = _strip_maps_outside_listener_maps_block(new_body)
        new_block = old_block[:open_idx + 1] + new_body + "}"
        replacements.append((lb.start, lb.end + 1, new_block))
        used_existing_keys.add(key)

    for start, end, repl in sorted(replacements, key=lambda x: x[0], reverse=True):
        text = text[:start] + repl + text[end:]

    missing_listener_blocks = []
    for key, map_lines in sorted(desired_listener_maps.items()):
        if key in external_listener_keys:
            continue
        port, secure, family = key
        lname = f"{'IPv6' if family == 'ipv6' else 'IPv4'}_migrated_{port}"
        missing_listener_blocks.append(render_listener_block(lname, port, secure, family, map_lines))

    php_apps = sorted({s.php_app for s in sites if s.php_app})
    ext_blocks = [render_php_extprocessor(app) for app in php_apps]
    vh_blocks = [render_virtualhost_block(s, ols_vhosts_root) for s in sites]

    managed_content = "\n".join(x.rstrip() for x in (missing_listener_blocks + ext_blocks + vh_blocks) if x).rstrip() + "\n"
    text = upsert_global_managed_block(text, managed_content)

    return text

# ============================================================
# Apply / ownership / restart
# ============================================================

def detect_target_uid_gid(vhosts_root: Path) -> Tuple[Optional[int], Optional[int]]:
    try:
        st = vhosts_root.stat()
        fallback = (st.st_uid, st.st_gid)
    except Exception:
        fallback = (None, None)

    pairs = []
    try:
        for p in vhosts_root.iterdir():
            try:
                st = p.stat()
                pairs.append((st.st_uid, st.st_gid))
            except Exception:
                pass
    except Exception:
        pass

    if not pairs:
        return fallback

    pair, _ = Counter(pairs).most_common(1)[0]
    return pair

def chown_if_possible(path: Path, uid: Optional[int], gid: Optional[int]):
    if uid is None or gid is None:
        return
    try:
        if os.geteuid() == 0:
            os.chown(path, uid, gid)
    except Exception:
        pass

def apply_to_real_ols(
    patched_httpd: str,
    sites: List[Site],
    vhconf_texts: Dict[str, str],
    ols_httpd: Path,
    ols_vhosts_root: Path,
):
    TERM.info_kv("Writing patched OLS config", str(ols_httpd))
    backup_file(ols_httpd)
    spit(ols_httpd, patched_httpd)

    uid, gid = detect_target_uid_gid(ols_vhosts_root)

    for site in sites:
        site_dir = ols_vhosts_root / site.name
        ensure_dir(site_dir)
        chown_if_possible(site_dir, uid, gid)

        vhconf = site_dir / "vhconf.conf"
        if vhconf.exists():
            backup_file(vhconf)
        spit(vhconf, vhconf_texts[site.name])

        chown_if_possible(vhconf, uid, gid)
        TERM.debug(f"Wrote vhost config: {vhconf}")

def detect_pkg_reinstall_cmd() -> Optional[List[str]]:
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                os_release[k.strip()] = v.strip().strip('"')
    except Exception:
        pass

    os_id = os_release.get("ID", "").lower()
    like = os_release.get("ID_LIKE", "").lower()

    if shutil.which("apt-get") and (os_id in ("debian", "ubuntu") or "debian" in like or "ubuntu" in like):
        return ["apt-get", "install", "--reinstall", "-y", "openlitespeed"]

    if shutil.which("dnf") and any(x in (os_id + " " + like) for x in ("rhel", "centos", "rocky", "almalinux", "fedora")):
        return ["dnf", "reinstall", "-y", "openlitespeed"]

    if shutil.which("yum") and any(x in (os_id + " " + like) for x in ("rhel", "centos", "rocky", "almalinux")):
        return ["yum", "reinstall", "-y", "openlitespeed"]

    if shutil.which("apt-get"):
        return ["apt-get", "install", "--reinstall", "-y", "openlitespeed"]
    if shutil.which("dnf"):
        return ["dnf", "reinstall", "-y", "openlitespeed"]
    if shutil.which("yum"):
        return ["yum", "reinstall", "-y", "openlitespeed"]

    return None

def confirm_use_nginx_user_group(args) -> bool:
    if args.yes:
        return True

    lines = [
        TERM.colorize("WARNING:", "yellow", bold=True) + " --use-nginx-user-group with --apply will:",
        "  - patch global OLS user/group",
        "  - reinstall OpenLiteSpeed",
        "  - remove /tmp/lshttpd/",
        "  - restart lsws",
        "",
    ]
    print("\n".join(lines), flush=True)

    try:
        ans = input(TERM.colorize("Do you want to continue? [y/N]: ", "yellow", bold=True)).strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")

def reinstall_and_restart_ols():
    cmd = detect_pkg_reinstall_cmd()
    if not cmd:
        raise RuntimeError("Could not determine package manager for OpenLiteSpeed reinstall")

    def run_cmd(cmd: List[str]):
        if TERM.verbose:
            subprocess.run(cmd, check=True)
        else:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    TERM.info_kv("Running", " ".join(cmd))
    run_cmd(cmd)

    TERM.info_kv("Removing", "/tmp/lshttpd/")
    shutil.rmtree("/tmp/lshttpd", ignore_errors=True)

    TERM.info_kv("Restarting", "lsws")
    run_cmd(["systemctl", "restart", "lsws"])

    TERM.ok("OpenLiteSpeed reinstall/reset/restart completed")

def restart_lsws_if_active() -> bool:
    if not shutil.which("systemctl"):
        return False
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "lsws"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception:
        return False

    if res.returncode != 0 or res.stdout.strip().lower() != "active":
        return False

    def run_cmd(cmd: List[str]):
        if TERM.verbose:
            subprocess.run(cmd, check=True)
        else:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    TERM.info_kv("Restarting", "lsws")
    run_cmd(["systemctl", "restart", "lsws"])
    TERM.ok("lsws restarted")
    return True

# ============================================================
# Report / output
# ============================================================

def build_report(
    parsed_files_count: int,
    sites: List[Site],
    warnings: List[WarningEntry],
    nginx_user: Optional[str],
    nginx_group: Optional[str],
    nginx_user_source: Optional[str],
    duration_sec: float,
) -> str:
    lines = []
    lines.append("Nginx -> OpenLiteSpeed Migration Report")
    lines.append("=" * 40)
    lines.append(f"Parsed nginx files: {parsed_files_count}")
    lines.append(f"Generated sites: {len(sites)}")
    lines.append(f"Warnings: {len(warnings)}")
    lines.append(f"Duration: {duration_sec:.2f}s")
    lines.append("")

    if nginx_user or nginx_group:
        lines.append(f"Detected nginx user/group: {nginx_user or '-'}:{nginx_group or '-'}")
        if nginx_user_source:
            lines.append(f"Detected from: {nginx_user_source}")
        lines.append("")

    lines.append("Sites:")
    for s in sites:
        listens = ", ".join([
            f"{l.port}{'/ssl' if l.secure else ''}{'/v6' if l.family == 'ipv6' else ''}"
            for l in s.listens
        ]) or "80"
        lines.append(f"- {s.name}")
        lines.append(f"  primary: {s.primary_host}")
        lines.append(f"  aliases: {', '.join(s.aliases) if s.aliases else '-'}")
        lines.append(f"  root: {s.root}")
        lines.append(f"  php_app: {s.php_app or '-'}")
        lines.append(f"  listens: {listens}")
        lines.append(f"  ssl: {'yes' if s.ssl_cert and s.ssl_key else 'no'}")
        if s.source_refs:
            lines.append(f"  sources: {', '.join(s.source_refs)}")
        lines.append("")

    if warnings:
        lines.append("Warnings:")
        for w in warnings:
            where = w.source
            if w.line:
                where = f"{where}:{w.line}" if where else f"line {w.line}"
            prefix = f"[{w.site}] " if w.site else ""
            tag = "Skip" if "skip" in w.message.lower() else "Warn"
            if where:
                lines.append(f"- [{tag}] {prefix}{w.message} ({where})")
            else:
                lines.append(f"- [{tag}] {prefix}{w.message}")

    return "\n".join(lines).rstrip() + "\n"

def print_final_summary(
    parsed_files_count: int,
    sites: List[Site],
    warnings: List[WarningEntry],
    output_dir: Path,
    applied: bool,
    ols_httpd: Path,
    ols_vhosts_root: Path,
    nginx_user: Optional[str] = None,
    nginx_group: Optional[str] = None,
    nginx_user_source: Optional[str] = None,
    used_nginx_user_group: bool = False,
    restarted_ols: bool = False,
    duration_sec: float = 0.0,
):
    if TERM.quiet:
        applied_s = "yes" if applied else "no"
        user_group = f"{nginx_user}:{nginx_group}" if nginx_user and nginx_group else "-"
        print(
            f"done parsed={parsed_files_count} sites={len(sites)} warnings={len(warnings)} "
            f"apply={applied_s} user_group={user_group} preview={output_dir} time={duration_sec:.2f}s"
        )
        return

    print()
    TERM.title("NGINX -> OPENLITESPEED MIGRATION SUMMARY")
    TERM.kv("Parsed nginx files", str(parsed_files_count), "white")
    TERM.kv("Generated sites", str(len(sites)), "green")
    TERM.kv("Warnings", str(len(warnings)), TERM.warning_count_color(len(warnings)))
    TERM.kv("Duration", f"{duration_sec:.2f}s", "white")

    if nginx_user and nginx_group:
        TERM.kv("OLS user/group target", f"{nginx_user}:{nginx_group}", "white")
        if nginx_user_source:
            TERM.kv("Source", nginx_user_source, "gray")

    TERM.kv("Preview written to", str(output_dir), "cyan")

    if applied:
        TERM.kv("Applied OLS config", str(ols_httpd), "green")
        TERM.kv("Applied vhosts", str(ols_vhosts_root), "green")
        if not used_nginx_user_group and not restarted_ols:
            TERM.note("Restart/reload OLS manually to apply config changes.")
    else:
        TERM.note("Preview only. Nothing has been written to live OLS paths.")

    print()
    TERM.print_warning_summary(warnings, limit=8)
    print()

# ============================================================
# CLI
# ============================================================

def preprocess_argv(argv: List[str]) -> List[str]:
    out = argv[:]
    if len(out) >= 2 and out[1] == "help":
        out[1] = "--help"
    out = ["--help" if x == "-H" else x for x in out]
    return out

def build_arg_parser() -> argparse.ArgumentParser:
    formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=38, width=110)

    p = argparse.ArgumentParser(
        formatter_class=formatter,
    )

    p.add_argument(
        "--nginx",
        default=DEFAULT_NGINX,
        metavar="<path>",
        help=f"nginx file or directory (default: {DEFAULT_NGINX})",
    )
    p.add_argument(
        "--ols-httpd",
        default=DEFAULT_OLS_HTTPD,
        metavar="<path>",
        help=f"OLS httpd_config.conf path (default: {DEFAULT_OLS_HTTPD})",
    )
    p.add_argument(
        "--ols-vhosts-root",
        metavar="<dir>",
        default=DEFAULT_OLS_VHOSTS_ROOT,
        help=f"OLS vhosts root (default: {DEFAULT_OLS_VHOSTS_ROOT})",
    )
    p.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        metavar="<dir>",
        help=f"preview output directory (default: {DEFAULT_OUTPUT})",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--apply",
        action="store_true",
        help="write patched config to real OLS paths",
    )
    mode.add_argument(
        "--revert",
        action="store_true",
        help="remove the managed block from OLS config and delete managed vhost dirs",
    )
    p.add_argument(
        "--disable-htaccess",
        action="store_true",
        help="disable autoLoadHtaccess in generated vhconf",
    )
    p.add_argument(
        "--extra-include",
        dest="extra_include_glob",
        action="append",
        default=[],
        metavar="<path|dir|glob>",
        help="additional <path|dir|glob> to parse as nginx sources",
    )
    p.add_argument(
        "--extra-include-glob",
        dest="extra_include_glob",
        action="append",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--only-public-sites",
        action="store_true",
        help="only include sites listening on ports 80/443 (skip others)",
    )
    p.add_argument(
        "--use-nginx-user-group",
        action="store_true",
        help="patch global OLS user/group from nginx and reinstall/restart OLS on --apply",
    )
    p.add_argument(
        "-y", "--yes",
        action="store_true",
        help="assume yes for confirmation prompts",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color output",
    )

    mx = p.add_mutually_exclusive_group()
    mx.add_argument(
        "-q", "--quiet", "--quite",
        dest="quiet",
        action="store_true",
        help="reduce console output to a minimal summary",
    )
    mx.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="show verbose/debug progress details",
    )

    return p

# ============================================================
# revert
# ============================================================

def do_revert(ols_httpd: Path, ols_vhosts_root: Path, yes: bool):
    errors = []
    if not ols_httpd.parent.is_dir():
        errors.append(f"OLS config directory does not exist: {ols_httpd.parent}")
    if not ols_vhosts_root.is_dir():
        errors.append(f"OLS vhosts root does not exist: {ols_vhosts_root}")
    if errors:
        for msg in errors:
            TERM.error(msg)
        TERM.error("Is OpenLiteSpeed installed? Aborting --revert.")
        sys.exit(1)

    # --- Strip managed block from httpd_config.conf ---
    if not ols_httpd.exists():
        TERM.warn(f"OLS httpd config not found: {ols_httpd} — nothing to revert")
    else:
        httpd_text = slurp(ols_httpd)
        span = find_global_managed_span(httpd_text)
        if not span:
            TERM.info("No managed block found in OLS httpd config — nothing to strip")
        else:
            reverted = httpd_text[:span[0]].rstrip() + "\n"
            backup_file(ols_httpd)
            spit(ols_httpd, reverted)
            TERM.ok(f"Removed managed block from {ols_httpd}")

    # --- Find managed vhost dirs ---
    managed_dirs: List[Path] = []
    for entry in sorted(ols_vhosts_root.iterdir()):
        if not entry.is_dir():
            continue
        vhconf = entry / "vhconf.conf"
        if not vhconf.exists():
            continue
        try:
            first_line = vhconf.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0].strip()
        except Exception:
            continue
        if first_line == VHCONF_MANAGED_MARKER:
            managed_dirs.append(entry)

    if not managed_dirs:
        TERM.info("No managed vhost dirs found — nothing to delete")
    else:
        TERM.info(f"Found {len(managed_dirs)} managed vhost dir(s) to delete:")
        for d in managed_dirs:
            print(f"  {d}")

        if not yes:
            try:
                ans = input(TERM.colorize("Delete these vhost dirs? [y/N]: ", "yellow", bold=True)).strip().lower()
            except EOFError:
                ans = ""
            if ans != "y":
                TERM.error("Aborted — vhost dirs not deleted.")
                sys.exit(1)

        for d in managed_dirs:
            shutil.rmtree(d)
            TERM.ok(f"Deleted {d}")

    # --- Restart OLS ---
    if restart_lsws_if_active():
        TERM.ok("OpenLiteSpeed restarted")
    else:
        TERM.info("OpenLiteSpeed is not running — no restart needed")

# ============================================================
# main
# ============================================================

def main():
    global TERM

    start_ts = time.time()

    argv = preprocess_argv(sys.argv)
    parser = build_arg_parser()
    args = parser.parse_args(argv[1:])

    TERM = Terminal(quiet=args.quiet, verbose=args.verbose, no_color=args.no_color)

    nginx_path = Path(args.nginx)
    ols_httpd = Path(args.ols_httpd)
    ols_vhosts_root = Path(args.ols_vhosts_root)
    output_dir = Path(args.output)

    if args.revert:
        do_revert(ols_httpd, ols_vhosts_root, yes=args.yes)
        sys.exit(0)

    warnings: List[WarningEntry] = []

    if not nginx_path.exists():
        TERM.error(f"nginx path does not exist: {nginx_path}")
        sys.exit(1)

    if args.apply:
        errors = []
        if not ols_httpd.parent.is_dir():
            errors.append(f"OLS config directory does not exist: {ols_httpd.parent}")
        if not ols_vhosts_root.is_dir():
            errors.append(f"OLS vhosts root does not exist: {ols_vhosts_root}")
        if errors:
            for msg in errors:
                TERM.error(msg)
            TERM.error("Is OpenLiteSpeed installed? Aborting --apply.")
            sys.exit(1)

    TERM.info_kv("Parsing nginx configuration")
    all_nodes, ctx = parse_nginx_sources(nginx_path, args.extra_include_glob, warnings)
    parsed_files_count = len(ctx["parsed_files"])

    nginx_user = nginx_group = nginx_user_source = None
    if args.use_nginx_user_group:
        nginx_user, nginx_group, nginx_user_source = detect_nginx_user_group(all_nodes)
        if not nginx_user or not nginx_group:
            add_warning(warnings, "Could not detect nginx user/group; global OLS user/group will not be patched")
            nginx_user = nginx_group = None
        else:
            TERM.info_kv("Detected nginx user/group", f"{nginx_user}:{nginx_group}")

    TERM.info_kv("Collecting upstreams and server blocks")
    upstreams = collect_upstreams(all_nodes, warnings)
    servers = collect_servers(all_nodes, upstreams, warnings)

    TERM.info_kv("Merging nginx servers into OLS sites")
    sites = merge_servers_to_sites(servers, warnings)
    TERM.debug(f"Generated site names: {', '.join(s.name for s in sites)}")

    if args.only_public_sites:
        TERM.info_kv("Filtering sites", "ports 80/443 only")
        sites = filter_public_sites(sites, warnings)

    try:
        existing_httpd = slurp(ols_httpd) if ols_httpd.exists() else ""
    except Exception as e:
        add_warning(warnings, f"Could not read existing OLS httpd config: {e}", source=str(ols_httpd))
        existing_httpd = ""

    if existing_httpd:
        external_vhosts = collect_external_vhost_names(existing_httpd, ols_vhosts_root=str(ols_vhosts_root))
        conflicting = [s for s in sites if s.name in external_vhosts]
        for s in conflicting:
            add_warning(
                warnings,
                f"virtualhost '{s.name}' already exists in OLS outside the managed block — skipped to avoid conflict",
                site=s.name,
            )
            TERM.warn(f"virtualhost '{s.name}' already exists in OLS outside managed block — skipped")
        sites = [s for s in sites if s.name not in external_vhosts]

    TERM.info_kv("Patching OLS global httpd_config.conf")
    patched_httpd = patch_httpd_config(
        existing_httpd=existing_httpd,
        sites=sites,
        ols_vhosts_root=ols_vhosts_root,
        nginx_user=nginx_user,
        nginx_group=nginx_group,
        use_nginx_user_group=args.use_nginx_user_group and bool(nginx_user and nginx_group),
    )

    TERM.info_kv("Rendering vhost configuration files")
    vhconf_texts: Dict[str, str] = {}
    for site in sites:
        vhconf_texts[site.name] = render_site_vhconf(site, auto_htaccess=not args.disable_htaccess)

    TERM.info_kv("Writing preview output")
    ensure_dir(output_dir)
    spit(output_dir / "httpd_config.patched.conf", patched_httpd)

    preview_vhosts_root = output_dir / "vhosts"
    for site in sites:
        spit(preview_vhosts_root / site.name / "vhconf.conf", vhconf_texts[site.name])
        TERM.debug(f"Preview vhost written: {preview_vhosts_root / site.name / 'vhconf.conf'}")

    spit(output_dir / "warnings.json", json.dumps([asdict(w) for w in warnings], indent=2, ensure_ascii=False) + "\n")

    duration_pre_apply = time.time() - start_ts
    report = build_report(
        parsed_files_count=parsed_files_count,
        sites=sites,
        warnings=warnings,
        nginx_user=nginx_user,
        nginx_group=nginx_group,
        nginx_user_source=nginx_user_source,
        duration_sec=duration_pre_apply,
    )
    spit(output_dir / "migration_report.txt", report)

    TERM.ok("Preview generated successfully")

    php_apps = sorted({s.php_app for s in sites if s.php_app})
    for app in php_apps:
        bin_path = f"/usr/local/lsws/{app}/bin/lsphp"
        if not Path(bin_path).exists():
            TERM.note(f"extprocessor '{app}' was created but {bin_path} not found — please install the package")

    if args.apply:
        restarted_ols = False
        if args.use_nginx_user_group:
            if not confirm_use_nginx_user_group(args):
                TERM.error("User cancelled.")
                sys.exit(1)

        TERM.info_kv("Applying patched config to live OLS paths")
        apply_to_real_ols(
            patched_httpd=patched_httpd,
            sites=sites,
            vhconf_texts=vhconf_texts,
            ols_httpd=ols_httpd,
            ols_vhosts_root=ols_vhosts_root,
        )

        if args.use_nginx_user_group and nginx_user and nginx_group:
            reinstall_and_restart_ols()
            restarted_ols = True
        else:
            TERM.ok("Live OLS config applied")
            if restart_lsws_if_active():
                restarted_ols = True

    duration_total = time.time() - start_ts

    print_final_summary(
        parsed_files_count=parsed_files_count,
        sites=sites,
        warnings=warnings,
        output_dir=output_dir,
        applied=args.apply,
        ols_httpd=ols_httpd,
        ols_vhosts_root=ols_vhosts_root,
        nginx_user=nginx_user,
        nginx_group=nginx_group,
        nginx_user_source=nginx_user_source,
        used_nginx_user_group=args.use_nginx_user_group,
        restarted_ols=restarted_ols if args.apply else False,
        duration_sec=duration_total,
    )

if __name__ == "__main__":
    main()
