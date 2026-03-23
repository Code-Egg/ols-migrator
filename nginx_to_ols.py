#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

GLOBAL_BEGIN_LISTENERS = "# BEGIN NGINX_TO_OLS MANAGED LISTENERS"
GLOBAL_END_LISTENERS = "# END NGINX_TO_OLS MANAGED LISTENERS"
GLOBAL_BEGIN_VHOSTS = "# BEGIN NGINX_TO_OLS MANAGED VHOSTS"
GLOBAL_END_VHOSTS = "# END NGINX_TO_OLS MANAGED VHOSTS"
GLOBAL_BEGIN_EXTPROC = "# BEGIN NGINX_TO_OLS MANAGED EXTPROCESSORS"
GLOBAL_END_EXTPROC = "# END NGINX_TO_OLS MANAGED EXTPROCESSORS"
INNER_BEGIN_MAPS = "# BEGIN NGINX_TO_OLS MAPS"
INNER_END_MAPS = "# END NGINX_TO_OLS MAPS"

DEFAULT_DOCROOT = "/var/www/html"
DEFAULT_INDEX_HTML = ["index.html", "index.htm"]
DEFAULT_INDEX_PHP = ["index.php", "index.html", "index.htm"]

# FIXED: secure listener defaults
DEFAULT_OLS_WEBADMIN_KEY = "/usr/local/lsws/admin/conf/webadmin.key"
DEFAULT_OLS_WEBADMIN_CERT = "/usr/local/lsws/admin/conf/webadmin.crt"

DEFAULT_OUTPUT_DIR = "ols_migration_conf_preview"

@dataclass
class WarningItem:
    level: str
    message: str
    file: str = ""
    line: int = 0
    site: str = ""

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "site": self.site,
        }

@dataclass
class Token:
    type: str
    value: str
    line: int

@dataclass
class Node:
    name: str
    args: List[str]
    children: List["Node"]
    file: str
    line: int

@dataclass
class NginxLocation:
    modifier: str = ""
    path: str = "/"
    root: Optional[str] = None
    alias: Optional[str] = None
    index_files: List[str] = field(default_factory=list)
    try_files: List[str] = field(default_factory=list)
    proxy_pass: Optional[str] = None
    fastcgi_pass: Optional[str] = None
    websocket_hint: bool = False
    add_headers: List[str] = field(default_factory=list)
    expires: Optional[str] = None
    deny_all: bool = False
    access_log_off: bool = False
    file: str = ""
    line: int = 0

@dataclass
class NginxServer:
    file: str
    line: int
    server_names: List[str] = field(default_factory=list)
    listen_specs: Set[Tuple[int, bool]] = field(default_factory=set)
    root: Optional[str] = None
    index_files: List[str] = field(default_factory=list)
    try_files: List[str] = field(default_factory=list)
    access_log: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_trusted_cert: Optional[str] = None
    enable_stapling: bool = False
    add_headers: List[str] = field(default_factory=list)
    locations: List[NginxLocation] = field(default_factory=list)
    enable_expires: bool = False
    # FIXED: track default_server-like server blocks
    default_server_like: bool = False

@dataclass
class NginxUpstream:
    name: str
    file: str
    line: int
    servers: List[str] = field(default_factory=list)

@dataclass
class Site:
    source_files: Set[str] = field(default_factory=set)
    vhost_name: str = ""
    server_names: List[str] = field(default_factory=list)
    listen_specs: Set[Tuple[int, bool]] = field(default_factory=set)
    root: Optional[str] = None
    index_files: List[str] = field(default_factory=list)
    try_files: List[str] = field(default_factory=list)
    access_log: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_trusted_cert: Optional[str] = None
    enable_stapling: bool = False
    locations: List[NginxLocation] = field(default_factory=list)
    php_app: Optional[str] = None
    php_socket_source: Optional[str] = None
    add_headers: List[str] = field(default_factory=list)
    enable_expires: bool = False

@dataclass
class PhpApp:
    name: str
    binary_path: str
    uds_address: str

@dataclass
class ProxyApp:
    name: str
    address: str

@dataclass
class ExistingListener:
    name: str
    start: int
    end: int
    text: str
    port: Optional[int]
    secure: bool

def warn(warnings: List[WarningItem], message: str,
         file: str = "", line: int = 0, site: str = "", level: str = "warn") -> None:
    warnings.append(WarningItem(level=level, message=message, file=file, line=line, site=site))

def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d%H%M%S")

def sanitize_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return "migrated-site"
    name = name.replace("*", "wildcard")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name)
    name = re.sub(r"-{2,}", "-", name).strip("-")
    return name or "migrated-site"

def ensure_unique_name(base: str, used: Set[str]) -> str:
    candidate = sanitize_name(base)
    if candidate not in used:
        used.add(candidate)
        return candidate
    idx = 2
    while True:
        c = f"{candidate}-migrated{idx}"
        if c not in used:
            used.add(c)
            return c
        idx += 1

def json_dump(obj, path: Path) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def backup_file(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    bak = path.with_name(path.name + f".bak.{now_stamp()}")
    shutil.copy2(path, bak)
    return bak

def file_identity(path: Path) -> Tuple[Tuple[int, int], Path]:
    real = path.resolve()
    st = os.stat(real)
    return (st.st_dev, st.st_ino), real

def read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")

def tokenize_nginx(text: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    line = 1
    n = len(text)

    while i < n:
        ch = text[i]

        if ch in " \t\r":
            i += 1
            continue
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "{":
            tokens.append(Token("LBRACE", "{", line))
            i += 1
            continue
        if ch == "}":
            tokens.append(Token("RBRACE", "}", line))
            i += 1
            continue
        if ch == ";":
            tokens.append(Token("SEMI", ";", line))
            i += 1
            continue
        if ch in ("'", '"'):
            q = ch
            start_line = line
            i += 1
            buf = []
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if c == q:
                    i += 1
                    break
                if c == "\n":
                    line += 1
                buf.append(c)
                i += 1
            tokens.append(Token("WORD", "".join(buf), start_line))
            continue

        start_line = line
        buf = []
        while i < n:
            c = text[i]
            if c in " \t\r\n{};":
                break
            if c == "#":
                break
            buf.append(c)
            i += 1
        if buf:
            tokens.append(Token("WORD", "".join(buf), start_line))
            continue

        i += 1

    return tokens

def parse_nginx_tokens(tokens: List[Token], file_path: str, pos: int = 0, stop_on_rbrace: bool = False):
    nodes: List[Node] = []

    while pos < len(tokens):
        tok = tokens[pos]

        if tok.type == "RBRACE":
            if stop_on_rbrace:
                return nodes, pos + 1
            pos += 1
            continue

        if tok.type != "WORD":
            pos += 1
            continue

        name = tok.value
        line = tok.line
        pos += 1

        args: List[str] = []
        while pos < len(tokens) and tokens[pos].type == "WORD":
            args.append(tokens[pos].value)
            pos += 1

        if pos >= len(tokens):
            nodes.append(Node(name=name, args=args, children=[], file=file_path, line=line))
            break

        if tokens[pos].type == "SEMI":
            nodes.append(Node(name=name, args=args, children=[], file=file_path, line=line))
            pos += 1
            continue

        if tokens[pos].type == "LBRACE":
            children, pos = parse_nginx_tokens(tokens, file_path, pos + 1, stop_on_rbrace=True)
            nodes.append(Node(name=name, args=args, children=children, file=file_path, line=line))
            continue

        nodes.append(Node(name=name, args=args, children=[], file=file_path, line=line))
        pos += 1

    return nodes, pos

def parse_nginx_text(text: str, file_path: str) -> List[Node]:
    tokens = tokenize_nginx(text)
    nodes, _ = parse_nginx_tokens(tokens, file_path)
    return nodes

def walk_nodes(nodes: List[Node]):
    for node in nodes:
        yield node
        if node.children:
            yield from walk_nodes(node.children)

def parse_file_cached(path: Path, cache: Dict[Path, List[Node]]) -> List[Node]:
    if path in cache:
        return cache[path]
    nodes = parse_nginx_text(read_text_file(path), str(path))
    cache[path] = nodes
    return nodes

def resolve_include_pattern(base_file: Path, pattern: str) -> List[Path]:
    p = Path(pattern)
    if not p.is_absolute():
        p = base_file.parent / pattern
    matches = [Path(x) for x in glob.glob(str(p), recursive=True)]
    return sorted([m for m in matches if m.is_file()])

def expand_nodes(nodes: List[Node],
                 current_file: Path,
                 raw_cache: Dict[Path, List[Node]],
                 expanded_cache: Dict[Path, List[Node]],
                 warnings: List[WarningItem],
                 stack: Set[Path]) -> List[Node]:
    out: List[Node] = []

    for node in nodes:
        if node.name == "include":
            for arg in node.args:
                for inc in resolve_include_pattern(current_file, arg):
                    out.extend(parse_nginx_file_expanded(inc, raw_cache, expanded_cache, warnings, stack))
            continue

        if node.children:
            children = expand_nodes(node.children, current_file, raw_cache, expanded_cache, warnings, stack)
            out.append(Node(name=node.name, args=node.args[:], children=children, file=node.file, line=node.line))
        else:
            out.append(Node(name=node.name, args=node.args[:], children=[], file=node.file, line=node.line))

    return out

def parse_nginx_file_expanded(path: Path,
                              raw_cache: Dict[Path, List[Node]],
                              expanded_cache: Dict[Path, List[Node]],
                              warnings: List[WarningItem],
                              stack: Set[Path]) -> List[Node]:
    real = path.resolve()

    if real in expanded_cache:
        return expanded_cache[real]

    if real in stack:
        warn(warnings, f"Detected include cycle at {real}; skipping recursive include.", file=str(real))
        return []

    stack.add(real)
    raw_nodes = parse_file_cached(real, raw_cache)
    expanded_nodes = expand_nodes(raw_nodes, real, raw_cache, expanded_cache, warnings, stack)
    expanded_cache[real] = expanded_nodes
    stack.remove(real)
    return expanded_nodes

def collect_nginx_sources(root: Path,
                          warnings: List[WarningItem],
                          extra_include_globs: Optional[List[str]] = None) -> Dict[Path, List[Node]]:
    parsed: Dict[Path, List[Node]] = {}
    raw_cache: Dict[Path, List[Node]] = {}
    expanded_cache: Dict[Path, List[Node]] = {}
    seen_top_identities: Set[Tuple[int, int]] = set()

    def add_top_file(path: Path):
        try:
            ident, real = file_identity(path)
        except OSError:
            return
        if ident in seen_top_identities:
            return
        if real in parsed:
            return
        if real in expanded_cache:
            return
        seen_top_identities.add(ident)
        parsed[real] = parse_nginx_file_expanded(real, raw_cache, expanded_cache, warnings, set())

    def add_root_file(path: Path):
        try:
            ident, real = file_identity(path)
        except OSError as e:
            warn(warnings, f"Could not stat file: {e}", file=str(path))
            return
        if ident in seen_top_identities:
            return
        seen_top_identities.add(ident)
        parsed[real] = parse_nginx_file_expanded(real, raw_cache, expanded_cache, warnings, set())

    def fallback_discover(directory: Path):
        candidates: List[Path] = []
        for p in directory.rglob("*"):
            if not p.is_file():
                continue
            if p.name.endswith(".conf"):
                candidates.append(p)
                continue
            if any(part in ("sites-enabled", "conf.d", "sites-available") for part in p.parts):
                candidates.append(p)
        for p in sorted(set(candidates)):
            add_top_file(p)

    if root.is_file():
        add_root_file(root)
    else:
        nginx_conf = root / "nginx.conf"
        if nginx_conf.exists():
            add_root_file(nginx_conf)
        else:
            fallback_discover(root)

    for pattern in extra_include_globs or []:
        for p in sorted(Path(x) for x in glob.glob(pattern, recursive=True)):
            if p.is_file():
                add_top_file(p)

    return parsed

LISTEN_FLAGS = {
    "default_server", "ssl", "http2", "http3", "quic", "proxy_protocol",
    "reuseport", "backlog", "so_keepalive", "bind", "deferred", "fastopen",
    "ipv6only=on", "ipv6only=off"
}

def extract_port_from_listen_arg(arg: str) -> Optional[int]:
    arg = arg.strip()
    if arg.isdigit():
        return int(arg)
    if arg.startswith("unix:"):
        return None
    m = re.search(r":(\d+)$", arg)
    if m:
        return int(m.group(1))
    return None

def parse_listen(args: List[str]) -> Tuple[int, bool]:
    ssl = any(a == "ssl" for a in args)
    port = None

    for a in args:
        if a in LISTEN_FLAGS:
            continue
        if "=" in a and a.split("=", 1)[0] in LISTEN_FLAGS:
            continue
        p = extract_port_from_listen_arg(a)
        if p is not None:
            port = p
            break

    if port is None:
        port = 443 if ssl else 80

    if port == 443:
        ssl = True

    return port, ssl

def parse_add_header(args: List[str], warnings: List[WarningItem], file: str, line: int) -> Optional[str]:
    if len(args) < 2:
        return None
    name = args[0]
    vals = args[1:]
    if vals and vals[-1].lower() == "always":
        vals = vals[:-1]
    value = " ".join(vals).strip()
    if not value:
        return None
    if "$" in name or "$" in value:
        warn(warnings, "Variable-based add_header could not be converted automatically.", file=file, line=line)
        return None
    return f"{name}: {value}"

def parse_more_set_headers(args: List[str], warnings: List[WarningItem], file: str, line: int) -> Optional[str]:
    raw = " ".join(args).strip()
    raw = re.sub(r"\s+always\s*$", "", raw, flags=re.I).strip()
    if not raw:
        return None
    if "$" in raw:
        warn(warnings, "Variable-based more_set_headers could not be converted automatically.", file=file, line=line)
        return None

    m = re.match(r"^([^:\s]+)\s*:\s*(.+)$", raw)
    if m:
        name = m.group(1).strip()
        value = m.group(2).strip()
        if name and value:
            return f"{name}: {value}"

    parts = raw.split(None, 1)
    if len(parts) == 2:
        name, value = parts[0].strip(), parts[1].strip()
        if name and value:
            return f"{name}: {value}"

    warn(warnings, f"Could not parse more_set_headers value '{raw}'.", file=file, line=line)
    return None

def unique_preserve(items: List[str]) -> List[str]:
    out = []
    seen = set()
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out

# FIXED: invalid/default server-name helpers
def is_invalid_server_name(name: str) -> bool:
    n = (name or "").strip().lower()
    return (
        not n or
        n in ("_", "localhost", "default_server") or
        n.startswith("127.") or
        n == "::1" or
        n.isdigit()
    )

def is_wildcard_server_name(name: str) -> bool:
    return "*" in (name or "")

def first_valid_non_wildcard_name(names: List[str]) -> Optional[str]:
    for n in names:
        if not is_invalid_server_name(n) and not is_wildcard_server_name(n):
            return n
    return None

def first_valid_name(names: List[str]) -> Optional[str]:
    non_wild = first_valid_non_wildcard_name(names)
    if non_wild:
        return non_wild
    for n in names:
        if not is_invalid_server_name(n):
            return n
    return None

def filter_listener_domains(names: List[str]) -> List[str]:
    # Prefer exact non-wildcard valid names; if none exist, fall back to any non-invalid names.
    exact = [n for n in names if not is_invalid_server_name(n) and not is_wildcard_server_name(n)]
    if exact:
        return unique_preserve(exact)
    broad = [n for n in names if not is_invalid_server_name(n)]
    return unique_preserve(broad)

def parse_location(node: Node, warnings: List[WarningItem]) -> NginxLocation:
    modifier = ""
    path = "/"

    if node.args:
        if node.args[0] in ("=", "~", "~*", "^~"):
            modifier = node.args[0]
            path = " ".join(node.args[1:]) if len(node.args) > 1 else "/"
        else:
            path = " ".join(node.args)

    loc = NginxLocation(modifier=modifier, path=path, file=node.file, line=node.line)

    for ch in node.children:
        n = ch.name
        a = ch.args

        if n == "root" and a:
            loc.root = a[0]
        elif n == "alias" and a:
            loc.alias = a[0]
        elif n == "index" and a:
            loc.index_files = a[:]
        elif n == "try_files" and a:
            loc.try_files = a[:]
        elif n == "proxy_pass" and a:
            loc.proxy_pass = a[0]
        elif n == "fastcgi_pass" and a:
            loc.fastcgi_pass = a[0]
        elif n == "proxy_set_header" and len(a) >= 2:
            hdr = a[0].lower()
            if hdr in ("upgrade", "connection"):
                loc.websocket_hint = True
        elif n == "add_header" and a:
            h = parse_add_header(a, warnings, ch.file, ch.line)
            if h:
                loc.add_headers.append(h)
        elif n == "more_set_headers" and a:
            h = parse_more_set_headers(a, warnings, ch.file, ch.line)
            if h:
                loc.add_headers.append(h)
        elif n == "expires" and a:
            loc.expires = " ".join(a)
        elif n == "deny" and a and a[0].lower() == "all":
            loc.deny_all = True
        elif n == "access_log" and a and a[0].lower() == "off":
            loc.access_log_off = True
        elif n == "if":
            warn(warnings, "Unsupported nginx 'if' inside location; review manually.", file=ch.file, line=ch.line)
        elif n == "location":
            warn(warnings, "Nested location block found; review manually.", file=ch.file, line=ch.line)
        elif n == "rewrite":
            warn(warnings, "Raw nginx rewrite directive not directly converted; review manually.", file=ch.file, line=ch.line)
        elif n == "error_page":
            warn(warnings, "nginx error_page is not directly converted; review manually.", file=ch.file, line=ch.line)
        elif n in ("ssl_protocols", "ssl_prefer_server_ciphers"):
            warn(warnings,
                 f"nginx '{n}' inside location is ignored; in OLS TLS settings belong to secure listener level.",
                 file=ch.file, line=ch.line)

    if loc.modifier in ("~", "~*"):
        php_like = bool(re.search(r"\\\.php\$|\.php\$|php", loc.path))
        if not php_like and not loc.expires:
            warn(warnings,
                 f"Regex location '{loc.modifier} {loc.path}' is not fully converted; review manually.",
                 file=loc.file, line=loc.line)

    if loc.websocket_hint:
        warn(warnings, "WebSocket-related proxy headers detected; review proxy context manually.", file=loc.file, line=loc.line)

    loc.add_headers = unique_preserve(loc.add_headers)
    return loc

def parse_server(node: Node, warnings: List[WarningItem]) -> NginxServer:
    srv = NginxServer(file=node.file, line=node.line)

    for ch in node.children:
        n = ch.name
        a = ch.args

        if n == "listen":
            if "quic" in a:
                continue
            port, secure = parse_listen(a)
            srv.listen_specs.add((port, secure))
            if "default_server" in a:
                srv.default_server_like = True
        elif n == "server_name" and a:
            srv.server_names.extend(a)
        elif n == "root" and a:
            srv.root = a[0]
        elif n == "index" and a:
            srv.index_files = a[:]
        elif n == "try_files" and a:
            srv.try_files = a[:]
        elif n == "access_log" and a:
            if a[0].lower() != "off":
                srv.access_log = a[0]
        elif n == "ssl_certificate" and a:
            srv.ssl_cert = a[0]
        elif n == "ssl_certificate_key" and a:
            srv.ssl_key = a[0]
        elif n == "ssl_trusted_certificate" and a:
            srv.ssl_trusted_cert = a[0]
        elif n in ("ssl_stapling", "ssl_stapling_verify") and a and a[0].lower() == "on":
            srv.enable_stapling = True
        elif n == "add_header" and a:
            h = parse_add_header(a, warnings, ch.file, ch.line)
            if h:
                srv.add_headers.append(h)
        elif n == "more_set_headers" and a:
            h = parse_more_set_headers(a, warnings, ch.file, ch.line)
            if h:
                srv.add_headers.append(h)
        elif n == "expires" and a:
            srv.enable_expires = True
        elif n == "location":
            loc = parse_location(ch, warnings)
            srv.locations.append(loc)
            if loc.expires:
                srv.enable_expires = True
        elif n == "if":
            warn(warnings, "Unsupported nginx 'if' inside server; review manually.", file=ch.file, line=ch.line)
        elif n == "error_page":
            warn(warnings, "nginx error_page is not directly converted; review manually.", file=ch.file, line=ch.line)
        elif n == "return":
            warn(warnings, "nginx return directive not directly converted; review manually.", file=ch.file, line=ch.line)
        elif n in ("ssl_protocols", "ssl_prefer_server_ciphers"):
            warn(warnings,
                 f"nginx '{n}' is ignored in vhost conversion; in OLS TLS settings belong to secure listener level.",
                 file=ch.file, line=ch.line)

    if not srv.listen_specs:
        srv.listen_specs.add((80, False))

    root_loc = None
    for loc in srv.locations:
        if loc.path == "/" and loc.modifier in ("", "^~"):
            root_loc = loc
            break

    if root_loc:
        if not srv.root and root_loc.root:
            srv.root = root_loc.root
        if not srv.index_files and root_loc.index_files:
            srv.index_files = root_loc.index_files[:]
        if not srv.try_files and root_loc.try_files:
            srv.try_files = root_loc.try_files[:]

    if srv.ssl_cert or srv.ssl_key:
        new_specs = set()
        for port, secure in srv.listen_specs:
            if port == 443:
                secure = True
            new_specs.add((port, secure))
        srv.listen_specs = new_specs

    if srv.root and "://" in srv.root:
        warn(warnings,
             f"Suspicious nginx root path '{srv.root}' contains '://'; review manually.",
             file=srv.file, line=srv.line)

    srv.add_headers = unique_preserve(srv.add_headers)
    return srv

def extract_nginx_objects(parsed: Dict[Path, List[Node]], warnings: List[WarningItem]):
    servers: List[NginxServer] = []
    upstreams: Dict[str, NginxUpstream] = {}

    for _, nodes in parsed.items():
        for node in walk_nodes(nodes):
            if node.name == "upstream" and node.children and node.args:
                up = NginxUpstream(name=node.args[0], file=node.file, line=node.line)
                for ch in node.children:
                    if ch.name == "server" and ch.args:
                        up.servers.append(ch.args[0])
                upstreams[up.name] = up
            elif node.name == "server" and node.children:
                servers.append(parse_server(node, warnings))

    return servers, upstreams

# FIXED: invalid/default server name handling
def primary_server_name(srv: NginxServer) -> str:
    chosen = first_valid_non_wildcard_name(srv.server_names)
    if chosen:
        return chosen

    chosen = first_valid_name(srv.server_names)
    if chosen:
        return chosen

    if srv.default_server_like or not srv.server_names or any(is_invalid_server_name(n) for n in srv.server_names):
        return "default"

    stem = Path(srv.file).name
    if stem.endswith(".conf"):
        stem = stem[:-5]
    return stem or "migrated-site"

def infer_php_app(fastcgi_pass: str) -> PhpApp:
    val = fastcgi_pass.strip()
    version = None

    m = re.search(r"php\s*([0-9]+)\.([0-9]+)", val)
    if m:
        version = f"{m.group(1)}{m.group(2)}"
    else:
        m = re.search(r"php([0-9]{2,3})", val)
        if m:
            version = m.group(1)

    if version:
        name = f"lsphp{version}"
        binary = f"/usr/local/lsws/{name}/bin/lsphp"
        uds = f"uds://tmp/lshttpd/{name}.sock"
    else:
        name = "lsphp"
        binary = "/usr/local/lsws/lsphp/bin/lsphp"
        uds = "uds://tmp/lshttpd/lsphp.sock"

    return PhpApp(name=name, binary_path=binary, uds_address=uds)

def merge_servers_to_sites(servers: List[NginxServer], warnings: List[WarningItem]) -> List[Site]:
    grouped: Dict[str, List[NginxServer]] = {}
    for srv in servers:
        grouped.setdefault(primary_server_name(srv), []).append(srv)

    used_names: Set[str] = set()
    sites: List[Site] = []

    for key, members in grouped.items():
        site = Site()
        site.vhost_name = ensure_unique_name(key, used_names)

        names_seen: List[str] = []
        warned_invalid_names: Set[str] = set()
        loc_signatures: Set[Tuple[str, str, str, str, str, str, str, str, str]] = set()
        php_apps_seen: Dict[str, str] = {}
        hdrs: List[str] = []

        for srv in members:
            site.source_files.add(srv.file)

            if srv.enable_expires:
                site.enable_expires = True
            if srv.enable_stapling:
                site.enable_stapling = True

            for sn in srv.server_names:
                if sn not in names_seen:
                    names_seen.append(sn)
                if is_invalid_server_name(sn) and sn not in warned_invalid_names:
                    warned_invalid_names.add(sn)
                    warn(
                        warnings,
                        f"Invalid/special nginx server_name '{sn}' treated as default-style mapping.",
                        file=srv.file,
                        line=srv.line,
                        site=site.vhost_name
                    )

            site.listen_specs |= srv.listen_specs

            if srv.root and not site.root:
                site.root = srv.root
            elif srv.root and site.root and srv.root != site.root:
                warn(warnings,
                     f"Conflicting roots for merged site '{site.vhost_name}': '{site.root}' vs '{srv.root}'. Using first one.",
                     file=srv.file, line=srv.line, site=site.vhost_name)

            if srv.index_files and not site.index_files:
                site.index_files = srv.index_files[:]
            elif srv.index_files and site.index_files and srv.index_files != site.index_files:
                warn(warnings,
                     f"Conflicting index files for merged site '{site.vhost_name}'. Using first set.",
                     file=srv.file, line=srv.line, site=site.vhost_name)

            if srv.try_files and not site.try_files:
                site.try_files = srv.try_files[:]

            if srv.access_log and not site.access_log:
                site.access_log = srv.access_log

            if srv.ssl_cert and not site.ssl_cert:
                site.ssl_cert = srv.ssl_cert
            elif srv.ssl_cert and site.ssl_cert and srv.ssl_cert != site.ssl_cert:
                warn(warnings,
                     f"Conflicting ssl_certificate values for '{site.vhost_name}'. Using first one.",
                     file=srv.file, line=srv.line, site=site.vhost_name)

            if srv.ssl_key and not site.ssl_key:
                site.ssl_key = srv.ssl_key
            elif srv.ssl_key and site.ssl_key and srv.ssl_key != site.ssl_key:
                warn(warnings,
                     f"Conflicting ssl_certificate_key values for '{site.vhost_name}'. Using first one.",
                     file=srv.file, line=srv.line, site=site.vhost_name)

            if srv.ssl_trusted_cert and not site.ssl_trusted_cert:
                site.ssl_trusted_cert = srv.ssl_trusted_cert

            hdrs.extend(srv.add_headers)

            for loc in srv.locations:
                sig = (
                    loc.modifier, loc.path,
                    loc.root or "", loc.alias or "",
                    loc.proxy_pass or "", loc.fastcgi_pass or "",
                    "|".join(loc.add_headers), loc.expires or "",
                    "deny" if loc.deny_all else ""
                )
                if sig not in loc_signatures:
                    loc_signatures.add(sig)
                    site.locations.append(loc)

                php_like = (
                    bool(loc.fastcgi_pass) and
                    loc.modifier in ("~", "~*") and
                    bool(re.search(r"\\\.php\$|\.php\$|php", loc.path))
                )
                if php_like:
                    app = infer_php_app(loc.fastcgi_pass or "")
                    php_apps_seen[app.name] = loc.fastcgi_pass or ""

        site.server_names = names_seen

        if php_apps_seen:
            if len(php_apps_seen) > 1:
                warn(warnings,
                     f"Multiple PHP backends detected for '{site.vhost_name}'. Using the first one.",
                     site=site.vhost_name)
            app_name = list(php_apps_seen.keys())[0]
            site.php_app = app_name
            site.php_socket_source = php_apps_seen[app_name]

        if not site.root:
            site.root = DEFAULT_DOCROOT
            warn(warnings,
                 f"No root found for '{site.vhost_name}'. Falling back to {DEFAULT_DOCROOT}.",
                 site=site.vhost_name)

        if not site.index_files:
            site.index_files = DEFAULT_INDEX_PHP[:] if site.php_app else DEFAULT_INDEX_HTML[:]

        site.add_headers = unique_preserve(hdrs)
        sites.append(site)

    return sites

def normalize_index_files(vals: List[str]) -> List[str]:
    out = []
    seen = set()
    for v in vals:
        v = v.strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out

def nginx_try_files_to_ols_rules(try_files: List[str], warnings: List[WarningItem], site: Site) -> List[str]:
    if not try_files or len(try_files) < 2:
        return []

    fallback = try_files[-1].strip()

    if fallback.startswith("="):
        warn(warnings,
             f"try_files fallback '{fallback}' for '{site.vhost_name}' is not directly converted.",
             site=site.vhost_name)
        return []

    if not fallback.startswith("/"):
        warn(warnings,
             f"Only path-based try_files fallback is converted. Got '{fallback}' for '{site.vhost_name}'.",
             site=site.vhost_name)
        return []

    target = fallback
    flags = "L"

    if "?" in fallback:
        path, query = fallback.split("?", 1)
        target = path
        if query in ("$args", "$query_string", "") or "$args" in query or "$query_string" in query:
            flags = "QSA,L"
        else:
            flags = "QSA,L"
            warn(warnings,
                 f"Complex try_files query part '{query}' for '{site.vhost_name}' converted best-effort.",
                 site=site.vhost_name)

    return [
        "RewriteCond %{REQUEST_FILENAME} !-f",
        "RewriteCond %{REQUEST_FILENAME} !-d",
        f"RewriteRule ^(.*)$ {target} [{flags}]",
    ]

def is_same_path(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    return os.path.normpath(a) == os.path.normpath(b)

def path_join_uri_root(root: str, uri_path: str) -> str:
    uri_part = uri_path.lstrip("/")
    return os.path.normpath(os.path.join(root, uri_part))

def resolve_proxy_pass(proxy_pass: str,
                       upstreams: Dict[str, NginxUpstream],
                       warnings: List[WarningItem],
                       site: Site,
                       loc: NginxLocation) -> Optional[ProxyApp]:
    val = proxy_pass.strip()

    if "$" in val:
        warn(warnings,
             f"Variable-based proxy_pass '{val}' is not supported automatically.",
             file=loc.file, line=loc.line, site=site.vhost_name)
        return None

    if val.startswith("http://") or val.startswith("https://"):
        parsed = urlparse(val)

        if parsed.scheme == "https":
            warn(warnings,
                 f"https upstream '{val}' for '{site.vhost_name}' needs manual review.",
                 file=loc.file, line=loc.line, site=site.vhost_name)

        host = parsed.hostname
        port = parsed.port
        path = parsed.path or ""

        if host in upstreams:
            up = upstreams[host]
            if not up.servers:
                warn(warnings,
                     f"Upstream '{host}' has no backend servers.",
                     file=loc.file, line=loc.line, site=site.vhost_name)
                return None

            if len(up.servers) > 1:
                warn(warnings,
                     f"Upstream '{host}' has multiple backends; only the first one will be used.",
                     file=up.file, line=up.line, site=site.vhost_name)

            first = up.servers[0]
            if first.startswith("unix:"):
                warn(warnings,
                     f"Unix-socket upstream '{host}' is not converted automatically.",
                     file=up.file, line=up.line, site=site.vhost_name)
                return None

            addr = first
            if "/" in addr:
                addr = addr.split("/", 1)[0]

            name = sanitize_name(f"proxy_{host}")
            return ProxyApp(name=name, address=addr)

        if host and port:
            if path not in ("", "/"):
                warn(warnings,
                     f"proxy_pass path '{val}' is simplified to backend '{host}:{port}'. Review manually.",
                     file=loc.file, line=loc.line, site=site.vhost_name)
            name = sanitize_name(f"proxy_{host}_{port}")
            return ProxyApp(name=name, address=f"{host}:{port}")

        if host and not port:
            default_port = 443 if parsed.scheme == "https" else 80
            name = sanitize_name(f"proxy_{host}_{default_port}")
            return ProxyApp(name=name, address=f"{host}:{default_port}")

    warn(warnings,
         f"Unsupported proxy_pass '{val}'. Review manually.",
         file=loc.file, line=loc.line, site=site.vhost_name)
    return None

def render_rewrite_block(enable_htaccess: bool, rules: List[str]) -> str:
    lines = [
        "rewrite  {",
        "  enable                  1",
        f"  autoLoadHtaccess        {1 if enable_htaccess else 0}",
    ]
    if rules:
        lines.append("  rewriteRules            <<<END_REWRITE_RULES")
        lines.extend(rules)
        lines.append("END_REWRITE_RULES")
    lines.append("}")
    return "\n".join(lines)

def render_index_block(index_files: List[str]) -> str:
    idx = " ".join(normalize_index_files(index_files))
    return "\n".join([
        "index  {",
        "  useServer               0",
        f"  indexFiles              {idx}",
        "}",
    ])

def render_accesslog_block(path: str) -> str:
    return "\n".join([
        f"accesslog {path} {{",
        "  useServer               0",
        "  logFormat               \"%h %l %u %t \\\"%r\\\" %>s %b\"",
        "  rollingSize             10M",
        "  keepDays                30",
        "  compressArchive         1",
        "}",
    ])

def render_vhssl_block(site: Site, warnings: List[WarningItem]) -> str:
    if site.ssl_cert and site.ssl_key:
        lines = [
            "vhssl  {",
            f"  keyFile                 {site.ssl_key}",
            f"  certFile                {site.ssl_cert}",
            "  certChain               1",
        ]
        if site.enable_stapling:
            lines.append("  enableStapling          1")
        lines.append("}")
        return "\n".join(lines)

    secure_ports = [p for p, s in site.listen_specs if s]
    if secure_ports:
        warn(warnings,
             f"Site '{site.vhost_name}' listens on secure port(s) {secure_ports} but cert/key is incomplete.",
             site=site.vhost_name)
    return ""

def render_scripthandler_block(site: Site) -> str:
    if not site.php_app:
        return ""
    return "\n".join([
        "scripthandler  {",
        f"  add                     lsapi:{site.php_app} php",
        "}",
    ])

def render_extra_headers(headers: List[str]) -> str:
    headers = unique_preserve(headers)
    if not headers:
        return ""
    lines = ["  extraHeaders            <<<END_extraHeaders"]
    lines.extend(headers)
    lines.append("END_extraHeaders")
    return "\n".join(lines)

def build_root_context(site: Site, root_loc: Optional[NginxLocation], headers: List[str]) -> Optional[str]:
    headers = unique_preserve(headers)
    if not headers and not root_loc:
        return None

    if root_loc and root_loc.alias:
        location = root_loc.alias
        if not location.endswith("/"):
            location += "/"
    elif root_loc and root_loc.root and not is_same_path(root_loc.root, site.root):
        location = root_loc.root
        if not location.endswith("/"):
            location += "/"
    else:
        location = "$DOC_ROOT/"

    parts = [
        "context / {",
        "  type                    static",
        f"  location                {location}",
        "  allowBrowse             1",
    ]

    hdr = render_extra_headers(headers)
    if hdr:
        parts.append(hdr)

    parts.append("}")
    return "\n".join(parts)

def build_static_context(site: Site, loc: NginxLocation) -> Optional[str]:
    if loc.modifier in ("~", "~*"):
        return None
    if loc.deny_all:
        return None
    if not (loc.root or loc.alias or loc.add_headers):
        return None

    uri = loc.path or "/"
    if not uri.startswith("/"):
        return None

    if loc.alias:
        target = loc.alias
        if uri.endswith("/") and not target.endswith("/"):
            target += "/"
    elif loc.root:
        if uri == "/" and is_same_path(loc.root, site.root) and not loc.add_headers:
            return None
        if uri.endswith("/"):
            target = path_join_uri_root(loc.root, uri)
            if not target.endswith("/"):
                target += "/"
        else:
            target = path_join_uri_root(loc.root, uri)
    else:
        target = "$DOC_ROOT/" if uri == "/" else f"$DOC_ROOT{uri}"

    parts = [
        f"context {uri} {{",
        "  type                    static",
        f"  location                {target}",
        f"  allowBrowse             {1 if uri.endswith('/') else 0}",
    ]

    hdr = render_extra_headers(loc.add_headers)
    if hdr:
        parts.append(hdr)

    parts.append("}")
    return "\n".join(parts)

def build_deny_context(site: Site, loc: NginxLocation) -> Optional[str]:
    if not loc.deny_all:
        return None
    if loc.modifier != "=":
        return None
    uri = loc.path.strip()
    if not uri.startswith("/"):
        return None

    if loc.alias:
        target = loc.alias
    elif loc.root:
        target = path_join_uri_root(loc.root, uri)
    else:
        target = f"$DOC_ROOT{uri}"

    return "\n".join([
        f"context {uri} {{",
        "  type                    static",
        f"  location                {target}",
        "  accessible              0",
        "  allowBrowse             0",
        "}",
    ])

def build_proxy_context(loc: NginxLocation, proxy_app: ProxyApp) -> str:
    uri = loc.path or "/"
    parts = [
        f"context {uri} {{",
        "  type                    proxy",
        f"  handler                 {proxy_app.name}",
        "  addDefaultCharset       off",
    ]
    hdr = render_extra_headers(loc.add_headers)
    if hdr:
        parts.append(hdr)
    parts.append("}")
    return "\n".join(parts)

def render_site_vhconf(site: Site,
                       upstreams: Dict[str, NginxUpstream],
                       warnings: List[WarningItem],
                       enable_htaccess: bool) -> Tuple[str, Dict[str, PhpApp], Dict[str, ProxyApp]]:
    php_apps: Dict[str, PhpApp] = {}
    proxy_apps: Dict[str, ProxyApp] = {}

    if site.php_app and site.php_socket_source:
        php = infer_php_app(site.php_socket_source)
        php_apps[php.name] = php

    rewrite_rules: List[str] = []
    if site.try_files:
        rewrite_rules.extend(nginx_try_files_to_ols_rules(site.try_files, warnings, site))

    root_loc = None
    for loc in site.locations:
        if loc.path == "/" and loc.modifier in ("", "^~"):
            root_loc = loc
            break

    root_headers = site.add_headers[:]
    if root_loc:
        root_headers.extend(root_loc.add_headers)
    root_headers = unique_preserve(root_headers)

    contexts: List[str] = []
    seen_contexts: Set[str] = set()

    root_ctx = build_root_context(site, root_loc, root_headers)
    if root_ctx:
        contexts.append(root_ctx)
        seen_contexts.add(root_ctx)

    for loc in site.locations:
        php_like = (
            bool(loc.fastcgi_pass) and
            loc.modifier in ("~", "~*") and
            bool(re.search(r"\\\.php\$|\.php\$|php", loc.path))
        )
        if php_like:
            continue

        if loc.try_files and loc.path != "/":
            warn(warnings,
                 f"try_files inside location '{loc.path}' for '{site.vhost_name}' is not fully converted.",
                 file=loc.file, line=loc.line, site=site.vhost_name)

        deny_ctx = build_deny_context(site, loc)
        if deny_ctx and deny_ctx not in seen_contexts:
            contexts.append(deny_ctx)
            seen_contexts.add(deny_ctx)
            continue

        if loc.proxy_pass:
            app = resolve_proxy_pass(loc.proxy_pass, upstreams, warnings, site, loc)
            if app:
                proxy_apps[app.name] = app
                ctx = build_proxy_context(loc, app)
                if ctx not in seen_contexts:
                    contexts.append(ctx)
                    seen_contexts.add(ctx)
            continue

        if loc.fastcgi_pass and not php_like:
            warn(warnings,
                 f"Non-standard fastcgi location '{loc.path}' for '{site.vhost_name}' needs manual review.",
                 file=loc.file, line=loc.line, site=site.vhost_name)
            continue

        if loc.path == "/" and loc.modifier in ("", "^~"):
            continue

        static_ctx = build_static_context(site, loc)
        if static_ctx and static_ctx not in seen_contexts:
            contexts.append(static_ctx)
            seen_contexts.add(static_ctx)

    docroot = site.root or DEFAULT_DOCROOT
    index_files = normalize_index_files(site.index_files or DEFAULT_INDEX_HTML)
    accesslog_path = site.access_log or "$VH_ROOT/logs/access.log"

    parts = []
    parts.append(f"docRoot                   {docroot}")
    parts.append("")

    if site.enable_expires:
        parts.append("enableExpires            1")
        parts.append("")

    parts.append(render_accesslog_block(accesslog_path))
    parts.append("")
    parts.append(render_index_block(index_files))
    parts.append("")

    sh = render_scripthandler_block(site)
    if sh:
        parts.append(sh)
        parts.append("")

    for ctx in contexts:
        parts.append(ctx)
        parts.append("")

    parts.append(render_rewrite_block(enable_htaccess=enable_htaccess, rules=rewrite_rules))
    parts.append("")

    ssl_block = render_vhssl_block(site, warnings)
    if ssl_block:
        parts.append(ssl_block)
        parts.append("")

    text = "\n".join(parts).rstrip() + "\n"
    return text, php_apps, proxy_apps

def render_php_extprocessor(app: PhpApp) -> str:
    return "\n".join([
        f"extprocessor {app.name} {{",
        "  type                    lsapi",
        f"  address                 {app.uds_address}",
        "  maxConns                35",
        "  env                     PHP_LSAPI_CHILDREN=35",
        "  initTimeout             60",
        "  retryTimeout            0",
        "  persistConn             1",
        "  respBuffer              0",
        "  autoStart               2",
        f"  path                    {app.binary_path}",
        "  backlog                 100",
        "  instances               1",
        "  extUser                 nobody",
        "  extGroup                nobody",
        "  runOnStartUp            3",
        "  priority                0",
        "  memSoftLimit            2047M",
        "  memHardLimit            2047M",
        "  procSoftLimit           1400",
        "  procHardLimit           1500",
        "}",
    ])

def render_proxy_extprocessor(app: ProxyApp) -> str:
    return "\n".join([
        f"extprocessor {app.name} {{",
        "  type                    webserver",
        f"  address                 {app.address}",
        "  maxConns                100",
        "  initTimeout             60",
        "  retryTimeout            0",
        "  persistConn             1",
        "  respBuffer              0",
        "}",
    ])

def render_virtualhost_block(site: Site, ols_vhosts_root: Path) -> str:
    vh_root = (ols_vhosts_root / site.vhost_name).as_posix().rstrip("/") + "/"
    vh_conf = (ols_vhosts_root / site.vhost_name / "vhconf.conf").as_posix()

    return "\n".join([
        f"virtualhost {site.vhost_name} {{",
        f"  vhRoot                  {vh_root}",
        f"  configFile              {vh_conf}",
        "  allowSymbolLink         1",
        "  enableScript            1",
        "  restrained              1",
        "  setUIDMode              0",
        "}",
    ])

def strip_managed_block(text: str, begin_marker: str, end_marker: str) -> str:
    pattern = re.compile(re.escape(begin_marker) + r".*?" + re.escape(end_marker), re.S)
    return pattern.sub("", text)

def strip_all_managed_sections(text: str) -> str:
    text = strip_managed_block(text, GLOBAL_BEGIN_LISTENERS, GLOBAL_END_LISTENERS)
    text = strip_managed_block(text, GLOBAL_BEGIN_VHOSTS, GLOBAL_END_VHOSTS)
    text = strip_managed_block(text, GLOBAL_BEGIN_EXTPROC, GLOBAL_END_EXTPROC)
    text = strip_managed_block(text, INNER_BEGIN_MAPS, INNER_END_MAPS)
    return text

def find_matching_brace(text: str, open_brace_idx: int) -> int:
    depth = 0
    i = open_brace_idx
    in_quote = None
    n = len(text)

    while i < n:
        ch = text[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_quote:
                in_quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            in_quote = ch
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    raise ValueError("Unmatched brace in OLS config.")

def parse_ols_existing_listeners(httpd_text: str) -> List[ExistingListener]:
    listeners: List[ExistingListener] = []

    for m in re.finditer(r'(^|\n)\s*listener\s+([^\s{]+)\s*\{', httpd_text):
        name = m.group(2)
        brace_idx = httpd_text.find("{", m.start())
        if brace_idx == -1:
            continue
        try:
            end_idx = find_matching_brace(httpd_text, brace_idx)
        except ValueError:
            continue

        block_text = httpd_text[m.start():end_idx + 1]
        body = httpd_text[brace_idx + 1:end_idx]

        port = None
        secure = False

        addr_match = re.search(r'^\s*address\s+([^\n]+)$', body, flags=re.M)
        if addr_match:
            addr = addr_match.group(1).strip()
            pm = re.search(r':(\d+)\s*$', addr)
            if pm:
                port = int(pm.group(1))

        sec_match = re.search(r'^\s*secure\s+([01])\s*$', body, flags=re.M)
        if sec_match:
            secure = sec_match.group(1) == "1"

        listeners.append(ExistingListener(
            name=name,
            start=m.start(),
            end=end_idx + 1,
            text=block_text,
            port=port,
            secure=secure,
        ))

    return listeners

def inject_maps_into_listener_block(block_text: str, map_lines: List[str]) -> str:
    block_text = strip_managed_block(block_text, INNER_BEGIN_MAPS, INNER_END_MAPS).rstrip()

    if not map_lines:
        return block_text + "\n"

    marker = "\n".join(
        ["  " + INNER_BEGIN_MAPS] +
        [f"  {line}" for line in map_lines] +
        ["  " + INNER_END_MAPS]
    )

    close_idx = block_text.rfind("}")
    if close_idx == -1:
        return block_text + "\n" + marker + "\n"

    before = block_text[:close_idx].rstrip()
    after = block_text[close_idx:]
    return before + "\n" + marker + "\n" + after + ("\n" if not after.endswith("\n") else "")

def replace_listener_blocks(httpd_text: str, replacements: List[Tuple[int, int, str]]) -> str:
    out = httpd_text
    for start, end, new_text in sorted(replacements, key=lambda x: x[0], reverse=True):
        out = out[:start] + new_text + out[end:]
    return out

def render_listener_block(name: str,
                          port: int,
                          secure: bool,
                          map_lines: List[str]) -> str:
    lines = [
        f"listener {name} {{",
        f"  address                 *:{port}",
        f"  secure                  {1 if secure else 0}",
    ]

    if secure:
        # FIXED: use requested webadmin cert/key for secure listener bootstrap
        lines.append(f"  keyFile                 {DEFAULT_OLS_WEBADMIN_KEY}")
        lines.append(f"  certFile                {DEFAULT_OLS_WEBADMIN_CERT}")

    lines.extend(map_lines)
    lines.append("}")
    return "\n".join(lines)

def append_managed_block(text: str, begin: str, end: str, content: str) -> str:
    block = f"\n{begin}\n{content.rstrip()}\n{end}\n"
    return text.rstrip() + "\n" + block

# FIXED: correct OLS listener map direction and invalid/default domain handling
def build_listener_map_line(site: Site) -> str:
    domains = filter_listener_domains(site.server_names)
    if not domains:
        domains = ["default"]
    rhs = ", ".join(domains)
    return f"map                     {site.vhost_name} {rhs}"

def patch_httpd_config(orig_httpd: str,
                       sites: List[Site],
                       php_apps: Dict[str, PhpApp],
                       proxy_apps: Dict[str, ProxyApp],
                       ols_vhosts_root: Path,
                       warnings: List[WarningItem]) -> Tuple[str, Dict[str, List[str]], Dict[str, List[str]]]:
    clean = strip_all_managed_sections(orig_httpd)
    existing = parse_ols_existing_listeners(clean)

    used_listener_names = {x.name for x in existing}
    listener_by_spec: Dict[Tuple[int, bool], str] = {}

    for lst in existing:
        if lst.port is not None:
            listener_by_spec.setdefault((lst.port, lst.secure), lst.name)

    site_listeners: Dict[str, List[str]] = {}
    new_listener_specs: Dict[Tuple[int, bool], str] = {}

    for site in sites:
        site_listeners[site.vhost_name] = []
        for spec in sorted(site.listen_specs):
            port, secure = spec
            if spec in listener_by_spec:
                lname = listener_by_spec[spec]
            else:
                if spec not in new_listener_specs:
                    base = f"NginxMigrated_{port}{'_SSL' if secure else ''}"
                    lname = ensure_unique_name(base, used_listener_names)
                    new_listener_specs[spec] = lname
                    listener_by_spec[spec] = lname
                lname = new_listener_specs[spec]
            if lname not in site_listeners[site.vhost_name]:
                site_listeners[site.vhost_name].append(lname)

    listener_maps: Dict[str, Set[str]] = {}
    for site in sites:
        map_line = build_listener_map_line(site)
        for lname in site_listeners[site.vhost_name]:
            listener_maps.setdefault(lname, set())
            listener_maps[lname].add(map_line)

    listener_map_lines: Dict[str, List[str]] = {name: sorted(lines) for name, lines in listener_maps.items()}

    replacements = []
    for lst in existing:
        new_block = inject_maps_into_listener_block(lst.text, listener_map_lines.get(lst.name, []))
        replacements.append((lst.start, lst.end, new_block))
    patched = replace_listener_blocks(clean, replacements)

    new_listener_blocks: List[str] = []
    for (port, secure), lname in sorted(new_listener_specs.items()):
        block = render_listener_block(
            name=lname,
            port=port,
            secure=secure,
            map_lines=listener_map_lines.get(lname, []),
        )
        new_listener_blocks.append(block)

    ext_blocks = []
    for app in sorted(php_apps.values(), key=lambda x: x.name):
        ext_blocks.append(render_php_extprocessor(app))
    for app in sorted(proxy_apps.values(), key=lambda x: x.name):
        ext_blocks.append(render_proxy_extprocessor(app))

    vh_blocks = [render_virtualhost_block(site, ols_vhosts_root) for site in sites]

    if new_listener_blocks:
        patched = append_managed_block(
            patched, GLOBAL_BEGIN_LISTENERS, GLOBAL_END_LISTENERS, "\n\n".join(new_listener_blocks)
        )

    if ext_blocks:
        patched = append_managed_block(
            patched, GLOBAL_BEGIN_EXTPROC, GLOBAL_END_EXTPROC, "\n\n".join(ext_blocks)
        )

    if vh_blocks:
        patched = append_managed_block(
            patched, GLOBAL_BEGIN_VHOSTS, GLOBAL_END_VHOSTS, "\n\n".join(vh_blocks)
        )

    return patched, {k: sorted(v) for k, v in listener_map_lines.items()}, site_listeners

def write_preview_output(output_dir: Path,
                         patched_httpd: str,
                         vhost_texts: Dict[str, str],
                         warnings: List[WarningItem],
                         sites: List[Site],
                         site_listeners: Dict[str, List[str]],
                         listener_maps: Dict[str, List[str]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "httpd_config.patched.conf").write_text(patched_httpd, encoding="utf-8")

    vhosts_root = output_dir / "vhosts"
    for site_name, text in vhost_texts.items():
        site_dir = vhosts_root / site_name
        site_dir.mkdir(parents=True, exist_ok=True)
        (site_dir / "vhconf.conf").write_text(text, encoding="utf-8")

    json_dump([w.to_dict() for w in warnings], output_dir / "warnings.json")

    report_lines = []
    report_lines.append("NGINX -> OLS MIGRATION REPORT")
    report_lines.append("=" * 80)
    report_lines.append("")
    report_lines.append(f"Generated at: {dt.datetime.now().isoformat()}")
    report_lines.append("")
    report_lines.append("Generated sites:")
    report_lines.append("")

    for site in sites:
        report_lines.append(f"- vhost: {site.vhost_name}")
        names_desc = " ".join(site.server_names) if site.server_names else "(none)"
        report_lines.append(f"  server_names: {names_desc}")
        listen_desc = ", ".join([f"{p}{'/ssl' if s else ''}" for p, s in sorted(site.listen_specs)])
        report_lines.append(f"  listens: {listen_desc}")
        report_lines.append(f"  docRoot: {site.root}")
        report_lines.append(f"  enableExpires: {1 if site.enable_expires else 0}")
        report_lines.append(f"  enableStapling: {1 if site.enable_stapling else 0}")
        report_lines.append(f"  php_app: {site.php_app or '(none)'}")
        report_lines.append(f"  listeners: {', '.join(site_listeners.get(site.vhost_name, []))}")
        report_lines.append(f"  sources: {', '.join(sorted(site.source_files))}")
        report_lines.append("")

    report_lines.append("Listener maps:")
    report_lines.append("")
    for listener, maps in sorted(listener_maps.items()):
        report_lines.append(f"- {listener}")
        for m in maps:
            report_lines.append(f"    {m}")
    report_lines.append("")

    report_lines.append(f"Warnings: {len(warnings)}")
    report_lines.append("")
    for w in warnings:
        prefix = f"[{w.level.upper()}]"
        where = []
        if w.site:
            where.append(f"site={w.site}")
        if w.file:
            where.append(f"file={w.file}")
        if w.line:
            where.append(f"line={w.line}")
        suffix = f" ({', '.join(where)})" if where else ""
        report_lines.append(f"{prefix} {w.message}{suffix}")

    (output_dir / "migration_report.txt").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

# FIXED: ownership / permission helpers
def stat_uid_gid(path: Path) -> Tuple[Optional[int], Optional[int]]:
    try:
        st = path.stat()
        return st.st_uid, st.st_gid
    except Exception:
        return None, None

def stat_mode(path: Path) -> Optional[int]:
    try:
        st = path.stat()
        return stat.S_IMODE(st.st_mode)
    except Exception:
        return None

def detect_owner_group_for_site_dir(site_dir: Path, ols_vhosts_root: Path) -> Tuple[Optional[int], Optional[int]]:
    for p in (site_dir, ols_vhosts_root, ols_vhosts_root.parent):
        uid, gid = stat_uid_gid(p)
        if uid is not None and gid is not None:
            return uid, gid
    return None, None

def safe_chown(path: Path,
               uid: Optional[int],
               gid: Optional[int],
               warnings: List[WarningItem],
               site: str = "") -> None:
    if uid is None or gid is None:
        return
    try:
        os.chown(str(path), uid, gid)
    except PermissionError:
        warn(warnings, f"Could not chown '{path}' (permission denied).", file=str(path), site=site)
    except Exception as e:
        warn(warnings, f"Could not chown '{path}': {e}", file=str(path), site=site)

def safe_chmod(path: Path,
               mode: int,
               warnings: List[WarningItem],
               site: str = "") -> None:
    try:
        os.chmod(path, mode)
    except Exception as e:
        warn(warnings, f"Could not chmod '{path}': {e}", file=str(path), site=site)

def apply_to_real_ols(patched_httpd: str,
                      vhost_texts: Dict[str, str],
                      ols_httpd: Path,
                      ols_vhosts_root: Path,
                      warnings: List[WarningItem]) -> List[str]:
    actions: List[str] = []

    ols_httpd.parent.mkdir(parents=True, exist_ok=True)
    bak = backup_file(ols_httpd)
    if bak:
        actions.append(f"Backed up {ols_httpd} -> {bak}")
    ols_httpd.write_text(patched_httpd, encoding="utf-8")
    actions.append(f"Wrote {ols_httpd}")

    for site_name, text in vhost_texts.items():
        site_dir = ols_vhosts_root / site_name
        logs_dir = site_dir / "logs"
        target = site_dir / "vhconf.conf"

        uid, gid = detect_owner_group_for_site_dir(site_dir, ols_vhosts_root)

        site_dir_mode = stat_mode(site_dir) or stat_mode(ols_vhosts_root) or 0o755
        logs_dir_mode = stat_mode(logs_dir) or site_dir_mode or 0o755
        target_mode = stat_mode(target) or 0o640

        site_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)

        safe_chown(site_dir, uid, gid, warnings, site=site_name)
        safe_chown(logs_dir, uid, gid, warnings, site=site_name)
        safe_chmod(site_dir, site_dir_mode, warnings, site=site_name)
        safe_chmod(logs_dir, logs_dir_mode, warnings, site=site_name)

        bak = backup_file(target)
        if bak:
            actions.append(f"Backed up {target} -> {bak}")

        target.write_text(text, encoding="utf-8")

        safe_chown(target, uid, gid, warnings, site=site_name)
        safe_chmod(target, target_mode, warnings, site=site_name)

        actions.append(f"Wrote {target}")

    return actions

def build_argument_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Convert nginx config to OpenLiteSpeed config.",
        add_help=False
    )
    p.add_argument("-h", "--help", "-H", action="help", help="show this help message and exit")
    p.add_argument("--nginx", default="/etc/nginx",
                   help="Path to nginx.conf, a single nginx .conf file, or nginx config directory")
    p.add_argument("--ols-httpd", default="/usr/local/lsws/conf/httpd_config.conf",
                   help="Path to OLS global httpd_config.conf")
    p.add_argument("--ols-vhosts-root", default="/usr/local/lsws/conf/vhosts",
                   help="Path to OLS vhosts root")
    p.add_argument("--output", default=DEFAULT_OUTPUT_DIR,
                   help="Preview output directory")
    p.add_argument("--apply", action="store_true",
                   help="Write generated config to real OLS paths")
    p.add_argument("--disable-htaccess", action="store_true",
                   help="Disable OLS autoLoadHtaccess")
    p.add_argument("--extra-include-glob", action="append", default=[],
                   help="Additional nginx include glob to parse as extra top-level input")
    return p

def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "help":
        sys.argv = [sys.argv[0], "--help"] + sys.argv[2:]

    parser = build_argument_parser()
    args = parser.parse_args()

    nginx_path = Path(args.nginx)
    ols_httpd = Path(args.ols_httpd)
    ols_vhosts_root = Path(args.ols_vhosts_root)
    output_dir = Path(args.output)
    enable_htaccess = not args.disable_htaccess

    warnings: List[WarningItem] = []

    if not nginx_path.exists():
        print(f"ERROR: nginx path does not exist: {nginx_path}", file=sys.stderr)
        return 1

    if not ols_httpd.exists():
        warn(warnings, f"OLS httpd config does not exist yet: {ols_httpd}. A new file will be written.")

    parsed = collect_nginx_sources(
        nginx_path,
        warnings,
        extra_include_globs=args.extra_include_glob
    )

    if not parsed:
        print("ERROR: No nginx config files could be parsed.", file=sys.stderr)
        return 1

    servers, upstreams = extract_nginx_objects(parsed, warnings)
    sites = merge_servers_to_sites(servers, warnings) if servers else []

    vhost_texts: Dict[str, str] = {}
    php_apps: Dict[str, PhpApp] = {}
    proxy_apps: Dict[str, ProxyApp] = {}

    for site in sites:
        vh_text, site_php_apps, site_proxy_apps = render_site_vhconf(
            site=site,
            upstreams=upstreams,
            warnings=warnings,
            enable_htaccess=enable_htaccess,
        )
        vhost_texts[site.vhost_name] = vh_text
        php_apps.update(site_php_apps)
        proxy_apps.update(site_proxy_apps)

    orig_httpd = read_text_file(ols_httpd) if ols_httpd.exists() else "# Auto-created preview baseline for OpenLiteSpeed\n"

    patched_httpd, listener_maps, site_listeners = patch_httpd_config(
        orig_httpd=orig_httpd,
        sites=sites,
        php_apps=php_apps,
        proxy_apps=proxy_apps,
        ols_vhosts_root=ols_vhosts_root,
        warnings=warnings,
    )

    write_preview_output(
        output_dir=output_dir,
        patched_httpd=patched_httpd,
        vhost_texts=vhost_texts,
        warnings=warnings,
        sites=sites,
        site_listeners=site_listeners,
        listener_maps=listener_maps,
    )

    print(f"Preview written to: {output_dir}")
    print(f"  - {output_dir / 'httpd_config.patched.conf'}")
    print(f"  - {output_dir / 'vhosts'}")
    print(f"  - {output_dir / 'warnings.json'}")
    print(f"  - {output_dir / 'migration_report.txt'}")

    if args.apply:
        actions = apply_to_real_ols(
            patched_httpd=patched_httpd,
            vhost_texts=vhost_texts,
            ols_httpd=ols_httpd,
            ols_vhosts_root=ols_vhosts_root,
            warnings=warnings,
        )
        print("")
        print("Applied changes:")
        for a in actions:
            print(f"  - {a}")
        print("")
        print("Restart/reload OpenLiteSpeed after review.")
        print("Example: sudo /usr/local/lsws/bin/lswsctrl restart")
    else:
        print("")
        print("Preview only. No real OLS files were changed.")
        print("Use --apply to write to the real OLS paths.")

    print("")
    print(f"autoLoadHtaccess default: {'YES' if enable_htaccess else 'NO'}")
    print(f"Parsed nginx files: {len(parsed)}")
    print(f"Generated sites: {len(sites)}")
    print(f"Warnings: {len(warnings)}")

    return 0

if __name__ == "__main__":
    sys.exit(main())