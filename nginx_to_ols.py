#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

MANAGED_BEGIN = "# BEGIN NGINX_TO_OLS MANAGED"
MANAGED_END = "# END NGINX_TO_OLS MANAGED"
MAPS_BEGIN = "# BEGIN NGINX_TO_OLS MAPS"
MAPS_END = "# END NGINX_TO_OLS MAPS"

# ============================================================
# Models
# ============================================================

@dataclass
class Token:
    value: str
    line: int

@dataclass
class Directive:
    name: str
    args: List[str]
    file: str
    line: int

@dataclass
class Block:
    name: str
    args: List[str]
    children: List[Union["Directive", "Block"]]
    file: str
    line: int

Node = Union[Directive, Block]

@dataclass
class Listen:
    raw: str
    port: int
    address: str = "*"
    ssl: bool = False

@dataclass
class Upstream:
    name: str
    servers: List[str] = field(default_factory=list)
    keepalive: Optional[int] = None
    file: str = ""
    line: int = 0

@dataclass
class LocationData:
    modifier: str = ""
    pattern: str = "/"
    file: str = ""
    line: int = 0

    root: Optional[str] = None
    alias: Optional[str] = None
    proxy_pass: Optional[str] = None
    fastcgi_pass: Optional[str] = None
    try_files: Optional[List[str]] = None
    rewrites: List[List[str]] = field(default_factory=list)
    returns: List[List[str]] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)

    expires: Optional[str] = None
    deny_all: bool = False
    websocket: bool = False

@dataclass
class ServerData:
    file: str = ""
    line: int = 0
    names: List[str] = field(default_factory=list)
    listens: List[Listen] = field(default_factory=list)
    root: Optional[str] = None
    index_files: List[str] = field(default_factory=list)
    ssl_certificate: Optional[str] = None
    ssl_certificate_key: Optional[str] = None

    rewrites: List[List[str]] = field(default_factory=list)
    returns: List[List[str]] = field(default_factory=list)
    locations: List[LocationData] = field(default_factory=list)

    php_apps: List[str] = field(default_factory=list)
    ols_vhost_name: Optional[str] = None

@dataclass
class OLSBlock:
    kind: str
    name: str
    start: int
    end: int
    text: str

@dataclass
class OLSListenerMeta:
    name: str
    port: int
    secure: bool
    block: OLSBlock
    existing_maps: List[Tuple[str, str]] = field(default_factory=list)

# ============================================================
# Warning helpers
# ============================================================

def add_warning(warnings: List[dict], file: str, line: int, directive: str, message: str, context: str = "") -> None:
    warnings.append({
        "file": file,
        "line": line,
        "directive": directive,
        "message": message,
        "context": context,
    })

# ============================================================
# Generic helpers
# ============================================================

def uniq(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def sanitize_name(value: str) -> str:
    value = value.strip() or "unnamed"
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value.strip("._") or "unnamed"

def ensure_trailing_slash(path_str: str) -> str:
    if not path_str.endswith("/"):
        return path_str + "/"
    return path_str

def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def strip_managed_section(text: str) -> str:
    pattern = re.compile(
        re.escape(MANAGED_BEGIN) + r".*?" + re.escape(MANAGED_END) + r"\n?",
        re.S
    )
    return pattern.sub("", text).rstrip() + "\n"

def primary_server_name(server: ServerData, idx: int) -> str:
    if server.names:
        return sanitize_name(server.names[0])
    if server.listens:
        return f"unnamed_{idx}_{server.listens[0].port}"
    return f"unnamed_{idx}"

def nginx_prefix_from_input(input_path: Path) -> Path:
    return input_path if input_path.is_dir() else input_path.parent

def render_flags(flags: List[str]) -> str:
    return "[" + ",".join(flags) + "]"

def apacheize_pattern(pattern: str) -> str:
    p = pattern.strip()
    if p.startswith("^/"):
        return "^" + p[2:]
    if p.startswith("/"):
        return "^" + re.escape(p.lstrip("/")) + "$"
    return p

def convert_nginx_target(target: str) -> Tuple[str, bool]:
    add_qsa = False
    t = target

    if "?$query_string" in t:
        t = t.replace("?$query_string", "")
        add_qsa = True

    t = t.replace("$request_uri", "$1")
    t = t.replace("$uri", "$1")
    t = t.replace("$host", "%{HTTP_HOST}")
    t = t.replace("$scheme", "%{REQUEST_SCHEME}")

    return t, add_qsa

def rewrite_flags_from_nginx(flag: Optional[str], add_qsa: bool = False) -> str:
    flags = []
    f = (flag or "").lower()

    if f == "permanent":
        flags = ["R=301", "L"]
    elif f == "redirect":
        flags = ["R=302", "L"]
    elif f in ("last", "break", ""):
        flags = ["L"]
    else:
        flags = ["L"]

    if add_qsa:
        flags.append("QSA")
    return render_flags(flags)

def infer_lsphp_app(fastcgi_pass: str) -> str:
    m = re.search(r"php(\d+)\.(\d+)-fpm", fastcgi_pass)
    if m:
        return f"lsphp{m.group(1)}{m.group(2)}"

    m = re.search(r"php(\d{2,3})-fpm", fastcgi_pass)
    if m:
        return f"lsphp{m.group(1)}"

    return "lsphp"

def filter_map_domains(names: List[str]) -> List[str]:
    out = []
    saw_wild = False

    for name in names:
        n = name.strip()
        if not n:
            continue
        if n == "_" or n == "default_server":
            saw_wild = True
            continue
        out.append(n)

    out = uniq(out)
    if not out:
        return ["*"]
    if saw_wild and "*" not in out:
        return ["*"] + out
    return out

def listener_is_secure(server: ServerData, listen: Listen) -> bool:
    if listen.ssl:
        return True
    if listen.port in (443, 8443) and server.ssl_certificate and server.ssl_certificate_key:
        return True
    return False

def parse_listen_args(args: List[str]) -> Optional[Listen]:
    if not args:
        return None

    ssl = any(a.lower() == "ssl" for a in args)
    first = args[0]

    address = "*"
    port = None

    if first.isdigit():
        port = int(first)
    elif first.startswith("[") and "]:" in first:
        address, p = first.rsplit(":", 1)
        if p.isdigit():
            port = int(p)
    elif ":" in first:
        address, p = first.rsplit(":", 1)
        if p.isdigit():
            port = int(p)

    if port is None:
        return None

    return Listen(raw=" ".join(args), port=port, address=address, ssl=ssl)

def path_to_rule_pattern(location: LocationData) -> Optional[str]:
    if not location.pattern:
        return None

    if location.modifier == "=":
        p = location.pattern.lstrip("/")
        return "^/" + re.escape(p) + "/?$"

    if location.modifier in ("", "^~") and location.pattern.startswith("/"):
        p = location.pattern.lstrip("/")
        if not p:
            return "^/"
        return "^/" + re.escape(p)

    if location.modifier in ("~", "~*"):
        return location.pattern

    return None

# ============================================================
# Nginx tokenizer/parser
# ============================================================

def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    buf = []
    buf_line = 1
    line = 1
    i = 0
    n = len(text)

    def flush():
        nonlocal buf, buf_line
        if buf:
            tokens.append(Token("".join(buf), buf_line))
            buf = []

    while i < n:
        c = text[i]

        if c == "#":
            flush()
            while i < n and text[i] != "\n":
                i += 1
            continue

        if c in ("'", '"'):
            flush()
            quote = c
            start_line = line
            i += 1
            qbuf = []
            while i < n:
                ch = text[i]
                if ch == "\\" and i + 1 < n:
                    qbuf.append(text[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    i += 1
                    break
                if ch == "\n":
                    line += 1
                qbuf.append(ch)
                i += 1
            tokens.append(Token("".join(qbuf), start_line))
            continue

        if c in "{};":
            flush()
            tokens.append(Token(c, line))
            i += 1
            continue

        if c.isspace():
            flush()
            if c == "\n":
                line += 1
            i += 1
            continue

        if not buf:
            buf_line = line
        buf.append(c)
        i += 1

    flush()
    return tokens

def parse_nodes(tokens: List[Token], start: int = 0, source_file: str = "") -> Tuple[List[Node], int]:
    nodes: List[Node] = []
    i = start

    while i < len(tokens):
        if tokens[i].value == "}":
            return nodes, i

        if tokens[i].value in ("{", ";"):
            i += 1
            continue

        parts = []
        line = tokens[i].line
        while i < len(tokens) and tokens[i].value not in ("{", "}", ";"):
            parts.append(tokens[i])
            i += 1

        if not parts:
            continue

        name = parts[0].value
        args = [p.value for p in parts[1:]]

        if i >= len(tokens):
            raise ValueError(f"Unexpected EOF near '{name}' in {source_file}:{line}")

        if tokens[i].value == ";":
            nodes.append(Directive(name=name, args=args, file=source_file, line=line))
            i += 1
            continue

        if tokens[i].value == "{":
            i += 1
            children, i = parse_nodes(tokens, i, source_file)
            if i >= len(tokens) or tokens[i].value != "}":
                raise ValueError(f"Missing closing brace for '{name}' in {source_file}:{line}")
            nodes.append(Block(name=name, args=args, children=children, file=source_file, line=line))
            i += 1
            continue

    return nodes, i

def resolve_include_patterns(include_arg: str, current_file: Path, prefix_dir: Path) -> List[Path]:
    candidates = []
    inc_path = Path(include_arg)

    if inc_path.is_absolute():
        candidates.append(str(inc_path))
    else:
        candidates.append(str((current_file.parent / include_arg).resolve()))
        candidates.append(str((prefix_dir / include_arg).resolve()))

    seen = set()
    out = []
    for pattern in candidates:
        for m in sorted(glob.glob(pattern)):
            rp = str(Path(m).resolve())
            if rp not in seen:
                seen.add(rp)
                out.append(Path(rp))
    return out

def expand_includes(nodes: List[Node], prefix_dir: Path, warnings: List[dict], stack: List[Path]) -> List[Node]:
    expanded: List[Node] = []

    for node in nodes:
        if isinstance(node, Directive) and node.name == "include" and node.args:
            current_file = Path(node.file)
            all_matches = []
            for arg in node.args:
                all_matches.extend(resolve_include_patterns(arg, current_file, prefix_dir))

            if not all_matches:
                add_warning(warnings, node.file, node.line, "include", f"Included file not found: {' '.join(node.args)}")
                continue

            for inc in all_matches:
                if inc in stack:
                    add_warning(warnings, node.file, node.line, "include", f"Include cycle detected: {inc}")
                    continue
                expanded.extend(parse_file(inc, prefix_dir, warnings, stack + [inc]))
            continue

        if isinstance(node, Block):
            node.children = expand_includes(node.children, prefix_dir, warnings, stack)
            expanded.append(node)
        else:
            expanded.append(node)

    return expanded

def parse_file(path: Path, prefix_dir: Path, warnings: List[dict], stack: Optional[List[Path]] = None) -> List[Node]:
    stack = stack or [path]

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        add_warning(warnings, str(path), 0, "read", f"Failed to read file: {e}")
        return []

    try:
        tokens = tokenize(text)
        nodes, _ = parse_nodes(tokens, 0, str(path))
        return expand_includes(nodes, prefix_dir, warnings, stack)
    except Exception as e:
        add_warning(warnings, str(path), 0, "parse", f"Failed to parse file: {e}")
        return []

def find_http_children(nodes: List[Node]) -> List[Node]:
    http_children = []
    for node in nodes:
        if isinstance(node, Block) and node.name == "http":
            http_children.extend(node.children)
    return http_children if http_children else nodes

# ============================================================
# Nginx extraction
# ============================================================

def extract_upstreams(nodes: List[Node]) -> Dict[str, Upstream]:
    upstreams: Dict[str, Upstream] = {}

    for node in nodes:
        if isinstance(node, Block) and node.name == "upstream" and node.args:
            up = Upstream(name=node.args[0], file=node.file, line=node.line)
            for child in node.children:
                if isinstance(child, Directive):
                    if child.name == "server" and child.args:
                        up.servers.append(child.args[0])
                    elif child.name == "keepalive" and child.args:
                        try:
                            up.keepalive = int(child.args[0])
                        except Exception:
                            pass
            upstreams[up.name] = up

    return upstreams

def parse_location(block: Block, warnings: List[dict]) -> LocationData:
    loc = LocationData(file=block.file, line=block.line)

    if block.args:
        if len(block.args) >= 2 and block.args[0] in ("=", "~", "~*", "^~"):
            loc.modifier = block.args[0]
            loc.pattern = block.args[1]
        else:
            loc.pattern = block.args[0]

    for child in block.children:
        if isinstance(child, Directive):
            if child.name == "root" and child.args:
                loc.root = child.args[0]
            elif child.name == "alias" and child.args:
                loc.alias = child.args[0]
            elif child.name == "proxy_pass" and child.args:
                loc.proxy_pass = child.args[0]
            elif child.name == "fastcgi_pass" and child.args:
                loc.fastcgi_pass = child.args[0]
            elif child.name == "try_files" and child.args:
                loc.try_files = child.args
            elif child.name == "rewrite":
                loc.rewrites.append(child.args)
            elif child.name == "return":
                loc.returns.append(child.args)
            elif child.name == "include" and child.args:
                loc.includes.extend(child.args)
            elif child.name == "expires" and child.args:
                loc.expires = " ".join(child.args)
            elif child.name == "deny" and child.args and child.args[0] == "all":
                loc.deny_all = True
            elif child.name == "proxy_set_header" and len(child.args) >= 2:
                hname = child.args[0].lower()
                hval = " ".join(child.args[1:]).lower()
                if hname == "upgrade" or "upgrade" in hval:
                    loc.websocket = True
        elif isinstance(child, Block):
            if child.name == "if":
                add_warning(warnings, child.file, child.line, "if", "Nginx 'if' inside location requires manual review.", context=f"location {loc.pattern}")
            elif child.name == "location":
                add_warning(warnings, child.file, child.line, "location", "Nested location detected; manual review required.", context=f"location {loc.pattern}")

    return loc

def extract_servers(nodes: List[Node], warnings: List[dict]) -> List[ServerData]:
    servers: List[ServerData] = []

    for node in nodes:
        if not (isinstance(node, Block) and node.name == "server"):
            continue

        srv = ServerData(file=node.file, line=node.line)

        for child in node.children:
            if isinstance(child, Directive):
                if child.name == "listen":
                    parsed = parse_listen_args(child.args)
                    if parsed:
                        srv.listens.append(parsed)
                elif child.name == "server_name":
                    srv.names.extend(child.args)
                elif child.name == "root" and child.args:
                    srv.root = child.args[0]
                elif child.name == "index":
                    srv.index_files.extend(child.args)
                elif child.name == "ssl_certificate" and child.args:
                    srv.ssl_certificate = child.args[0]
                elif child.name == "ssl_certificate_key" and child.args:
                    srv.ssl_certificate_key = child.args[0]
                elif child.name == "rewrite":
                    srv.rewrites.append(child.args)
                elif child.name == "return":
                    srv.returns.append(child.args)
            elif isinstance(child, Block):
                if child.name == "location":
                    loc = parse_location(child, warnings)
                    srv.locations.append(loc)
                    if loc.fastcgi_pass and (
                        r"\.php" in loc.pattern
                        or "fastcgi-php.conf" in " ".join(loc.includes)
                        or "php" in loc.pattern.lower()
                    ):
                        srv.php_apps.append(infer_lsphp_app(loc.fastcgi_pass))
                elif child.name == "if":
                    add_warning(warnings, child.file, child.line, "if", "Nginx 'if' inside server requires manual review.", context="server " + " ".join(srv.names))

        srv.names = uniq(srv.names)
        srv.index_files = uniq(srv.index_files)
        srv.php_apps = uniq(srv.php_apps)

        seen = set()
        dedup = []
        for l in srv.listens:
            key = (l.port, l.address, l.ssl)
            if key not in seen:
                seen.add(key)
                dedup.append(l)
        srv.listens = dedup

        servers.append(srv)

    return servers

# ============================================================
# OLS block parsing
# ============================================================

def find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(text)

    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    raise ValueError("Unmatched brace in OLS config")

def parse_ols_top_blocks(text: str) -> List[OLSBlock]:
    pattern = re.compile(r"(?m)^[ \t]*(listener|virtualhost|extprocessor)\s+([^\s{]+)\s*\{")
    blocks: List[OLSBlock] = []

    pos = 0
    while True:
        m = pattern.search(text, pos)
        if not m:
            break

        kind = m.group(1)
        name = m.group(2)
        open_idx = text.find("{", m.start())
        close_idx = find_matching_brace(text, open_idx)
        end = close_idx + 1

        # include trailing newline
        while end < len(text) and text[end] in "\r\n":
            end += 1

        blocks.append(OLSBlock(kind=kind, name=name, start=m.start(), end=end, text=text[m.start():end]))
        pos = end

    return blocks

def parse_listener_meta(block: OLSBlock) -> Optional[OLSListenerMeta]:
    if block.kind != "listener":
        return None

    port = None
    secure = False
    existing_maps: List[Tuple[str, str]] = []

    m = re.search(r"(?m)^\s*address\s+\S*:(\d+)\s*$", block.text)
    if m:
        port = int(m.group(1))

    m = re.search(r"(?m)^\s*secure\s+([01])\s*$", block.text)
    if m:
        secure = (m.group(1) == "1")

    for mm in re.finditer(r"(?m)^\s*map\s+([^\s]+)\s+(.+?)\s*$", block.text):
        existing_maps.append((mm.group(1).strip(), mm.group(2).strip()))

    if port is None:
        return None

    return OLSListenerMeta(
        name=block.name,
        port=port,
        secure=secure,
        block=block,
        existing_maps=existing_maps
    )

# ============================================================
# Naming / planning
# ============================================================

def make_unique_name(base: str, used: set) -> str:
    name = base
    i = 1
    while name in used:
        i += 1
        name = f"{base}-migrated{i}"
    used.add(name)
    return name

def assign_vhost_names(servers: List[ServerData], existing_vhost_names: set) -> None:
    used = set(existing_vhost_names)
    for idx, server in enumerate(servers, start=1):
        base = primary_server_name(server, idx)
        server.ols_vhost_name = make_unique_name(base, used)

def map_domains_for_server(server: ServerData) -> List[str]:
    return filter_map_domains(server.names)

def listen_groups_for_servers(servers: List[ServerData]) -> Dict[Tuple[int, bool], List[ServerData]]:
    groups: Dict[Tuple[int, bool], List[ServerData]] = {}

    for srv in servers:
        listens = srv.listens or [Listen(raw="80", port=80, address="*", ssl=False)]
        for l in listens:
            secure = listener_is_secure(srv, l)
            key = (l.port, secure)
            groups.setdefault(key, []).append(srv)

    return groups

# ============================================================
# Upstream / proxy helpers
# ============================================================

def resolve_proxy_backend(proxy_pass: str, upstreams: Dict[str, Upstream], warnings: List[dict], file: str, line: int) -> Optional[str]:
    target = proxy_pass.strip()

    if target.startswith("http://") or target.startswith("https://"):
        body = target.split("://", 1)[1].rstrip("/")

        if "/" in body:
            body = body.split("/", 1)[0]

        if body in upstreams:
            up = upstreams[body]
            if not up.servers:
                add_warning(warnings, file, line, "proxy_pass", f"Upstream '{body}' has no servers.")
                return None
            if len(up.servers) > 1:
                add_warning(warnings, file, line, "upstream", f"Upstream '{body}' has multiple backends; using first only.", context=", ".join(up.servers))
            return up.servers[0]

        return body

    if target.startswith("unix:"):
        add_warning(warnings, file, line, "proxy_pass", "unix socket proxy_pass requires manual review.")
        return None

    return target

# ============================================================
# Rewrite generation
# ============================================================

def build_try_files_rules(loc: LocationData, warnings: List[dict]) -> List[str]:
    rules = []
    tf = loc.try_files
    if not tf:
        return rules

    if len(tf) >= 3 and tf[0] == "$uri" and tf[1] == "$uri/":
        fallback = tf[-1]
        rules.append("RewriteCond %{REQUEST_FILENAME} !-f")
        rules.append("RewriteCond %{REQUEST_FILENAME} !-d")

        if fallback == "=404":
            rules.append("RewriteRule ^ - [R=404,L]")
            return rules

        if fallback == "/index.php?$query_string":
            rules.append("RewriteRule ^(.*)$ /index.php [QSA,L]")
            return rules

        if fallback == "/index.html":
            rules.append("RewriteRule ^(.*)$ /index.html [L]")
            return rules

        target, add_qsa = convert_nginx_target(fallback)
        rules.append(f"RewriteRule ^(.*)$ {target} {rewrite_flags_from_nginx('last', add_qsa)}")
        return rules

    add_warning(warnings, loc.file, loc.line, "try_files", "Unsupported try_files pattern; manual review required.", context=f"location {loc.pattern}")
    return rules

def build_rewrite_rules(server: ServerData, warnings: List[dict]) -> List[str]:
    rules: List[str] = []

    for rw in server.rewrites:
        if len(rw) >= 2:
            pattern = apacheize_pattern(rw[0])
            target, add_qsa = convert_nginx_target(rw[1])
            flag = rw[2] if len(rw) >= 3 else "last"
            rules.append(f"RewriteRule {pattern} {target} {rewrite_flags_from_nginx(flag, add_qsa)}")

    for ret in server.returns:
        if len(ret) >= 2 and ret[0].isdigit():
            status = ret[0]
            target = ret[1]
            if status in ("301", "302", "307", "308"):
                t, add_qsa = convert_nginx_target(target)
                flags = [f"R={status}", "L"]
                if add_qsa:
                    flags.append("QSA")
                rules.append(f"RewriteRule ^(.*)$ {t} {render_flags(flags)}")
            else:
                add_warning(warnings, server.file, server.line, "return", f"Non-redirect return requires manual review: {' '.join(ret)}")
        else:
            add_warning(warnings, server.file, server.line, "return", f"Unsupported return directive: {' '.join(ret)}")

    for loc in server.locations:
        if loc.deny_all and loc.modifier in ("~", "~*") and ("\\." in loc.pattern or "/\\." in loc.pattern):
            rules.append("RewriteRule (^|/)\\. - [F,L]")

        if (loc.pattern == "/" and loc.modifier in ("", "^~")) and loc.try_files:
            rules.extend(build_try_files_rules(loc, warnings))

        for rw in loc.rewrites:
            if len(rw) < 2:
                continue
            path_rule = path_to_rule_pattern(loc)
            if not path_rule:
                add_warning(warnings, loc.file, loc.line, "rewrite", "Location rewrite could not be translated automatically.", context=f"location {loc.pattern}")
                continue
            target, add_qsa = convert_nginx_target(rw[1])
            flag = rw[2] if len(rw) >= 3 else "last"
            rules.append(f"RewriteCond %{{REQUEST_URI}} {path_rule}")
            rules.append(f"RewriteRule {apacheize_pattern(rw[0])} {target} {rewrite_flags_from_nginx(flag, add_qsa)}")

        for ret in loc.returns:
            if len(ret) >= 2 and ret[0].isdigit():
                status = ret[0]
                target = ret[1]
                if status in ("301", "302", "307", "308"):
                    path_rule = path_to_rule_pattern(loc)
                    if path_rule:
                        t, add_qsa = convert_nginx_target(target)
                        flags = [f"R={status}", "L"]
                        if add_qsa:
                            flags.append("QSA")
                        rules.append(f"RewriteCond %{{REQUEST_URI}} {path_rule}")
                        rules.append(f"RewriteRule ^(.*)$ {t} {render_flags(flags)}")
                    else:
                        add_warning(warnings, loc.file, loc.line, "return", "Location return could not be translated automatically.", context=f"location {loc.pattern}")
                else:
                    add_warning(warnings, loc.file, loc.line, "return", f"Non-redirect location return requires manual review: {' '.join(ret)}", context=f"location {loc.pattern}")

    return uniq(rules)

# ============================================================
# VHost config rendering
# ============================================================

def build_proxy_blocks(server: ServerData, upstreams: Dict[str, Upstream], warnings: List[dict]) -> Tuple[List[str], List[str]]:
    ext_lines: List[str] = []
    ctx_lines: List[str] = []

    count = 0
    for loc in server.locations:
        if not loc.proxy_pass:
            continue

        if loc.modifier not in ("", "^~", "="):
            add_warning(warnings, loc.file, loc.line, "proxy_pass", "Regex-based proxy location requires manual review.", context=f"location {loc.pattern}")
            continue

        backend = resolve_proxy_backend(loc.proxy_pass, upstreams, warnings, loc.file, loc.line)
        if not backend:
            continue

        count += 1
        handler = f"proxy_{sanitize_name(server.ols_vhost_name or 'site')}_{count}"

        ext_lines.extend([
            f"extprocessor {handler} {{",
            f"type                    webserver",
            f"address                 {backend}",
            f"maxConns                100",
            f"initTimeout             60",
            f"retryTimeout            0",
            f"respBuffer              0",
            f"}}",
            ""
        ])

        path = loc.pattern if loc.pattern else "/"
        ctx_lines.extend([
            f"context {path} {{",
            f"type                    proxy",
            f"handler                 {handler}",
            f"addDefaultCharset       off",
            f"}}",
            ""
        ])

        if loc.websocket:
            add_warning(warnings, loc.file, loc.line, "websocket", "WebSocket proxy detected; verify behavior manually.", context=f"location {loc.pattern}")

    return ext_lines, ctx_lines

def build_alias_contexts(server: ServerData, warnings: List[dict]) -> List[str]:
    lines: List[str] = []

    for loc in server.locations:
        if not loc.alias:
            continue

        if loc.modifier not in ("", "^~", "=") or not loc.pattern.startswith("/"):
            add_warning(warnings, loc.file, loc.line, "alias", "Regex alias requires manual review.", context=f"location {loc.pattern}")
            continue

        lines.extend([
            f"context {loc.pattern} {{",
            f"location                {loc.alias}",
            f"allowBrowse             1",
            f"addDefaultCharset       off",
            f"}}",
            ""
        ])
        add_warning(warnings, loc.file, loc.line, "alias", "Alias converted to context; verify path behavior manually.", context=f"{loc.pattern} -> {loc.alias}")

    return lines

def render_vhconf(server: ServerData, upstreams: Dict[str, Upstream], warnings: List[dict]) -> str:
    root = ensure_trailing_slash(server.root or f"/var/www/{sanitize_name(server.ols_vhost_name or 'site')}")
    index_files = server.index_files or ["index.php", "index.html"]
    php_app = server.php_apps[0] if server.php_apps else None

    if len(server.php_apps) > 1:
        add_warning(warnings, server.file, server.line, "fastcgi_pass", f"Multiple PHP apps found ({', '.join(server.php_apps)}); using first only.", context=server.ols_vhost_name or "")

    rewrite_rules = build_rewrite_rules(server, warnings)
    proxy_ext, proxy_ctx = build_proxy_blocks(server, upstreams, warnings)
    alias_ctx = build_alias_contexts(server, warnings)

    lines = [
        f"docRoot                 {root}",
        "",
        "accesslog  {",
        "useServer               1",
        "}",
        "",
        "index  {",
        "useServer               0",
        f"indexFiles              {' '.join(index_files)}",
        "}",
        ""
    ]

    if php_app:
        lines.extend([
            "scripthandler  {",
            f"add                     lsapi:{php_app} php",
            "}",
            ""
        ])

    if proxy_ext:
        lines.extend(proxy_ext)

    if proxy_ctx:
        lines.extend(proxy_ctx)

    if alias_ctx:
        lines.extend(alias_ctx)

    if rewrite_rules:
        lines.extend([
            "rewrite  {",
            "enable                  1",
            "autoLoadHtaccess        0",
            "rules                   <<<END_rules",
        ])
        lines.extend(rewrite_rules)
        lines.extend([
            "END_rules",
            "}",
            ""
        ])
    else:
        lines.extend([
            "rewrite  {",
            "enable                  0",
            "autoLoadHtaccess        0",
            "}",
            ""
        ])

    if server.ssl_certificate and server.ssl_certificate_key:
        lines.extend([
            "vhssl  {",
            f"keyFile                 {server.ssl_certificate_key}",
            f"certFile                {server.ssl_certificate}",
            "certChain               1",
            "}",
            ""
        ])

    lines.extend([
        "module cache {",
        "storagePath             $VH_ROOT/lscache",
        "}",
        ""
    ])

    # Comments for manual review
    lines.append(f"# Source nginx: {server.file}:{server.line}")
    for loc in server.locations:
        if loc.fastcgi_pass:
            lines.append(f"# Detected PHP location: {loc.pattern} -> {loc.fastcgi_pass}")
        if loc.expires:
            lines.append(f"# NOTE: nginx expires '{loc.expires}' found in location {loc.pattern}; verify manually.")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"

# ============================================================
# Global OLS rendering
# ============================================================

def render_extprocessor_block(app_name: str) -> str:
    path = f"{app_name}/bin/lsphp"
    socket = f"uds://tmp/lshttpd/{app_name}.sock"
    return "\n".join([
        f"extprocessor {app_name} {{",
        f"type                    lsapi",
        f"address                 {socket}",
        f"maxConns                20",
        f"env                     PHP_LSAPI_CHILDREN=20",
        f"env                     LSAPI_AVOID_FORK=200M",
        f"initTimeout             60",
        f"retryTimeout            0",
        f"persistConn             1",
        f"respBuffer              0",
        f"autoStart               2",
        f"path                    {path}",
        f"backlog                 100",
        f"instances               1",
        f"priority                0",
        f"memSoftLimit            0",
        f"memHardLimit            0",
        f"procSoftLimit           1400",
        f"procHardLimit           1500",
        f"}}",
        ""
    ])

def render_virtualhost_block(server: ServerData, ols_vhosts_root: Path) -> str:
    vh_root = server.root or f"/var/www/{sanitize_name(server.ols_vhost_name or 'site')}"
    config_path = str((ols_vhosts_root / (server.ols_vhost_name or "site") / "vhconf.conf").resolve())

    return "\n".join([
        f"virtualhost {server.ols_vhost_name} {{",
        f"vhRoot                  {vh_root}",
        f"configFile              {config_path}",
        f"allowSymbolLink         1",
        f"enableScript            1",
        f"restrained              1",
        f"setUIDMode              0",
        f"}}",
        ""
    ])

def render_map_line(vhost_name: str, domains: List[str]) -> str:
    return f"map                     {vhost_name} {', '.join(domains)}"

def render_listener_block(
    name: str,
    port: int,
    secure: bool,
    mapping_lines: List[str],
    bootstrap_cert: Optional[str] = None,
    bootstrap_key: Optional[str] = None
) -> str:
    lines = [
        f"listener {name} {{",
        f"address                 *:{port}",
        f"secure                  {1 if secure else 0}",
    ]

    if secure:
        if bootstrap_key:
            lines.append(f"keyFile                 {bootstrap_key}")
        if bootstrap_cert:
            lines.append(f"certFile                {bootstrap_cert}")

    lines.extend(mapping_lines)
    lines.extend(["}", ""])
    return "\n".join(lines)

def replace_or_insert_maps_in_listener(block_text: str, map_lines: List[str]) -> str:
    map_body = "\n".join([MAPS_BEGIN] + map_lines + [MAPS_END]) + "\n"

    pattern = re.compile(re.escape(MAPS_BEGIN) + r".*?" + re.escape(MAPS_END) + r"\n?", re.S)
    if pattern.search(block_text):
        return pattern.sub(map_body, block_text)

    idx = block_text.rfind("}")
    if idx == -1:
        return block_text

    before = block_text[:idx].rstrip() + "\n"
    after = block_text[idx:]
    return before + map_body + after

# ============================================================
# Planning against existing OLS
# ============================================================

def build_existing_ols_maps(httpd_base_text: str) -> Tuple[Dict[Tuple[int, bool], List[OLSListenerMeta]], set, set]:
    listener_map: Dict[Tuple[int, bool], List[OLSListenerMeta]] = {}
    existing_vhosts = set()
    existing_ext = set()

    for block in parse_ols_top_blocks(httpd_base_text):
        if block.kind == "virtualhost":
            existing_vhosts.add(block.name)
        elif block.kind == "extprocessor":
            existing_ext.add(block.name)
        elif block.kind == "listener":
            meta = parse_listener_meta(block)
            if meta:
                listener_map.setdefault((meta.port, meta.secure), []).append(meta)

    return listener_map, existing_vhosts, existing_ext

def plan_listener_mappings(
    servers: List[ServerData],
    existing_listener_map: Dict[Tuple[int, bool], List[OLSListenerMeta]],
    warnings: List[dict]
) -> Tuple[Dict[str, List[str]], Dict[Tuple[int, bool], List[str]], Dict[Tuple[int, bool], Tuple[Optional[str], Optional[str]]]]:
    """
    Returns:
      existing_listener_updates: listener_name -> [map lines]
      new_listener_groups: (port, secure) -> [map lines]
      new_listener_ssl_bootstrap: (port, secure) -> (cert, key)
    """
    existing_updates: Dict[str, List[str]] = {}
    new_groups: Dict[Tuple[int, bool], List[str]] = {}
    ssl_bootstrap: Dict[Tuple[int, bool], Tuple[Optional[str], Optional[str]]] = {}

    by_group = listen_groups_for_servers(servers)

    for key, group_servers in by_group.items():
        port, secure = key
        mapping_lines = []
        ssl_refs = []

        for srv in group_servers:
            domains = map_domains_for_server(srv)
            mapping_lines.append(render_map_line(srv.ols_vhost_name or "site", domains))
            if secure and srv.ssl_certificate and srv.ssl_certificate_key:
                ssl_refs.append((srv.ssl_certificate, srv.ssl_certificate_key))

        mapping_lines = uniq(mapping_lines)

        existing_listeners = existing_listener_map.get(key, [])
        if existing_listeners:
            if len(existing_listeners) > 1:
                add_warning(
                    warnings, "httpd_config.conf", 0, "listener",
                    f"Multiple existing listeners found for port {port} secure={int(secure)}; using first only.",
                    context=", ".join([x.name for x in existing_listeners])
                )
            target_listener = existing_listeners[0]
            existing_updates[target_listener.name] = mapping_lines
        else:
            new_groups[key] = mapping_lines
            if secure:
                if ssl_refs:
                    first_cert, first_key = ssl_refs[0]
                    # warn if multiple different SSL certs exist on same secure listener
                    if len(set(ssl_refs)) > 1:
                        add_warning(
                            warnings, "httpd_config.conf", 0, "listener",
                            f"New secure listener on port {port} will use first cert/key as bootstrap; per-vhost vhssl will still be written.",
                            context=", ".join([f"{c}|{k}" for c, k in ssl_refs])
                        )
                    ssl_bootstrap[key] = (first_cert, first_key)
                else:
                    ssl_bootstrap[key] = (None, None)
                    add_warning(
                        warnings, "httpd_config.conf", 0, "listener",
                        f"New secure listener on port {port} has no bootstrap cert/key available; manual listener SSL setup required."
                    )

    return existing_updates, new_groups, ssl_bootstrap

def patch_existing_listeners(base_text: str, existing_listener_updates: Dict[str, List[str]]) -> str:
    blocks = parse_ols_top_blocks(base_text)
    replacements: List[Tuple[int, int, str]] = []

    for block in blocks:
        if block.kind != "listener":
            continue
        if block.name not in existing_listener_updates:
            continue

        new_block_text = replace_or_insert_maps_in_listener(block.text, existing_listener_updates[block.name])
        replacements.append((block.start, block.end, new_block_text))

    replacements.sort(key=lambda x: x[0], reverse=True)

    text = base_text
    for start, end, new_chunk in replacements:
        text = text[:start] + new_chunk + text[end:]

    return text

def render_managed_section(
    servers: List[ServerData],
    existing_extprocessors: set,
    new_listener_groups: Dict[Tuple[int, bool], List[str]],
    ssl_bootstrap: Dict[Tuple[int, bool], Tuple[Optional[str], Optional[str]]],
    ols_vhosts_root: Path
) -> str:
    lines = [MANAGED_BEGIN, ""]

    all_php_apps = []
    for srv in servers:
        all_php_apps.extend(srv.php_apps)
    for app in uniq(all_php_apps):
        if app not in existing_extprocessors:
            lines.append(render_extprocessor_block(app).rstrip())
            lines.append("")

    for srv in servers:
        lines.append(render_virtualhost_block(srv, ols_vhosts_root).rstrip())
        lines.append("")

    for (port, secure), map_lines in sorted(new_listener_groups.items(), key=lambda x: (x[0][0], x[0][1])):
        if secure:
            listener_name = f"nginx_migrated_ssl_{port}"
            cert, key = ssl_bootstrap.get((port, secure), (None, None))
            lines.append(render_listener_block(listener_name, port, True, map_lines, cert, key).rstrip())
            lines.append("")
        else:
            listener_name = f"nginx_migrated_{port}"
            lines.append(render_listener_block(listener_name, port, False, map_lines).rstrip())
            lines.append("")

    lines.append(MANAGED_END)
    lines.append("")
    return "\n".join(lines)

# ============================================================
# Reports
# ============================================================

def render_report(servers: List[ServerData], upstreams: Dict[str, Upstream], warnings: List[dict], output_dir: Path, preview_httpd: Path) -> str:
    lines = [
        "NGINX -> OPENLITESPEED MIGRATION REPORT",
        "=======================================",
        "",
        f"Servers found      : {len(servers)}",
        f"Upstreams found    : {len(upstreams)}",
        f"Warnings generated : {len(warnings)}",
        "",
        f"Patched httpd preview : {preview_httpd}",
        f"Generated vhconf dir  : {output_dir / 'vhosts'}",
        "",
        "Per-vhost summary",
        "-----------------",
        ""
    ]

    for srv in servers:
        ports = []
        for l in (srv.listens or [Listen(raw='80', port=80)]):
            ports.append(f"{l.port}{'/ssl' if listener_is_secure(srv, l) else ''}")

        lines.extend([
            f"- VHost name : {srv.ols_vhost_name}",
            f"  Domains    : {', '.join(srv.names) if srv.names else '*'}",
            f"  Ports      : {', '.join(uniq(ports))}",
            f"  Root       : {srv.root or '(not set)'}",
            f"  SSL        : {'yes' if srv.ssl_certificate and srv.ssl_certificate_key else 'no'}",
            f"  PHP app    : {', '.join(srv.php_apps) if srv.php_apps else '(none)'}",
            ""
        ])

    if warnings:
        lines.extend([
            "Important",
            "---------",
            "- Review warnings.json before apply.",
            "- Multi-backend upstreams are reduced to first backend only.",
            "- 'if' blocks are not auto-converted.",
            "- Regex proxy/alias locations may require manual work.",
            "- For new secure listeners, listener-level bootstrap cert/key may need manual adjustment.",
            ""
        ])

    return "\n".join(lines).rstrip() + "\n"

# ============================================================
# Main
# ============================================================

def backup_file(path: Path) -> Path:
    backup = path.with_name(path.name + ".bak.nginx-to-ols")
    shutil.copy2(path, backup)
    return backup

def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate nginx config to OpenLiteSpeed config for your OLS layout.")
    parser.add_argument("--nginx", required=True, help="Path to nginx.conf or nginx config directory")
    parser.add_argument("--ols-httpd", required=True, help="Path to /usr/local/lsws/conf/httpd_config.conf")
    parser.add_argument("--ols-vhosts-root", default="/usr/local/lsws/conf/vhosts", help="OLS vhosts root path")
    parser.add_argument("--output", required=True, help="Directory for preview files, reports, and generated vhconf files")
    parser.add_argument("--apply", action="store_true", help="Apply patched httpd_config.conf and copy vhconf files into OLS paths")
    args = parser.parse_args()

    nginx_input = Path(args.nginx).resolve()
    ols_httpd = Path(args.ols_httpd).resolve()
    ols_vhosts_root = Path(args.ols_vhosts_root).resolve()
    output_dir = Path(args.output).resolve()

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "vhosts").mkdir(parents=True, exist_ok=True)

    main_nginx_conf = nginx_input / "nginx.conf" if nginx_input.is_dir() else nginx_input
    if not main_nginx_conf.exists():
        print(f"ERROR: nginx input not found: {main_nginx_conf}", file=sys.stderr)
        return 2

    if not ols_httpd.exists():
        print(f"ERROR: OLS httpd config not found: {ols_httpd}", file=sys.stderr)
        return 2

    warnings: List[dict] = []

    # Parse nginx
    prefix_dir = nginx_prefix_from_input(main_nginx_conf)
    root_nodes = parse_file(main_nginx_conf, prefix_dir, warnings)
    http_nodes = find_http_children(root_nodes)
    upstreams = extract_upstreams(http_nodes)
    servers = extract_servers(http_nodes, warnings)

    if not servers:
        add_warning(warnings, str(main_nginx_conf), 0, "server", "No nginx server blocks found.")
        print("No nginx server blocks found.", file=sys.stderr)
        return 1

    # Parse existing OLS
    original_httpd_text = ols_httpd.read_text(encoding="utf-8")
    httpd_base_text = strip_managed_section(original_httpd_text)

    existing_listener_map, existing_vhost_names, existing_extprocessors = build_existing_ols_maps(httpd_base_text)
    assign_vhost_names(servers, existing_vhost_names)

    # Build listener map plan
    existing_listener_updates, new_listener_groups, ssl_bootstrap = plan_listener_mappings(
        servers, existing_listener_map, warnings
    )

    # Patch listeners in base text
    patched_base = patch_existing_listeners(httpd_base_text, existing_listener_updates)

    # Build managed section
    managed_section = render_managed_section(
        servers=servers,
        existing_extprocessors=existing_extprocessors,
        new_listener_groups=new_listener_groups,
        ssl_bootstrap=ssl_bootstrap,
        ols_vhosts_root=ols_vhosts_root
    )

    patched_httpd = patched_base.rstrip() + "\n\n" + managed_section

    # Write preview vhconf files
    for srv in servers:
        vhconf_text = render_vhconf(srv, upstreams, warnings)
        preview_vh_path = output_dir / "vhosts" / (srv.ols_vhost_name or "site") / "vhconf.conf"
        write_text(preview_vh_path, vhconf_text)

    # Write preview patched httpd
    preview_httpd = output_dir / "httpd_config.patched.conf"
    write_text(preview_httpd, patched_httpd)

    # Reports
    write_text(output_dir / "warnings.json", json.dumps(warnings, indent=2))
    report_text = render_report(servers, upstreams, warnings, output_dir, preview_httpd)
    write_text(output_dir / "migration_report.txt", report_text)

    # Apply if requested
    if args.apply:
        backup = backup_file(ols_httpd)
        ols_httpd.write_text(patched_httpd, encoding="utf-8")

        for srv in servers:
            src = output_dir / "vhosts" / (srv.ols_vhost_name or "site") / "vhconf.conf"
            dst = ols_vhosts_root / (srv.ols_vhost_name or "site") / "vhconf.conf"
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                backup_file(dst)
            shutil.copy2(src, dst)

        print(f"[APPLY] Backed up httpd_config.conf to: {backup}")
        print(f"[APPLY] Updated: {ols_httpd}")
        print(f"[APPLY] Copied vhost configs to: {ols_vhosts_root}")

    print(f"[DONE] Preview output: {output_dir}")
    print(f"[DONE] Preview patched httpd: {preview_httpd}")
    print(f"[DONE] Servers: {len(servers)}")
    print(f"[DONE] Upstreams: {len(upstreams)}")
    print(f"[DONE] Warnings: {len(warnings)}")

    return 0

if __name__ == "__main__":
    sys.exit(main())