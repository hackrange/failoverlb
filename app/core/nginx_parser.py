"""
Reading and writing real nginx config.

This exists so the GUI and the config file can both be the source of truth
without fighting each other.  You can edit a site in the forms, or you can open
the raw config and type directly, and either way the other side keeps up.

To do that we need to actually parse nginx config rather than run regexes over
it.  Regexes fall apart fast here.  Braces nest, strings can contain braces,
comments can contain anything, and a semicolon inside quotes does not end a
directive.  A tokenizer handles all of that and is not much more code.

What we get out is a tree of Directive objects.  Each one has a name, its
arguments, and possibly a block of children.  That maps cleanly onto how nginx
thinks about config, and it maps cleanly back onto our settings.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


class ParseError(Exception):
    """Config we could not read.  Carries the line number so the GUI can point at it."""

    def __init__(self, message, line=None):
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


# ==============================================================================
# The tree
# ==============================================================================

@dataclass
class Directive:
    name: str
    args: List[str] = field(default_factory=list)
    block: Optional[List["Directive"]] = None
    line: int = 0
    comment: str = ""

    # Comments that sat on their own lines just above this directive.  We hang
    # on to them so writing the file back out does not throw away somebody's
    # notes, which would make anybody stop trusting the editor pretty quickly.
    leading_comments: List[str] = field(default_factory=list)

    @property
    def is_block(self):
        return self.block is not None

    def arg_string(self):
        return " ".join(self.args)

    def find(self, name, recursive=False):
        """Every child directive with this name."""
        found = []
        if self.block:
            for child in self.block:
                if child.name == name:
                    found.append(child)
                if recursive and child.is_block:
                    found.extend(child.find(name, recursive=True))
        return found

    def find_one(self, name):
        hits = self.find(name)
        return hits[0] if hits else None

    def get_value(self, name, default=None):
        """The arguments of the first directive with this name, as one string."""
        d = self.find_one(name)
        return d.arg_string() if d else default


@dataclass
class Config:
    """A whole parsed config file."""

    directives: List[Directive] = field(default_factory=list)
    source: str = ""

    def find(self, name, recursive=False):
        found = []
        for d in self.directives:
            if d.name == name:
                found.append(d)
            if recursive and d.is_block:
                found.extend(d.find(name, recursive=True))
        return found

    def find_one(self, name):
        hits = self.find(name)
        return hits[0] if hits else None

    def server_blocks(self):
        """
        Every server block, wherever it is.

        The is_block check is doing real work here.  Inside an upstream block,
        "server" is a plain directive naming a backend, like
        "server 10.20.30.51:8080;".  Inside http it is a block that holds a
        whole site.  Same word, completely different thing.  Without this check
        a pool of three backends looks like three websites.
        """
        return [d for d in self._walk() if d.name == "server" and d.is_block]

    def upstream_blocks(self):
        return [d for d in self._walk() if d.name == "upstream" and d.is_block]

    def _walk(self):
        """Every directive in the tree, top down."""
        def rec(directives):
            for d in directives:
                yield d
                if d.is_block:
                    yield from rec(d.block)
        return rec(self.directives)


# ==============================================================================
# Turning text into tokens
# ==============================================================================

TOKEN_SPECIAL = {"{", "}", ";"}


def tokenize(text: str):
    """
    Break config text into tokens.

    Yields tuples of (token, line number, is_comment).

    The rules we care about:
      - # runs to the end of the line, unless it is inside quotes
      - single and double quotes both work, and a backslash escapes inside them
      - { } and ; are their own tokens, unless quoted
      - anything else is whitespace separated
    """
    i = 0
    line = 1
    n = len(text)

    while i < n:
        ch = text[i]

        if ch == "\n":
            line += 1
            i += 1
            continue

        if ch in " \t\r":
            i += 1
            continue

        # Comment, runs to end of line.  We keep it so we can write it back.
        if ch == "#":
            end = text.find("\n", i)
            if end == -1:
                end = n
            yield (text[i:end].rstrip(), line, True)
            i = end
            continue

        if ch in TOKEN_SPECIAL:
            yield (ch, line, False)
            i += 1
            continue

        # A quoted string is one token even with spaces and braces inside it.
        if ch in "\"'":
            quote = ch
            i += 1
            buf = []
            start_line = line
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    # Keep the escape as written.  Rewriting it could change
                    # what nginx sees, and we are not trying to normalize
                    # somebody's config, just read it and put it back.
                    buf.append(text[i:i + 2])
                    i += 2
                    continue
                if c == quote:
                    i += 1
                    break
                if c == "\n":
                    line += 1
                buf.append(c)
                i += 1
            else:
                raise ParseError("a quoted string never ends", start_line)

            yield (quote + "".join(buf) + quote, start_line, False)
            continue

        # A plain word.  Runs until whitespace or one of the special chars.
        start = i
        while i < n and text[i] not in " \t\r\n#;{}\"'":
            i += 1
        if i == start:
            # Belt and braces.  Should not happen, but an infinite loop here
            # would hang the whole app, so make sure we always move forward.
            i += 1
        yield (text[start:i], line, False)


# ==============================================================================
# Turning tokens into a tree
# ==============================================================================

def parse(text: str) -> Config:
    """Parse config text into a tree.  Raises ParseError on anything malformed."""
    tokens = list(tokenize(text))
    pos = 0

    def parse_block(depth=0):
        nonlocal pos
        directives = []
        pending_comments = []

        while pos < len(tokens):
            token, line, is_comment = tokens[pos]

            if is_comment:
                pending_comments.append(token)
                pos += 1
                continue

            if token == "}":
                if depth == 0:
                    raise ParseError("a closing brace with nothing open", line)
                pos += 1
                return directives

            if token == ";":
                # A stray semicolon.  nginx does not mind, so neither do we.
                pos += 1
                continue

            if token == "{":
                raise ParseError("a block opened without a directive in front of it", line)

            # Directive name, then arguments until ; or {
            name = token
            start_line = line
            pos += 1
            args = []

            while pos < len(tokens):
                token, line, is_comment = tokens[pos]

                if is_comment:
                    # A comment on the same line as the directive.  Rare, but
                    # people do it, so keep it attached.
                    pos += 1
                    continue

                if token == ";":
                    pos += 1
                    directives.append(Directive(
                        name=name, args=args, line=start_line,
                        leading_comments=pending_comments,
                    ))
                    pending_comments = []
                    break

                if token == "{":
                    pos += 1
                    if depth > 20:
                        # Nothing real nests this deep.  A file this odd is
                        # more likely hostile or corrupt than legitimate, and
                        # recursing forever would take the app down.
                        raise ParseError("config is nested far too deep", line)
                    block = parse_block(depth + 1)
                    directives.append(Directive(
                        name=name, args=args, block=block, line=start_line,
                        leading_comments=pending_comments,
                    ))
                    pending_comments = []
                    break

                args.append(token)
                pos += 1
            else:
                raise ParseError(f"{name} was never finished with a ; or a block", start_line)

        if depth != 0:
            raise ParseError("the file ended with a block still open", tokens[-1][1] if tokens else 0)

        return directives

    directives = parse_block(0)
    return Config(directives=directives, source=text)


# ==============================================================================
# Turning a tree back into text
# ==============================================================================

def serialize(config, indent: int = 0) -> str:
    """Write a parsed config back out as text."""
    directives = config.directives if isinstance(config, Config) else config
    lines = []
    pad = "    " * indent

    for d in directives:
        for comment in d.leading_comments:
            lines.append(f"{pad}{comment}")

        head = d.name
        if d.args:
            head += " " + " ".join(d.args)

        if d.is_block:
            lines.append(f"{pad}{head} {{")
            inner = serialize(d.block, indent + 1)
            if inner:
                lines.append(inner)
            lines.append(f"{pad}}}")
            # A blank line after a block keeps things readable.
            lines.append("")
        else:
            lines.append(f"{pad}{head};")

    # Drop a trailing blank so files do not grow an extra newline every time
    # somebody saves.
    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(lines)


# ==============================================================================
# Basic sanity checks
# ==============================================================================
#
# This is not a replacement for nginx -t and it never will be.  nginx is the
# only thing that truly knows whether a config is valid.  What this does is
# catch the obvious mistakes right in the editor, so you get an underline on
# line 12 instead of waiting for a round trip to the agent.
#
# Everything still goes to nginx -t before it is allowed anywhere near a
# running server.  This is a nicety on top, not a gate.

# Directives that have to have a block after them.
#
# "server" is deliberately not in here, because it is two different things
# depending on where it shows up.  In http it opens a block that holds a site.
# In upstream, stream and mail it is a plain directive naming a backend.  We
# check it separately below, where we know the context.
BLOCK_DIRECTIVES = {
    "http", "location", "upstream", "events", "mail", "stream",
    "map", "geo", "split_clients", "types", "if", "limit_except", "charset_map",
}

# Where a bare "server" means a backend rather than a site.
SERVER_IS_SIMPLE_IN = {"upstream", "mail", "stream"}

# Directives that must never have a block.
SIMPLE_DIRECTIVES = {
    "listen", "server_name", "root", "index", "proxy_pass", "return",
    "rewrite", "add_header", "access_log", "error_log", "include",
}


def quick_check(text: str) -> list:
    """
    Look for problems without asking nginx.

    Gives back a list of dicts with line, severity and message.
    """
    problems = []

    try:
        config = parse(text)
    except ParseError as exc:
        return [{
            "line": exc.line or 0,
            "severity": "error",
            "message": str(exc),
        }]

    def walk(directives, context):
        for d in directives:
            if d.name in BLOCK_DIRECTIVES and not d.is_block:
                problems.append({
                    "line": d.line,
                    "severity": "error",
                    "message": f"{d.name} needs a {{ }} block after it",
                })

            if d.name in SIMPLE_DIRECTIVES and d.is_block:
                problems.append({
                    "line": d.line,
                    "severity": "error",
                    "message": f"{d.name} takes arguments, not a block",
                })

            if d.name == "server":
                if context in SERVER_IS_SIMPLE_IN:
                    # A backend, so it must not have a block, and it needs an
                    # address to point at.
                    if d.is_block:
                        problems.append({
                            "line": d.line,
                            "severity": "error",
                            "message": f"server inside {context} names a backend, it does not take a block",
                        })
                    elif not d.args:
                        problems.append({
                            "line": d.line,
                            "severity": "error",
                            "message": "server needs an address, like server 10.20.30.51:8080",
                        })
                elif not d.is_block:
                    problems.append({
                        "line": d.line,
                        "severity": "error",
                        "message": "server needs a { } block after it",
                    })
                elif not d.find("listen"):
                    # Legal, nginx falls back to port 80, but it is almost
                    # always somebody forgetting rather than meaning it.
                    problems.append({
                        "line": d.line,
                        "severity": "warning",
                        "message": "this server block has no listen, so nginx will assume port 80",
                    })

            # proxy_pass with a trailing slash behaves completely differently
            # from one without, and mixing it up with a regex location is one of
            # the most common nginx bugs there is.
            if d.name == "proxy_pass" and context == "location_regex":
                if d.args and d.args[0].rstrip("/").count("/") > 2:
                    problems.append({
                        "line": d.line,
                        "severity": "warning",
                        "message": (
                            "proxy_pass with a path inside a regex location is not "
                            "allowed by nginx, the URI cannot be rewritten there"
                        ),
                    })

            if d.name == "if" and context == "location":
                problems.append({
                    "line": d.line,
                    "severity": "warning",
                    "message": (
                        "if inside a location is famously unpredictable.  Only return "
                        "and rewrite are really safe in there.  try_files or a map is "
                        "usually the better answer."
                    ),
                })

            if d.is_block:
                child_context = d.name
                if d.name == "location" and d.args and d.args[0] in ("~", "~*"):
                    child_context = "location_regex"
                walk(d.block, child_context)

    walk(config.directives, "main")
    return problems


# ==============================================================================
# Pulling settings back out of config
# ==============================================================================
#
# This is the half that makes the config editor two way.  Somebody types
# client_max_body_size 50m directly into the file, and next time they open the
# form it shows 50m rather than the old value.
#
# We only map directives we know about.  Anything else is left alone and kept in
# the custom config box, so hand written config never gets quietly dropped.

# directive name -> the settings key it belongs to
DIRECTIVE_TO_KEY = {
    "client_max_body_size": "client_max_body_size",
    "client_body_buffer_size": "client_body_buffer_size",
    "client_body_timeout": "client_body_timeout",
    "client_header_timeout": "client_header_timeout",
    "send_timeout": "send_timeout",
    "keepalive_timeout": "keepalive_timeout",
    "keepalive_requests": "keepalive_requests",
    "large_client_header_buffers": "large_client_header_buffers",
    "proxy_connect_timeout": "proxy_connect_timeout",
    "proxy_read_timeout": "proxy_read_timeout",
    "proxy_send_timeout": "proxy_send_timeout",
    "proxy_buffering": "proxy_buffering",
    # Rewriting what a backend says about itself.  Both take two arguments and
    # arg_string keeps them together, which is what the setting stores.
    "proxy_cookie_path": "proxy_cookie_path",
    "proxy_redirect": "proxy_redirect",
    "proxy_buffer_size": "proxy_buffer_size",
    "proxy_buffers": "proxy_buffers",
    "proxy_request_buffering": "proxy_request_buffering",
    "proxy_http_version": "proxy_http_version",
    "proxy_next_upstream": "proxy_next_upstream",
    "proxy_next_upstream_tries": "proxy_next_upstream_tries",
    "proxy_next_upstream_timeout": "proxy_next_upstream_timeout",
    "proxy_ssl_verify": "proxy_ssl_verify",
    "proxy_ssl_server_name": "proxy_ssl_server_name",
    "proxy_intercept_errors": "proxy_intercept_errors",
    "proxy_cache_valid": "proxy_cache_valid",
    "proxy_cache_key": "proxy_cache_key",
    "proxy_cache_bypass": "proxy_cache_bypass",
    "proxy_no_cache": "proxy_no_cache",
    "proxy_cache_use_stale": "proxy_cache_use_stale",
    "proxy_cache_background_update": "proxy_cache_background_update",
    "proxy_cache_lock": "proxy_cache_lock",
    "proxy_cache_min_uses": "proxy_cache_min_uses",
    "gzip": "gzip",
    "gzip_comp_level": "gzip_comp_level",
    "gzip_min_length": "gzip_min_length",
    "gzip_types": "gzip_types",
    "gzip_vary": "gzip_vary",
    "gzip_proxied": "gzip_proxied",
    "gzip_static": "gzip_static",
    "ssl_protocols": "ssl_protocols",
    "ssl_ciphers": "ssl_ciphers",
    "ssl_session_timeout": "ssl_session_timeout",
    "ssl_session_tickets": "ssl_session_tickets",
    "ssl_stapling": "ssl_stapling",
    "ssl_verify_client": "ssl_verify_client",
    "server_tokens": "server_tokens",
    "autoindex": "autoindex",
    "fancyindex": "fancyindex",
    "expires": "expires",
    "try_files": "try_files",
    "sendfile": "sendfile",
    "limit_rate": "limit_rate",
    "limit_rate_after": "limit_rate_after",
    "limit_req_status": "limit_req_status",
    "log_not_found": "log_not_found",
}

BOOL_VALUES = {"on": True, "off": False}

LIST_KEYS = {
    "gzip_types", "ssl_protocols", "proxy_next_upstream",
    "proxy_cache_use_stale", "proxy_cache_bypass", "proxy_no_cache",
    "proxy_cache_valid",
}


def extract_settings(block: Directive) -> dict:
    """
    Read a server or location block and give back settings keys we recognize.

    Only looks at this block's own directives, not nested ones, since a
    location's settings belong to that location and not to the server around it.
    """
    settings = {}

    if not block.is_block:
        return settings

    for d in block.block:
        key = DIRECTIVE_TO_KEY.get(d.name)
        if not key:
            continue

        if key in LIST_KEYS:
            # These can appear more than once and each one adds to the list.
            existing = settings.setdefault(key, [])
            if d.name == "proxy_cache_valid":
                existing.append(d.arg_string())
            else:
                existing.extend(d.args)
            continue

        value = d.arg_string()

        if value in BOOL_VALUES and key not in ("ssl_verify_client", "gzip_proxied"):
            settings[key] = BOOL_VALUES[value]
        elif value.isdigit():
            settings[key] = int(value)
        else:
            settings[key] = _unquote(value)

    return settings


def extract_unknown(block: Directive) -> str:
    """
    Everything in this block we do not have a setting for.

    Goes into the custom config box so hand written directives survive a round
    trip through the GUI.  Losing somebody's config because we did not
    understand it is the fastest way to make them stop using the tool.
    """
    if not block.is_block:
        return ""

    # These we generate ourselves, so seeing them here just means we wrote them.
    # Repeating them in the custom box would double them up on the next save.
    generated = set(DIRECTIVE_TO_KEY.keys()) | {
        "listen", "server_name", "root", "index", "ssl_certificate",
        "ssl_certificate_key", "access_log", "error_log", "location",
        "proxy_pass", "proxy_set_header", "add_header", "include",
        "limit_req", "limit_conn", "proxy_cache", "allow", "deny",
        "return", "error_page", "proxy_hide_header", "http2",
    }

    kept = [d for d in block.block if d.name not in generated]
    return serialize(kept) if kept else ""


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def find_server_for_names(config: Config, server_names: list) -> Optional[Directive]:
    """Find the server block that serves these names."""
    wanted = set(server_names)
    for block in config.server_blocks():
        sn = block.find_one("server_name")
        if sn and wanted & set(sn.args):
            return block
    return None


# ==============================================================================
# Diffing
# ==============================================================================

def diff_configs(old_text: str, new_text: str) -> list:
    """
    Compare two configs and say what actually changed.

    A plain text diff is noisy: reformatting shows up as a hundred changed
    lines even though nothing means anything different.  This compares the
    parsed trees, so you get real changes only.
    """
    try:
        old = parse(old_text)
        new = parse(new_text)
    except ParseError as exc:
        return [{"type": "parse_error", "message": str(exc)}]

    changes = []

    def flatten(directives, path=""):
        out = {}
        for d in directives:
            key = f"{path}/{d.name}"
            if d.args:
                key += f" {' '.join(d.args)}" if d.is_block else ""
            if d.is_block:
                out.update(flatten(d.block, key))
            else:
                out.setdefault(f"{path}/{d.name}", []).append(d.arg_string())
        return out

    old_flat = flatten(old.directives)
    new_flat = flatten(new.directives)

    for key in sorted(set(old_flat) | set(new_flat)):
        before = old_flat.get(key)
        after = new_flat.get(key)
        if before == after:
            continue
        if before is None:
            changes.append({"type": "added", "directive": key, "value": after})
        elif after is None:
            changes.append({"type": "removed", "directive": key, "value": before})
        else:
            changes.append({"type": "changed", "directive": key, "before": before, "after": after})

    return changes
