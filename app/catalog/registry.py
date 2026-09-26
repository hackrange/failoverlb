"""
The Feature dataclass, the registry, and value validation.

The features themselves are defined in features.py.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ==============================================================================
# Categories, in the order they show up in the GUI
# ==============================================================================
#
# Roughly the order people think about a site: basics and routing first,
# then limits, caching, and security settings.

CATEGORIES = [
    ("general", "General", "Basics for this site or path"),
    ("proxy", "Proxy", "How requests get passed to your backends"),
    ("limits", "Limits and Timeouts", "Upload sizes, request sizes, how long to wait"),
    ("ratelimit", "Rate Limiting", "Slow down clients asking for too much, too fast"),
    ("cache", "Caching", "Keep copies of backend responses so they are not asked for twice"),
    ("compression", "Compression", "Shrink responses on the way out"),
    ("headers", "Headers", "Add, change or remove headers"),
    ("security", "Security", "Headers and rules that make attacks harder"),
    ("tls", "TLS", "Certificate and encryption settings"),
    ("access", "Access Control", "Who is allowed in"),
    ("static", "Static Files", "Serving files off the disk"),
    ("logging", "Logging", "What gets written down and where"),
    ("websocket", "WebSocket", "Long lived upgraded connections"),
    ("advanced", "Advanced", "Sharp edges.  Know what you are doing."),
]

CATEGORY_LOOKUP = {key: (label, desc) for key, label, desc in CATEGORIES}


# ==============================================================================
# Help text
# ==============================================================================

@dataclass
class HelpText:
    """
    Help shown from the ? next to a setting.

      summary   one plain line
      detail    what it does and what can go wrong
      use_cases situations where you would use it
      example   what to type, and the resulting config
    """

    summary: str
    detail: str = ""
    use_cases: list = field(default_factory=list)
    example: str = ""
    example_config: str = ""

    # Link to the upstream nginx docs.
    docs_url: str = ""

    # Shown in a warning box, for settings that look harmless but are not.
    warning: str = ""


# ==============================================================================
# A feature
# ==============================================================================

@dataclass
class Feature:
    key: str                       # what we store it under
    label: str                     # what the person sees
    category: str
    help: HelpText

    # nginx directive name.  Blank means the renderer handles it specially,
    # usually because it expands to several lines.
    directive: str = ""

    # nginx contexts where the directive is valid.  Settings are only offered
    # where they can legally go.
    contexts: tuple = ("server", "location")

    # bool, int, size, time, string, text, select, multiselect, list
    type: str = "string"

    default: Any = None
    options: list = field(default_factory=list)   # [(value, label), ...]

    # Hidden from the generic settings form because it has a dedicated UI
    # (e.g. country blocking).  Still validated, rendered and accepted by the
    # API; this only avoids two controls for the same value.
    own_screen: bool = False

    # Entries are regex rules (e.g. rewrites) that need backslashes.  Checked
    # with _rule_problem instead of the blanket no-backslash rule, matching
    # what the renderer enforces.
    regex_values: bool = False

    # Value is written as a quoted, escaped header value (esc_header_value),
    # so semicolons are safe; a CSP needs them.  Only line breaks are refused.
    header_value: bool = False

    # Which module has to be compiled in.  "core" means it is always there.
    module: str = "core"

    # First nginx version with this directive.  Older versions fail with
    # "unknown directive", which the apply catches but without naming the
    # setting.  None means it is old enough to assume.
    min_version: tuple = None

    # Version where this was deprecated (usually still works, with a warning).
    deprecated_version: tuple = None

    # oss or plus.  Anything marked plus never renders a control.
    edition: str = "oss"

    # What a free alternative would be, when the feature is plus only.
    oss_alternative: str = ""

    unit: str = ""
    placeholder: str = ""

    # Validation: a regex, or a callable returning an error string or None.
    pattern: str = ""
    validator: Optional[Callable] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None

    # Takes several space separated arguments, e.g.
    # large_client_header_buffers "4 8k".  The renderer must not quote these
    # or nginx sees one argument and fails with "invalid number of arguments".
    multi_arg: bool = False

    # Hidden behind the "show advanced" toggle so the normal page stays short.
    advanced: bool = False

    # Confirmation text shown before enabling a setting that can break a
    # working site in non-obvious ways.  Not asked when turning it off, since
    # that is the recovery path.
    confirm: str = ""

    # Only shown when this other setting is on.
    depends_on: str = ""

    def render_value(self, value) -> str:
        """Turn a stored value into the text that goes after the directive."""
        if self.type == "bool":
            return "on" if value else "off"
        if self.type == "list" and isinstance(value, list):
            return " ".join(str(v) for v in value)
        return str(value)

    def is_available(self, modules: set, version: tuple = None) -> bool:
        """
        Whether the fleet supports this: OSS edition, module compiled in, and
        nginx new enough for the directive.
        """
        if self.edition != "oss":
            return False
        if self.module != "core" and self.module not in modules:
            return False
        if self.min_version and version and version < self.min_version:
            return False
        return True

    def unavailable_reason(self, modules: set, version: tuple = None) -> str:
        """Human-readable reason is_available() is False, or ""."""
        if self.edition != "oss":
            return "only in the paid nginx"
        if self.module != "core" and self.module not in modules:
            return (
                f"needs the {self.module} module, which is not compiled into every "
                f"node's nginx"
            )
        if self.min_version and version and version < self.min_version:
            want = ".".join(str(p) for p in self.min_version)
            have = ".".join(str(p) for p in version) if version else "unknown"
            return (
                f"needs nginx {want} or newer, and the oldest node in the fleet is "
                f"running {have}"
            )
        return ""


# ==============================================================================
# The registry
# ==============================================================================

_REGISTRY: dict = {}


def register(*features):
    for f in features:
        if f.key in _REGISTRY:
            raise ValueError(f"two features are both called {f.key}")
        _REGISTRY[f.key] = f
    return features


def get_feature(key: str) -> Optional[Feature]:
    _ensure_loaded()
    return _REGISTRY.get(key)


def all_features() -> dict:
    _ensure_loaded()
    return dict(_REGISTRY)


def features_for_context(context: str, modules: set = None, include_plus: bool = False,
                         version: tuple = None):
    """
    Features valid in this context.

    `modules` comes from nginx -V.  None skips the availability filter.
    """
    _ensure_loaded()
    out = []
    for f in _REGISTRY.values():
        if context not in f.contexts:
            continue
        if f.edition != "oss" and not include_plus:
            continue
        if modules is not None and not f.is_available(modules, version) and f.edition == "oss":
            continue
        out.append(f)
    return out


def features_in_category(category: str, context: str = None, modules: set = None):
    feats = features_for_context(context, modules) if context else list(all_features().values())
    return [f for f in feats if f.category == category]


def plus_only_features():
    """
    NGINX Plus only features, listed on the comparison page with the open
    source alternative so people do not go hunting for them.
    """
    _ensure_loaded()
    return [f for f in _REGISTRY.values() if f.edition != "oss"]


# ==============================================================================
# Checking values
# ==============================================================================

SIZE_RE = re.compile(r"^\d+[kKmMgG]?$")
TIME_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h|d|w|M|y)?$")
RATE_RE = re.compile(r"^\d+r/[sm]$")

# Deliberately strict.  A semicolon or brace could close the directive and
# inject arbitrary config.
SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9 _.:/@$~^|=+*?()\[\]{}<>,'\"%!&#-]*$")
NO_BREAKOUT_RE = re.compile(r"[;{}\n\r\\]")


def _rule_problem(text: str) -> Optional[str]:
    r"""
    Problem with one regex rule entry, or None.

    Backslashes are allowed.  Refuses what would end the directive, `#`
    (comments out the rest), and a trailing odd backslash.  Must match what
    the renderer enforces, or a rule would save but never render.
    """
    if not text.strip():
        return "an empty entry is not a rule"
    if re.search(r"[;{}\n\r]", text):
        return "entries cannot contain ; { } or line breaks"
    if "#" in text:
        return ("entries cannot contain #, which nginx reads as the start of a "
                "comment and would drop the rest of the rule")
    trailing = len(text) - len(text.rstrip("\\"))
    if trailing % 2:
        return "an entry cannot end in a single backslash"
    return None


def validate_value(feature: Feature, value) -> Optional[str]:
    """
    Validate one value; return an error message or None.

    Runs server side on every save.  Browser checks are only a convenience.
    """
    if value is None or value == "":
        return None

    # Block directive breakout for every type.  Header values are quoted by
    # the renderer, so only line breaks matter there.
    if isinstance(value, str):
        if feature.header_value:
            if re.search(r"[\n\r]", value):
                return "cannot contain a line break"
        elif NO_BREAKOUT_RE.search(value):
            return "cannot contain ; { } backslashes or line breaks"

    t = feature.type

    if t == "bool":
        if not isinstance(value, bool):
            return "has to be true or false"
        return None

    if t == "int":
        try:
            n = int(value)
        except (TypeError, ValueError):
            return "has to be a whole number"
        if feature.min_value is not None and n < feature.min_value:
            return f"has to be {feature.min_value} or more"
        if feature.max_value is not None and n > feature.max_value:
            return f"has to be {feature.max_value} or less"
        return None

    if t == "size":
        if not SIZE_RE.match(str(value)):
            return "has to be a size like 10m, 512k or 1g"
        return None

    if t == "time":
        if not TIME_RE.match(str(value)):
            return "has to be a time like 30s, 5m or 1h"
        return None

    if t == "select":
        valid = [v for v, _ in feature.options]
        if not valid:
            # Choices come from the database and the caller should have
            # validated them already.  Reaching here is a bug.
            return ("this setting takes its choices from the database and "
                    "nothing checked them, which is a bug in this tool rather "
                    "than anything you typed")
        if value not in valid:
            return f"has to be one of: {', '.join(valid)}"
        return None

    if t == "multiselect":
        if not isinstance(value, list):
            return "has to be a list"
        valid = [v for v, _ in feature.options]
        for v in value:
            if v not in valid:
                return f"{v} is not one of the choices"
        return None

    if t == "list":
        if not isinstance(value, list):
            return "has to be a list"
        for v in value:
            if not isinstance(v, str):
                return "every entry has to be text"
            if feature.regex_values:
                problem = _rule_problem(v)
                if problem:
                    return problem
            elif feature.header_value:
                # Quoted when written; only line breaks can break out.
                if re.search(r"[\n\r]", v):
                    return "an entry cannot contain a line break"
            elif NO_BREAKOUT_RE.search(v):
                return "entries cannot contain ; { } backslashes or line breaks"
        return None

    if t in ("string", "text"):
        if feature.pattern and not re.match(feature.pattern, str(value)):
            return f"does not match the expected format: {feature.pattern}"
        # Already checked above; SAFE_TEXT_RE would reject its semicolons.
        if feature.header_value:
            return None
        if t == "string" and not SAFE_TEXT_RE.match(str(value)):
            return "has characters in it we will not put in a config file"

        # Multi argument values are written unquoted, so check each token.
        if feature.multi_arg:
            tokens = str(value).split()
            if not tokens:
                return "needs at least one value"
            if len(tokens) > 16:
                return "that is far more arguments than any of these directives take"
            for token in tokens:
                if not SAFE_TEXT_RE.match(token):
                    return f"{token!r} has characters we will not put in a config file"
        return None

    if feature.validator:
        return feature.validator(value)

    return None


# ==============================================================================
# Loading
# ==============================================================================

_loaded = False


def _ensure_loaded():
    """
    Import features.py on first use.  It imports register() from here, so a
    top-level import would be circular.
    """
    global _loaded
    if not _loaded:
        _loaded = True
        from app.catalog import features  # noqa: F401
