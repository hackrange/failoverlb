"""
How a feature is described, and the code that looks them up.

The actual list of features lives in features.py.  This file is just the shape
of one and the tools for finding them.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ==============================================================================
# Categories, in the order they show up in the GUI
# ==============================================================================
#
# The order here is the order a person thinks about a site, roughly.  What is it
# and where does it go, then how big can requests be, then how fast, then how
# it is cached, then the security bits.  Putting TLS at the top looks tidy but
# nobody starts there.

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
    What shows up when somebody clicks the ? next to a setting.

    Four parts, and all four earn their place:

      summary   one line, plain words, no jargon
      detail    the why.  What actually happens, and what goes wrong.
      use_cases real situations where you would reach for this
      example   what to type, and what it turns into in the config
    """

    summary: str
    detail: str = ""
    use_cases: list = field(default_factory=list)
    example: str = ""
    example_config: str = ""

    # Link to the nginx docs so people can go read the real thing.
    docs_url: str = ""

    # The trap.  Shown in a warning box, for settings that look harmless and
    # are not.
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

    # What nginx directive this becomes.  Blank means we handle it specially in
    # the renderer, usually because one setting turns into several lines.
    directive: str = ""

    # Where nginx will accept it.  We only offer a setting on a page where it
    # can legally go, so you cannot save something that fails nginx -t.
    contexts: tuple = ("server", "location")

    # bool, int, size, time, string, text, select, multiselect, list
    type: str = "string"

    default: Any = None
    options: list = field(default_factory=list)   # for select, list of (value, label)

    # Kept out of the generic settings form.
    #
    # For a setting that has a screen of its own.  Blocking by country is a
    # list of two letter codes typed into a box when it lives here, and a list
    # of countries with tick boxes when it has its own card, and offering both
    # is how two controls end up disagreeing about what is set.  The setting is
    # still real: it validates, it renders, and the API takes it.
    own_screen: bool = False

    # The value is the rest of a directive, not a value in one.
    #
    # A rewrite rule is a regular expression and a replacement, and nearly every
    # regular expression worth writing has a backslash in it.  The blanket rule
    # below refuses backslashes everywhere, which is right for a value going
    # into a directive and stops these settings being usable at all.  Set this
    # and the entries are checked against what actually breaks out of a
    # directive instead, the same list the renderer enforces.
    regex_values: bool = False

    # The value ends up inside a quoted response header rather than as a bare
    # directive argument.
    #
    # The renderer quotes these and escapes what needs escaping, so a semicolon
    # in one cannot end the directive: esc_header_value exists for exactly that
    # and its docstring says so.  The blanket rule below did not know, so a
    # Content Security Policy could never be saved, because every CSP ever
    # written is a list separated by semicolons and so is the placeholder in
    # the field itself.  Only a newline is refused here, which is the one thing
    # quoting does not survive.
    header_value: bool = False

    # Which module has to be compiled in.  "core" means it is always there.
    module: str = "core"

    # The nginx version this directive first appeared in, as a tuple.
    #
    # Offering a directive an older nginx has never heard of gets you
    # "unknown directive", and the whole config fails to load.  The two phase
    # apply catches that before anything goes live, so nothing breaks, but you
    # are left with a change that will not go out and an error that does not
    # say which setting caused it.
    #
    # None means it has been there long enough that nobody is running an nginx
    # without it.
    min_version: tuple = None

    # The version where this stopped being the right way to write it.  Usually
    # it still works and logs a warning on every start, which is its own kind
    # of annoying.
    deprecated_version: tuple = None

    # oss or plus.  Anything marked plus never renders a control.
    edition: str = "oss"

    # What a free alternative would be, when the feature is plus only.
    oss_alternative: str = ""

    unit: str = ""
    placeholder: str = ""

    # Checking.  Either a regex or a function that takes the value and gives
    # back an error string, or None when it is fine.
    pattern: str = ""
    validator: Optional[Callable] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None

    # This directive takes several space separated arguments rather than one
    # value.  large_client_header_buffers wants "4 8k", proxy_buffers wants
    # "8 4k", try_files wants a list of paths.
    #
    # It matters because the renderer quotes anything with a space in it, which
    # is right for a header value and completely wrong here: nginx sees
    # large_client_header_buffers "4 8k" as one argument and refuses to start
    # with "invalid number of arguments".
    multi_arg: bool = False

    # Hidden behind the "show advanced" toggle so the normal page stays short.
    advanced: bool = False

    # Stop and make somebody read something before this is switched on.
    #
    # For the few settings that can take a working site away from most of the
    # people using it, where the damage is not obvious from the label and does
    # not show up until real traffic arrives.  Help text is not enough on its
    # own: nobody opens the help for a checkbox they already understand, and
    # this is the class of setting where they only think they do.
    #
    # Only on the way on.  Turning one of these off is how you recover, so it
    # should never need a dialog.
    confirm: str = ""

    # Only show this when another setting is on.  Keeps the form from showing
    # you twelve cache options when caching is off.
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
        Can the fleet actually do this.

        Both halves matter.  A module has to be compiled in, and the nginx has
        to be new enough to know the directive.  Either one missing means the
        config will not load.
        """
        if self.edition != "oss":
            return False
        if self.module != "core" and self.module not in modules:
            return False
        if self.min_version and version and version < self.min_version:
            return False
        return True

    def unavailable_reason(self, modules: set, version: tuple = None) -> str:
        """Why not, in words somebody can act on."""
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
    Every feature you can set in this context.

    modules is what we read off the box with nginx -V.  Pass None and you get
    everything, which is only useful for the docs page.
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
    The paid only ones.

    We show these on a page of their own, grayed out, with what to use instead.
    Sounds odd to advertise what you cannot have, but the alternative is people
    hunting for sticky sessions for an hour before finding out it is not free.
    Telling them up front, next to the free workaround, saves that hour.
    """
    _ensure_loaded()
    return [f for f in _REGISTRY.values() if f.edition != "oss"]


# ==============================================================================
# Checking values
# ==============================================================================

SIZE_RE = re.compile(r"^\d+[kKmMgG]?$")
TIME_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h|d|w|M|y)?$")
RATE_RE = re.compile(r"^\d+r/[sm]$")

# nginx variables and simple text.  We are deliberately strict here.  Anything
# that could carry a semicolon or a brace could close the directive early and
# then write whatever it wants into the config, so those characters never make
# it through.
SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9 _.:/@$~^|=+*?()\[\]{}<>,'\"%!&#-]*$")
NO_BREAKOUT_RE = re.compile(r"[;{}\n\r\\]")


def _rule_problem(text: str) -> Optional[str]:
    r"""
    What is wrong with one line that becomes the tail of a directive.

    Backslashes are the point of these, so what is refused is only what ends
    the directive and starts writing config of somebody else's choosing, plus a
    `#`, which comments away the rest of the rule and would silently drop half
    of it.  A trailing single backslash escapes whatever nginx reads next.

    The same list the renderer enforces before writing, on purpose: a rule that
    saves and then cannot be rendered is a setting that looks accepted and does
    nothing, which is the whole reason these two were rewritten.
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
    Check one value.  Gives back an error message, or None when it is fine.

    This runs on every save, on the server, no matter what the browser already
    checked.  Browser checks are a nicety for the person typing.  They are not
    security, since anybody can skip them entirely by calling the API directly.
    """
    if value is None or value == "":
        return None

    # First and most important.  Nothing that could end the directive early and
    # start writing its own config ever gets through, whatever type it is.
    #
    # A header value is the exception, and it is quoted and escaped by the
    # renderer rather than pasted in raw, so the only thing that still breaks
    # out of it is a line break.
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
            # A select with nothing to select from is a feature whose choices
            # live in the database, and the caller was supposed to check it
            # against those rows before getting here.  Saying so beats the old
            # answer, which was "has to be one of:" followed by nothing and
            # sent somebody looking through nginx documentation for a value
            # that was never going to be accepted.
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
                # Quoted and escaped when it is written, so the only thing left
                # that breaks out is a line break.  A Set-Cookie has semicolons
                # in it by definition.
                if re.search(r"[\n\r]", v):
                    return "an entry cannot contain a line break"
            elif NO_BREAKOUT_RE.search(v):
                return "entries cannot contain ; { } backslashes or line breaks"
        return None

    if t in ("string", "text"):
        if feature.pattern and not re.match(feature.pattern, str(value)):
            return f"does not match the expected format: {feature.pattern}"
        # A header value has already been checked for the one thing that breaks
        # a quoted argument, and the safe character list has no semicolon in
        # it, which is the character these settings are made of.
        if feature.header_value:
            return None
        if t == "string" and not SAFE_TEXT_RE.match(str(value)):
            return "has characters in it we will not put in a config file"

        # For a multi argument directive, check each piece on its own.  The
        # whole string goes into the config unquoted, so every token has to be
        # something we are happy to write there.
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
    Import the feature list the first time somebody asks for it.

    features.py imports register() from this file, so importing it at the top
    would be a circular import.  Doing it lazily sidesteps that.
    """
    global _loaded
    if not _loaded:
        _loaded = True
        from app.catalog import features  # noqa: F401
