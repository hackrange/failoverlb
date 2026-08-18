"""
Settings an admin can change from the GUI.

There are two kinds of setting in this tool and it is worth being clear about
which is which.

Some live in the environment: which port to listen on, what this node is
called, the secret key.  Those are read once at startup, they cannot change
while the process is running, and putting them in the GUI would just mean a
box that says "restart the container for this to do anything".

The rest are things you genuinely want to change at 2am without touching a
compose file.  The ACME email, whether to use the staging service, how early to
renew.  Those live in the database and are what this module is for.

Anything read here falls back to the environment when the database has nothing,
so an existing setup keeps working and the GUI shows what is actually in force.
"""

import json
import logging

from app.config import get_settings
from app.core.crypto import decrypt, encrypt
from app.db import session_scope
from app.models import SystemSetting

log = logging.getLogger("nfm.settings")


# What the GUI is allowed to change, and how to treat each one.
#
#   type     how to store and show it
#   secret   encrypted at rest and never sent back to the browser
#   env      the environment variable it falls back to
#   fleet    belongs to the fleet rather than to one box, so it travels with
#            the config snapshot on every apply
#
# **fleet is not decoration.**  A setting only this node knows is a setting the
# standby does not have the morning it gets promoted.  For most of what is
# below that is survivable; for how people sign in it is not, which is why the
# sign in settings are the first ones marked.
EDITABLE = {
    "acme_email": {
        "type": "string",
        "env": "acme_email",
        "label": "Certificate contact email",
    },
    "acme_staging": {
        "type": "bool",
        "env": "acme_staging",
        "label": "Use the Lets Encrypt staging service",
    },
    "acme_renew_days_before": {
        "type": "int",
        "env": "acme_renew_days_before",
        "label": "Renew this many days before expiry",
    },
    "acme_dns_provider": {
        "type": "string",
        "env": None,
        "label": "DNS provider for dns-01 challenges",
    },
    "acme_dns_credentials": {
        "type": "secret",
        "env": None,
        "label": "DNS provider credentials",
    },
    "acme_directory_url": {
        "type": "string",
        "env": None,
        "label": "ACME directory URL",
    },
    "acme_ca_bundle": {
        "type": "string",
        "env": None,
        "label": "CA certificate for that ACME server",
    },
    "dns_resolvers": {
        "type": "list",
        "env": None,
        "label": "DNS servers for domain checks",
    },
    "dns_use_system_resolver": {
        "type": "bool",
        "env": None,
        "label": "Use this box's own resolver as well",
    },
    "management_networks": {
        "type": "list",
        "env": None,
        "label": "Management networks",
    },
    "health_check_interval": {
        "type": "int",
        "env": "health_check_interval",
        "label": "Default health check interval",
    },
    "log_parsing_enabled": {
        "type": "bool",
        "env": None,
        "label": "Read the access logs for per site numbers",
    },
    "geoip_source": {
        "type": "string",
        "env": None,
        "label": "Where the country database comes from",
    },
    "geoip_account_id": {
        "type": "string",
        "env": None,
        "label": "MaxMind account id",
    },
    "geoip_license_key": {
        "type": "secret",
        "env": None,
        "label": "MaxMind licence key",
    },
    "geoip_refresh": {
        "type": "string",
        "env": None,
        "label": "How often to fetch a new country database",
    },
    "waf_crs_track": {
        "type": "string",
        "env": None,
        "label": "Which rule set track to follow",
    },
    "waf_crs_refresh": {
        "type": "string",
        "env": None,
        "label": "How often to fetch a new rule set",
    },

    # ---- how people sign in to this GUI --------------------------------------
    #
    # These were environment only until now, which meant editing .env on every
    # node and restarting all of them to change an identity provider.  They are
    # all marked fleet, because sign in has to work on whichever node answers,
    # and after a failover that is not the node somebody set them on.
    "auth_mode": {
        "type": "string",
        "env": None,
        "fleet": True,
        "label": "How people sign in",
    },
    "oidc_discovery_url": {
        "type": "string",
        "env": "oidc_discovery_url",
        "fleet": True,
        "label": "OpenID discovery URL",
    },
    "oidc_client_id": {
        "type": "string",
        "env": "oidc_client_id",
        "fleet": True,
        "label": "Client id",
    },
    "oidc_client_secret": {
        "type": "secret",
        "env": "oidc_client_secret",
        "fleet": True,
        "label": "Client secret",
    },
    "oidc_redirect_base": {
        "type": "string",
        "env": "oidc_redirect_base",
        "fleet": True,
        "label": "The address the provider sends people back to",
    },
    "oidc_groups_claim": {
        "type": "string",
        "env": "oidc_groups_claim",
        "fleet": True,
        "label": "Which claim holds the group names",
    },
    "oidc_admin_group": {
        "type": "string",
        "env": "oidc_admin_group",
        "fleet": True,
        "label": "Group that gets admin",
    },
    "oidc_operator_group": {
        "type": "string",
        "env": "oidc_operator_group",
        "fleet": True,
        "label": "Group that gets operator",
    },
    "oidc_viewer_group": {
        "type": "string",
        "env": "oidc_viewer_group",
        "fleet": True,
        "label": "Group that gets viewer",
    },
}

# The three ways in, and what each one means.
#
#   local   passwords on this box only.  The provider is ignored even if it is
#           configured, which is what you want while you are still setting one
#           up and do not want a half finished button on the login page.
#   both    either.  The safe middle, and the only mode you can reach oidc from,
#           because it is where somebody proves their account maps to a real
#           person at the provider.
#   oidc    the provider only.  Local passwords stop working.  This is the mode
#           people want once the provider is the system of record, and it is the
#           one that can lock everybody out, so it has its own guard rails.
AUTH_MODES = ("local", "both", "oidc")

# Settings that belong to the fleet rather than to one box.  Read by the config
# snapshot so they travel on every apply.
FLEET_KEYS = tuple(k for k, spec in EDITABLE.items() if spec.get("fleet"))

# Internal values that still have to be the same on every node.
#
# `INTERNAL` below is deliberately off the settings page, and for most of it
# that is the end of the story: it is this node's own bookkeeping.  These two
# are not.  They describe what the *fleet* is, and a node that does not have
# them makes the wrong decision the moment it becomes the active one.
#
# `waf_module` is the one that bites.  Every rebuild reads it so an unrelated
# version upgrade does not quietly drop the WAF module, which is exactly the
# promise its own comment makes further down.  That promise only held on the
# node somebody happened to click on.  Fail over to the other node, upgrade
# nginx from there, and it rebuilds without the module; every site running the
# WAF then fails its config test, and since an apply is all or nothing that is
# the whole fleet unable to apply anything.  Found on 18 August, on a fleet
# where lb01 said True and lb02 said None.
#
# They travel in the config snapshot with everything else, so a standby that
# has never been clicked on still knows what the fleet is.
INTERNAL_FLEET_KEYS = ("waf_module", "waf_crs_last_install")

# What may cross the wire in a snapshot, in one place, because capture and
# restore reading two different lists is how a setting travels out and is
# refused on arrival.
SNAPSHOT_KEYS = FLEET_KEYS + INTERNAL_FLEET_KEYS


# Settings the app keeps for itself.  Not on the GUI's editable list, because
# nobody should be typing these, but they still need somewhere to live that
# survives a restart.  Kept separate so the settings page cannot show or change
# them by accident.
INTERNAL = {
    "acme_hook_secret": {"type": "secret", "env": None, "label": "certbot hook secret"},
    # When the country database was last put on the fleet.  Kept by the app so
    # the schedule knows whether anything is due, and shown on the page, but
    # not something anybody should be typing.
    "geoip_last_install": {"type": "string", "env": None,
                           "label": "country database last installed"},
    # Whether nginx is built with the WAF module in it.  Not a normal setting
    # and deliberately not on the settings page: turning it on by itself does
    # nothing, because the module only appears after nginx is rebuilt.  The
    # flow that switches the WAF on sets this and then offers the rebuild, and
    # every rebuild after that reads it so the module is not quietly dropped by
    # an unrelated version upgrade.
    "waf_module": {"type": "bool", "env": None,
                   "label": "build nginx with the WAF module"},
    # When the rule set was last put on the fleet, so the schedule knows
    # whether anything is due.  Kept by the app, shown on the page, not
    # something anybody should be typing.
    "waf_crs_last_install": {"type": "string", "env": None,
                             "label": "rule set last installed"},
    # Which node somebody asked to be the active one.  Empty means nobody
    # asked and the election decides on priority as it always did.
    #
    # Not on the settings page, because it is not a preference somebody types,
    # it is the record of pressing the failover button.  It is deliberately not
    # a fleet key either: fleet keys travel in the config snapshot, which only
    # moves on an apply, and this has to reach the other node in seconds.  It
    # rides the heartbeat instead, with the timestamp below deciding which of
    # two instructions is the newer one.
    "preferred_active_node": {"type": "string", "env": None,
                              "label": "node asked to be active"},
    "preferred_active_at": {"type": "string", "env": None,
                            "label": "when that was asked for"},
}


def _spec(key: str):
    return EDITABLE.get(key) or INTERNAL.get(key)


def get(key: str, default=None):
    """
    Read a setting.  Database first, then the environment, then the default.
    """
    spec = _spec(key)

    with session_scope() as session:
        row = session.query(SystemSetting).filter(SystemSetting.key == key).first()
        raw = row.value if row else None
        was_encrypted = bool(row and row.encrypted)

    if raw is not None:
        if was_encrypted:
            raw = decrypt(raw)
            if raw is None:
                # The node key changed, so this cannot be read any more.  Fall
                # through to the environment rather than handing back garbage.
                log.warning("could not decrypt the stored value for %s", key)
                raw = None

    if raw is not None:
        return _coerce(raw, spec["type"] if spec else "string")

    if spec and spec.get("env"):
        value = getattr(get_settings(), spec["env"], None)
        if value not in (None, ""):
            return value

    return default


def set(key: str, value, actor: str = "system"):
    """Store a setting.  Refuses anything not on the editable list."""
    spec = _spec(key)
    if not spec:
        raise ValueError(f"{key} is not a setting this tool knows about")

    if spec["type"] == "list" and isinstance(value, list):
        stored = json.dumps(value)
    elif spec["type"] == "bool":
        stored = "true" if value else "false"
    else:
        stored = "" if value is None else str(value)

    encrypted = spec["type"] == "secret"
    if encrypted and stored:
        stored = encrypt(stored)

    with session_scope() as session:
        row = session.query(SystemSetting).filter(SystemSetting.key == key).first()
        if not row:
            row = SystemSetting(key=key)
            session.add(row)
        row.value = stored
        row.encrypted = encrypted
        row.updated_by = actor
        session.commit()


def all_visible() -> dict:
    """
    Everything the settings page shows.

    Secrets come back as a flag saying whether one is stored, never as the
    value.  A settings page that helpfully fills the password box with the real
    password is a settings page that leaks it to anybody who opens the browser
    developer tools, or to the next person to use that machine.
    """
    out = {}
    for key, spec in EDITABLE.items():
        if spec["type"] == "secret":
            out[key] = {"is_set": bool(get(key)), "label": spec["label"]}
        else:
            out[key] = {"value": get(key), "label": spec["label"]}
    return out


def _coerce(raw: str, kind: str):
    if kind == "bool":
        return str(raw).lower() in ("true", "1", "yes", "on")
    if kind == "int":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    if kind == "list":
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            return []
    return raw


# ==============================================================================
# Signing in
# ==============================================================================

def auth_mode() -> str:
    """
    Which of the three ways in is switched on: local, both, or oidc.

    Falls back to the environment the way everything else here does, so an
    install that set `NFM_OIDC_ENABLED` before this page existed keeps the
    behaviour it had: the provider offered alongside local passwords.  Anything
    unrecognised reads as local, because the failure that matters is a typo in
    a database row turning into nobody being able to sign in.
    """
    stored = str(get("auth_mode") or "").strip().lower()
    if stored in AUTH_MODES:
        return stored
    return "both" if get_settings().oidc_enabled else "local"


def local_passwords_allowed() -> bool:
    """Whether a username and password still gets anybody in."""
    return auth_mode() != "oidc"


def oidc_offered() -> bool:
    """
    Whether the provider should be offered at all.

    Only says the mode allows it.  Whether it is actually usable is
    `app.auth.oidc.is_configured()`, which also wants a discovery URL, a client
    id and somewhere to come back to.
    """
    return auth_mode() in ("both", "oidc")


def oidc_config() -> dict:
    """
    Every OIDC value, database first and the environment behind it.

    One function rather than nine lookups scattered about, because the failure
    this prevents is subtle: half the flow reading the database and half of it
    still reading the environment gives a login that starts against one
    provider and finishes against another.
    """
    return {
        "discovery_url": (get("oidc_discovery_url") or "").strip(),
        "client_id": (get("oidc_client_id") or "").strip(),
        "client_secret": (get("oidc_client_secret") or "").strip(),
        "redirect_base": (get("oidc_redirect_base") or "").strip(),
        "groups_claim": (get("oidc_groups_claim") or "groups").strip(),
        "admin_group": (get("oidc_admin_group") or "nginx-admins").strip(),
        "operator_group": (get("oidc_operator_group") or "nginx-operators").strip(),
        "viewer_group": (get("oidc_viewer_group") or "nginx-viewers").strip(),
    }


# ==============================================================================
# What travels with the config
# ==============================================================================

def capture_fleet() -> list:
    """
    The fleet wide settings, as plain data, for the config snapshot.

    Secrets are unsealed here and sealed again with the receiving node's own
    key, exactly as `snapshot.py` already does for pool tokens and private
    keys.  The reasoning is the same and so is the trade: the peer link is
    mutual TLS between two nodes holding certificates from the same private CA,
    with a signature on every message, and a client secret that does not
    survive a failover is a fleet where nobody can sign in the moment the
    standby takes over.

    A value that will not decrypt here is left out rather than sent as bytes
    the far end would store and never be able to read.
    """
    out = []
    for key in SNAPSHOT_KEYS:
        with session_scope() as session:
            row = session.query(SystemSetting).filter(
                SystemSetting.key == key).first()
            if row is None:
                continue
            raw, sealed = row.value, bool(row.encrypted)

        if sealed and raw:
            raw = decrypt(raw)
            if raw is None:
                log.warning("could not read %s for the snapshot, leaving it out", key)
                continue

        out.append({"key": key, "value": raw, "encrypted": sealed})
    return out


def restore_fleet(rows) -> int:
    """
    Put the fleet wide settings back from a snapshot.

    Only keys on the fleet list are accepted.  A snapshot is data that arrived
    over the network, and a loop that wrote whatever keys it was handed would
    let a peer set anything in this table, including the internal values the
    settings page deliberately cannot reach.
    """
    if not rows:
        return 0

    # A set literal, not set().  This module defines its own `set` a hundred
    # lines up, so the builtin is not the builtin in here.  The check caught
    # this, which is the only reason it is not still sitting in the one code
    # path that runs during a failover and nowhere else.
    allowed = {*SNAPSHOT_KEYS}
    written = 0
    with session_scope() as session:
        for row in rows:
            key = row.get("key")
            if key not in allowed:
                log.warning("a snapshot tried to set %s, which is not a fleet "
                            "setting, so it was ignored", key)
                continue

            value = row.get("value")
            sealed = bool(row.get("encrypted"))
            if sealed and value:
                value = encrypt(value)

            existing = session.query(SystemSetting).filter(
                SystemSetting.key == key).first()
            if existing is None:
                existing = SystemSetting(key=key)
                session.add(existing)
            existing.value = value
            existing.encrypted = sealed
            existing.updated_by = "snapshot"
            written += 1
        session.commit()
    return written


def acme_email() -> str:
    """
    The contact address for certificates, or empty if nobody set one.

    Empty is allowed.  Lets Encrypt will issue without a contact address, it
    just will not email you before something expires.  That matters less here
    than it would elsewhere, because the manager is watching expiry itself and
    puts a warning on the dashboard well before it becomes a problem.

    Refusing to issue without an email would be us inventing a requirement the
    certificate authority does not have.
    """
    return (get("acme_email") or "").strip()
