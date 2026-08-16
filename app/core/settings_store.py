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
}


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
