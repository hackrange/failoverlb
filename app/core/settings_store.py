"""
Settings an admin can change from the GUI.

Startup settings (listen port, node name, secret key) come from the
environment and need a restart.  Settings worth changing at runtime (ACME
email, staging, renewal window, SSO, and so on) live in the database and are
handled here.

Reads fall back to the environment when the database has no value, so the GUI
shows what is actually in effect.
"""

import json
import logging

from app.config import get_settings
from app.core.crypto import decrypt, encrypt
from app.db import session_scope
from app.models import SystemSetting

log = logging.getLogger("nfm.settings")


# Settings the GUI may change.
#
#   type     how to store and show it ("secret" is encrypted at rest and
#            never sent back to the browser)
#   env      the environment variable it falls back to
#   fleet    fleet-wide rather than per node; travels with the config
#            snapshot on every apply so a promoted standby has it
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
    # All fleet keys: sign in must work on whichever node is active.
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

# Sign in modes.
#
#   local   local passwords only; the provider is ignored even if configured
#   both    either.  The only mode oidc can be selected from, so an admin
#           has proven an SSO login works first.
#   oidc    provider only; local passwords are refused.  Can lock everyone
#           out, hence the guard rails.
AUTH_MODES = ("local", "both", "oidc")

# Fleet-wide editable settings, carried in the config snapshot.
FLEET_KEYS = tuple(k for k, spec in EDITABLE.items() if spec.get("fleet"))

# INTERNAL values that must still match on every node, so they travel in
# the snapshot too.  If waf_module were missing on the standby, an nginx
# upgrade run after failover would rebuild without the WAF module, and every
# WAF site would then fail the config test and block all applies.
INTERNAL_FLEET_KEYS = ("waf_module", "waf_crs_last_install")

# Single allowlist shared by capture_fleet() and restore_fleet().
SNAPSHOT_KEYS = FLEET_KEYS + INTERNAL_FLEET_KEYS


# Values the app keeps for itself.  Persisted like settings but kept off
# the settings page.
INTERNAL = {
    "acme_hook_secret": {"type": "secret", "env": None, "label": "certbot hook secret"},
    # Last GeoIP database install, used by the refresh schedule.
    "geoip_last_install": {"type": "string", "env": None,
                           "label": "country database last installed"},
    # Whether nginx should be built with the WAF module.  Set by the WAF
    # enable flow (which then offers a rebuild) and read by every later
    # rebuild so an upgrade does not drop the module.
    "waf_module": {"type": "bool", "env": None,
                   "label": "build nginx with the WAF module"},
    # Last CRS rule set install, used by the refresh schedule.
    "waf_crs_last_install": {"type": "string", "env": None,
                             "label": "rule set last installed"},
    # Node requested as active via the failover button; empty means the
    # election uses priority.  Not a fleet key, since snapshots only move on
    # apply and this must propagate in seconds.  It travels on the heartbeat,
    # and preferred_active_at decides which request is newer.
    "preferred_active_node": {"type": "string", "env": None,
                              "label": "node asked to be active"},
    "preferred_active_at": {"type": "string", "env": None,
                            "label": "when that was asked for"},
}


def _spec(key: str):
    return EDITABLE.get(key) or INTERNAL.get(key)


def get(key: str, default=None):
    """Read a setting: database, then environment, then default."""
    spec = _spec(key)

    with session_scope() as session:
        row = session.query(SystemSetting).filter(SystemSetting.key == key).first()
        raw = row.value if row else None
        was_encrypted = bool(row and row.encrypted)

    if raw is not None:
        if was_encrypted:
            raw = decrypt(raw)
            if raw is None:
                # Node key changed; fall back to the environment.
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
    Values for the settings page.  Secrets are reported only as set or not
    set, never returned to the browser.
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
    Current sign in mode: local, both, or oidc.

    Without a stored value, `NFM_OIDC_ENABLED` maps to "both", otherwise
    "local".  An unrecognized stored value also falls back this way, so a bad
    row cannot lock everyone out.
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
    Whether the mode allows SSO.  See `app.auth.oidc.is_configured()` for
    whether it is actually usable.
    """
    return auth_mode() in ("both", "oidc")


def oidc_config() -> dict:
    """
    All OIDC settings, database first with environment fallback.

    Read in one place so a login cannot start against one provider and finish
    against another.
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
    Fleet-wide settings as plain data for the config snapshot.

    Secrets are decrypted here and re-encrypted with the receiving node's key,
    as `snapshot.py` does for pool tokens and private keys; the peer link is
    mutual TLS with signed messages.  Values that fail to decrypt are skipped.
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
    Restore fleet-wide settings from a snapshot.

    Only SNAPSHOT_KEYS are accepted, so a peer cannot write arbitrary rows.
    """
    if not rows:
        return 0

    # Not set(): this module defines its own `set`, shadowing the builtin.
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
    ACME contact email, or "".

    Empty is fine: the CA issues without one, and expiry is monitored here
    anyway.
    """
    return (get("acme_email") or "").strip()
