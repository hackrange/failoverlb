"""
The whole config as data, so a promoted standby has something to work from.

A standby holds the rendered files but not the objects they came from, since
config objects only live on the active node.  When the active node goes away
the survivor is promoted with nothing to render from.  So every apply carries
the objects alongside the files, and a promoted node that finds itself empty
restores them from the newest snapshot it was given.

Columns are read off the models rather than listed here, so a new column can't
be forgotten and silently fail to survive a failover.

Secrets (pool tokens, uploaded private keys, TOTP seeds) are encrypted with a
per-node key, so they are decrypted on the way out and re-encrypted with the
receiving node's key on the way in.  The plain values cross the peer link,
which is mutual TLS with a private CA and signed messages, the same channel
certificate replication already trusts with private keys.  Peer HMAC keys
belong to the node, not the config, and are not included.

Accounts travel too, so password changes and revoked access reach every node.
They are merged by username rather than replaced: sessions cascade off users
(replacing rows would log everyone out on every apply), lockout counters and
last login belong to the box that saw them, and ids stay stable.  A snapshot
with no enabled admin is refused and local accounts are left untouched, since
that is the one thing here that could lock everyone out of every node.
"""
import logging
from datetime import datetime

from app.core.crypto import decrypt, encrypt
from app.models import (
    AccessList,
    CacheZone,
    Certificate,
    CertificateAuthority,
    ConnLimitZone,
    ErrorPageImage,
    ErrorPageTemplate,
    GslbAnswer,
    GslbRecord,
    GslbZone,
    Location,
    LoginWatch,
    MapBlock,
    Pool,
    PoolMember,
    RateLimitZone,
    StreamServer,
    TunnelNetwork,
    TunnelPeer,
    User,
    UserRole,
    VirtualHost,
    WafExclusion,
    WafSurfaceEntry,
    WafProfile,
    WafSession,
)

log = logging.getLogger("nfm.snapshot")

# In dependency order.  Restoring writes them in this order and clears them in
# reverse, so a row never points at a parent that is not there yet or has gone.
TABLES = [
    ("access_lists", AccessList),
    ("rate_zones", RateLimitZone),
    ("conn_zones", ConnLimitZone),
    ("cache_zones", CacheZone),
    ("maps", MapBlock),
    ("certificate_authorities", CertificateAuthority),
    ("certificates", Certificate),
    ("error_page_templates", ErrorPageTemplate),
    ("error_page_images", ErrorPageImage),
    # Tuned WAF profiles, before the sites that point at them.  They are
    # expensive to recreate by hand.
    ("waf_profiles", WafProfile),
    ("waf_exclusions", WafExclusion),
    # The positive model.  Without it a promoted standby would enforce with
    # nothing allowed and refuse every request.
    ("waf_surface_entries", WafSurfaceEntry),
    ("pools", Pool),
    ("pool_members", PoolMember),
    ("hosts", VirtualHost),
    ("locations", Location),
    # After the sites, since a watch belongs to one.
    ("login_watches", LoginWatch),
    # After the sites.  Kept because a profile's provenance points back at
    # the session it came from.
    ("waf_sessions", WafSession),
    ("streams", StreamServer),
    # Parents before children, or records with no zone get dropped.
    ("gslb_zones", GslbZone),
    ("gslb_records", GslbRecord),
    ("gslb_answers", GslbAnswer),
    # The network before its peers.
    ("tunnel_networks", TunnelNetwork),
    ("tunnel_peers", TunnelPeer),
]

# Encrypted with a per-node key: decrypted to travel, re-encrypted on arrival.
SECRET_COLUMNS = {
    "token_encrypted",
    "token_next_encrypted",
    "token_previous_encrypted",
    "dns_credentials_encrypted",
    "eab_hmac_key_encrypted",
    "uploaded_privkey_encrypted",
    # WireGuard pre-shared keys.  Both ends must hold the same one.
    "psk_encrypted",
    "totp_secret_encrypted",
}

# Fleet-wide account fields.  Anything else is local to the node that saw it.
USER_FLEET_COLUMNS = [
    "username",
    "email",
    "full_name",
    "source",
    "role",
    "password_hash",
    "totp_secret_encrypted",
    "totp_enrolled",
    "recovery_codes",
    "enabled",
    "must_change_password",
    "oidc_subject",
    "created_at",
    "updated_at",
    "created_by",
]


def _columns(model):
    return [c.name for c in model.__table__.columns]


def _coerce(model, name, value):
    """
    Turn a value from json back into what the column expects.

    Dates come out of json as strings and sqlite won't take a string for a
    DateTime.  Enums need nothing; SQLAlchemy maps their values itself.
    """
    if value is None:
        return None

    column = model.__table__.columns.get(name)
    if column is None:
        return value

    kind = type(column.type).__name__

    if kind == "DateTime" and isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            # Not worth failing a failover over.  These are all "last
            # happened at" fields, so we only lose a timestamp.
            log.warning("could not read %s.%s as a date, leaving it empty", model.__name__, name)
            return None

    if kind == "Boolean" and isinstance(value, int):
        return bool(value)

    return value


def capture(session) -> dict:
    """
    Every config object, as plain data.  Ids are kept since that's how
    objects reference each other.
    """
    out = {"version": 1, "tables": {}}

    for key, model in TABLES:
        rows = []
        for obj in session.query(model).all():
            row = {}
            for name in _columns(model):
                value = getattr(obj, name, None)

                if name in SECRET_COLUMNS and value:
                    value = decrypt(value)
                    if value is None:
                        # Key changed under us.  Better to send nothing than
                        # something the other end can never read.
                        log.warning("could not read %s.%s to put in the snapshot",
                                    key, name)
                        continue

                if hasattr(value, "value"):        # an enum
                    value = value.value
                elif hasattr(value, "isoformat"):  # a date
                    value = value.isoformat()

                row[name] = value
            rows.append(row)
        out["tables"][key] = rows

    out["users"] = _capture_users(session)

    # Sign-in settings (OIDC etc.) belong to the fleet.  Without them a
    # promoted standby with local passwords disabled can't be logged in to.
    from app.core import settings_store
    out["settings"] = settings_store.capture_fleet()

    return out


def _capture_users(session) -> list:
    """
    Accounts, fleet-wide fields only.  Lockout counters and last login stay
    local so a failed login on one node can't lock the account on another.
    """
    rows = []
    for user in session.query(User).all():
        row = {}
        for name in USER_FLEET_COLUMNS:
            value = getattr(user, name, None)

            if name in SECRET_COLUMNS and value:
                value = decrypt(value)
                if value is None:
                    log.warning("could not read the totp secret for %s to put in "
                                "the snapshot", user.username)
                    continue

            if hasattr(value, "value"):
                value = value.value
            elif hasattr(value, "isoformat"):
                value = value.isoformat()

            row[name] = value
        rows.append(row)
    return rows


def _restore_users(session, rows) -> dict:
    """
    Merge accounts by username (see the module docstring for why).

    A username missing from the snapshot is deleted here, which is what
    makes revoking access work everywhere, and why the admin guard exists.
    """
    if rows is None:
        # Snapshot from an older version.  Leave accounts alone.
        return {"skipped": "this snapshot has no accounts in it"}

    incoming = {r.get("username"): r for r in rows if r.get("username")}

    # Refuse anything that would leave no enabled admin anywhere.
    has_admin = any(
        r.get("enabled") and str(r.get("role")) in ("admin", str(UserRole.ADMIN.value))
        for r in incoming.values()
    )
    if not has_admin:
        log.error("refusing to take accounts from a snapshot with no enabled admin "
                  "in it, keeping the ones this node already has")
        return {"refused": "that snapshot had no enabled admin account in it"}

    existing = {u.username: u for u in session.query(User).all()}
    added = updated = removed = 0

    for username, row in incoming.items():
        user = existing.get(username)
        if user is None:
            user = User(username=username)
            session.add(user)
            added += 1
        else:
            updated += 1

        for name, value in row.items():
            if name == "username" or name not in USER_FLEET_COLUMNS:
                continue
            if name in SECRET_COLUMNS and value:
                value = encrypt(value)
            setattr(user, name, _coerce(User, name, value))

    for username, user in existing.items():
        if username not in incoming:
            # The cascade removes their sessions too, so an existing cookie
            # stops working.
            session.delete(user)
            removed += 1

    session.flush()
    return {"added": added, "updated": updated, "removed": removed}


def restore(session, data: dict) -> dict:
    """
    Put the objects back from a snapshot.

    Tables are replaced, not merged, so there's never a mix of old and new
    config.  Returns row counts so the caller can log what was restored.
    """
    tables = (data or {}).get("tables") or {}
    if not tables:
        raise ValueError("that snapshot has no tables in it")

    written = {}

    # Only replace tables the snapshot carries.  A snapshot from older code
    # won't know about newer tables, and clearing those would silently lose
    # config during a rolling upgrade.  A present but empty table is still
    # replaced, which is how deleting the last row travels.
    present = [(key, model) for key, model in TABLES if key in tables]
    absent = [key for key, _model in TABLES if key not in tables]
    if absent:
        log.warning("this snapshot says nothing about %s, so those are left "
                    "alone.  It came from a node running older code.",
                    ", ".join(absent))

    # Clear in reverse order so children go before their parents.
    for key, model in reversed(present):
        session.query(model).delete()
    session.flush()

    for key, model in present:
        rows = tables.get(key) or []
        known = set(_columns(model))
        for row in rows:
            values = {}
            for name, value in row.items():
                if name not in known:
                    # Snapshot from a newer version.  Skip the column rather
                    # than refuse the whole restore.
                    continue
                if name in SECRET_COLUMNS and value:
                    value = encrypt(value)
                values[name] = _coerce(model, name, value)
            session.add(model(**values))
        written[key] = len(rows)
        session.flush()

    # Accounts are merged, not replaced, so they get their own path.
    written["users"] = _restore_users(session, (data or {}).get("users"))

    session.commit()

    # Sign-in settings live in a key/value table, so they go separately.
    # Only written if present; as with tables, absent means leave alone.
    if "settings" in (data or {}):
        from app.core import settings_store
        written["settings"] = settings_store.restore_fleet(data.get("settings"))

    log.warning("restored the config from a snapshot: %s",
                ", ".join(f"{k}={v}" for k, v in written.items() if v))
    return written


def capture_users(session) -> list:
    """
    Just the accounts, for the periodic sync.  Full snapshots only travel
    when the rendered nginx config changes, and a password change doesn't
    change nginx config.
    """
    return _capture_users(session)


def restore_users(session, rows) -> dict:
    """Take on a set of accounts.  See `_restore_users` for the rules."""
    return _restore_users(session, rows)


GSLB_TABLES = ("gslb_zones", "gslb_records", "gslb_answers")


def capture_gslb(session) -> dict:
    """
    Just the DNS zones, for the periodic sync.

    Zones render no nginx config (our own listener answers them), so a full
    snapshot never fires for a zone change.  Without this sync, zone edits
    would never reach the other nameserver.
    """
    out = {}
    for key, model in TABLES:
        if key not in GSLB_TABLES:
            continue
        rows = []
        for obj in session.query(model).all():
            row = {}
            for name in _columns(model):
                value = getattr(obj, name, None)
                if hasattr(value, "value"):
                    value = value.value
                elif hasattr(value, "isoformat"):
                    value = value.isoformat()
                row[name] = value
            rows.append(row)
        out[key] = rows
    return out


def restore_gslb(session, tables: dict, sender_has_config: bool = True) -> dict:
    """
    Replace the fleet's DNS zones.  Children are deleted first and parents
    inserted first.

    An empty set is normally applied so deleting the last zone works.  It is
    refused when the sender has no config at all (sender_has_config False),
    since that looks like a blank standby that won an election rather than
    someone deleting a zone.
    """
    incoming = {k: (tables.get(k) or []) for k in GSLB_TABLES}
    models = dict(TABLES)

    have = session.query(models["gslb_zones"]).count()
    if have and not incoming["gslb_zones"] and not sender_has_config:
        return {"refused": (
            f"this node has {have} dns zone(s) and the set that arrived is "
            f"empty, from a node that has no config objects at all, which is "
            f"what a standby that came up blank looks like rather than "
            f"somebody deleting a zone.  Nothing was changed."
        )}

    written = {}
    for key in reversed(GSLB_TABLES):          # answers, records, zones
        session.query(models[key]).delete()
    session.flush()

    for key in GSLB_TABLES:                    # zones, records, answers
        model = models[key]
        allowed = set(_columns(model))
        for row in incoming[key]:
            session.add(model(**{k: _coerce(model, k, v)
                                 for k, v in row.items() if k in allowed}))
        session.flush()
        written[key] = len(incoming[key])
    return {"written": written}


def is_empty(session) -> bool:
    """
    Does this node have no config of its own.  Checked by a promoted standby
    before restoring.  Sites and pools only, since zones and access lists can
    legitimately be empty.
    """
    return (session.query(VirtualHost).count() == 0
            and session.query(Pool).count() == 0)
