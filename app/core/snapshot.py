"""
The whole config as data, so a node that was a standby can carry on being useful.

A standby holds the rendered files but not the objects they came from, because
config objects only ever lived on the active node.  That is fine right up until
the active node goes away.  The survivor is promoted, has nothing to render
from, and cannot change anything.  Before the guard in cluster.py it did worse
than that: it rendered an empty config and applied it over the top of what it
was serving.

So every apply now carries the objects alongside the files, and a promoted node
that finds itself with none puts them back from the newest one it was given.

Columns are read off the models rather than listed here.  A list would be one
more place to remember when somebody adds a column, and the failure mode is a
setting that silently does not survive a failover, which is the worst kind of
thing to find out during one.

## Secrets

Pool tokens and uploaded private keys are encrypted with the node's own secret
key, and every node has a different one, so the stored form is meaningless to
anybody else.  They are decrypted on the way out and encrypted again on the way
in, with each node using its own key.

That means the plain values cross the peer link.  This is the same trade the
certificate replication already makes, and for the same reason: the link is
mutual TLS between two nodes holding certificates from the same private CA, with
a signature on every message.  A pool token that does not survive a failover is
a backend that starts refusing traffic the moment the standby takes over, which
is a worse outcome than sending it over a channel we already trust with private
keys.

Peer HMAC keys are not here.  Those belong to the node rather than to the
config, and a standby has its own.

## Accounts

Accounts travel too, and they did not used to, which was a security bug rather
than a missing feature.  Every node kept the admin it was installed with and
nothing since, so a password changed on the active node left the standby on the
install password, an operator added after setup did not exist on the standby at
all, and an account taken away on the active node was still live on the standby
and came back the moment it was promoted.  Revoking somebody's access has to
revoke it everywhere.

Accounts are merged by username rather than replaced wholesale, which is the one
place this module does not simply swap a table out.  Three reasons:

- Sessions hang off users with a cascading delete.  Replacing the rows would end
  every session on the receiving node on every apply, which logs people out of a
  healthy box for no reason.
- Lockout counters and last login belong to the box that saw the attempt.  A
  node should not forget that somebody is part way through guessing a password
  because a config change happened to arrive, and it should not import another
  node's lockout either.
- Ids stay put, so anything holding a user id keeps pointing at the same person.

TOTP seeds do travel, and that is a change of mind.  Leaving them behind meant a
person with TOTP required on their account could not log in at all after a
failover, which is a lockout dressed up as a security measure.  They are
encrypted per node, so they are decrypted on the way out and encrypted again on
the way in, the same as the pool tokens above.  Recovery codes are already
hashed and travel as they are.

There is one guard.  A snapshot carrying no enabled admin is refused outright,
and the accounts on the receiving node are left exactly as they were.  Nothing
else in here can lock every person out of every box at once, so nothing else
needs it.
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
    # The tuned firewall profiles, before the sites that point at them.  These
    # are the expensive thing in the whole system to recreate: somebody
    # exercised an application, watched what the rules said about it and
    # decided which of those were wrong.  A restore that quietly dropped them
    # would leave every site pointing at a profile that no longer exists.
    ("waf_profiles", WafProfile),
    ("waf_exclusions", WafExclusion),
    # The positive model, alongside the exclusions and for the same reason.
    # A standby that inherits the exclusions and not the surface would come up
    # after a promotion with a site set to enforce and nothing allowed, which
    # is every request refused.
    ("waf_surface_entries", WafSurfaceEntry),
    ("pools", Pool),
    ("pool_members", PoolMember),
    ("hosts", VirtualHost),
    ("locations", Location),
    # After the sites, since a watch belongs to one.  It travels because a
    # standby that inherited the sites and not the thresholds would come up
    # after a promotion watching nothing, and nobody would notice until the
    # week nothing was reported.
    ("login_watches", LoginWatch),
    # After the sites, since a session belongs to one.  Kept rather than
    # treated as scratch, because a profile's provenance points back at the
    # session it came from and an exclusion nobody can explain is one nobody
    # will dare remove.
    ("waf_sessions", WafSession),
    ("streams", StreamServer),
    # Parents before children, because a restore replays this in order and a
    # record with no zone to hang off is dropped.
    ("gslb_zones", GslbZone),
    ("gslb_records", GslbRecord),
    ("gslb_answers", GslbAnswer),
    # The network before its peers, same reason as the zones above.
    ("tunnel_networks", TunnelNetwork),
    ("tunnel_peers", TunnelPeer),
]

# Encrypted at rest with a key that belongs to one node, so they have to be
# turned back into plain values to travel and re-sealed at the other end.
SECRET_COLUMNS = {
    "token_encrypted",
    "token_next_encrypted",
    "token_previous_encrypted",
    "dns_credentials_encrypted",
    "eab_hmac_key_encrypted",
    "uploaded_privkey_encrypted",
    # The tunnel pre-shared keys.  Both ends of a WireGuard peering have to
    # hold the same one, so a standby that inherited the peer list without
    # these would refuse every workload the moment it was promoted.
    "psk_encrypted",
    "totp_secret_encrypted",
}

# What an account is, fleet wide.  Anything not in here belongs to the box that
# saw it happen and is left alone on the receiving node.
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

    Dates come out of json as strings and sqlite will not take a string for a
    DateTime, which is how the first version of this failed: the restore threw
    on the first row and a promoted node was left with nothing, having been told
    the config was on its way.

    Enums are handed back as their value and SQLAlchemy maps those itself, so
    they need nothing here.
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
            # A date we cannot read is not worth failing a whole failover for.
            # These are all "when did this last happen" fields, so losing one
            # costs a timestamp in the GUI and nothing else.
            log.warning("could not read %s.%s as a date, leaving it empty", model.__name__, name)
            return None

    if kind == "Boolean" and isinstance(value, int):
        return bool(value)

    return value


def capture(session) -> dict:
    """
    Every config object, as plain data.

    Ids are kept.  They are what sites point at pools with, and a restore that
    renumbered them would quietly re-point half the config.
    """
    out = {"version": 1, "tables": {}}

    for key, model in TABLES:
        rows = []
        for obj in session.query(model).all():
            row = {}
            for name in _columns(model):
                value = getattr(obj, name, None)

                if name in SECRET_COLUMNS and value:
                    # Unsealed here, sealed again with the far node's own key.
                    value = decrypt(value)
                    if value is None:
                        # Undecryptable here means the key changed under us.
                        # Sending nothing beats sending something the other end
                        # will store and never be able to read.
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

    # How people sign in, which belongs to the fleet and not to one box.
    #
    # Left out until it was needed, and the gap only shows on the day it costs
    # most: the identity provider is set on the active node, the active node
    # goes away, and the standby that takes over knows nothing about it.  With
    # local passwords switched off that is a fleet nobody can sign in to.
    from app.core import settings_store
    out["settings"] = settings_store.capture_fleet()

    return out


def _capture_users(session) -> list:
    """
    Accounts, with only the parts that belong to the fleet.

    Lockout counters and last login are left out on purpose.  They describe what
    one box saw rather than who somebody is, and sending them would let a failed
    login on one node lock an account out on another.
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
    Bring accounts into line, matching on username.

    Merged rather than replaced.  See the note at the top of this module for
    why: sessions cascade off users, and lockout counters belong to the box.

    Deletions are the whole point of this, so a username missing from the
    snapshot is removed here.  That is what makes revoking access actually
    revoke it, and it is why the guard below exists.
    """
    if rows is None:
        # A snapshot from a version that predates this.  Leaving accounts alone
        # is the only safe reading of "the sender said nothing about users".
        return {"skipped": "this snapshot has no accounts in it"}

    incoming = {r.get("username"): r for r in rows if r.get("username")}

    # The one thing that could lock every person out of every box at once.
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
            # Gone on the node that owns the config, so gone here.  The cascade
            # takes their sessions with them, which is the point: an account
            # taken away should not still be able to use a cookie it already has.
            session.delete(user)
            removed += 1

    session.flush()
    return {"added": added, "updated": updated, "removed": removed}


def restore(session, data: dict) -> dict:
    """
    Put the objects back from a snapshot.

    Everything is replaced, not merged.  A half restored config is worse than
    none: merging would leave whatever this node happened to have alongside what
    it was given, and nobody could say which of the two is being served.

    Gives back what it wrote, so the caller can log it and a person can see that
    a failover actually carried the config across.
    """
    tables = (data or {}).get("tables") or {}
    if not tables:
        raise ValueError("that snapshot has no tables in it")

    written = {}

    # Only tables the snapshot actually carries are replaced.  A table the
    # sender said nothing about is left exactly as it is.
    #
    # Clearing everything in TABLES was silent data loss during any rolling
    # upgrade.  A node on new code takes a snapshot from a node on old code,
    # that snapshot has no key for a table the old code did not know about, the
    # loop below writes nothing for it, and the clear above has already emptied
    # it.  The config is gone, the apply reports success, and the only sign is
    # a table that is quietly empty on one node.
    #
    # This is not a merge and does not become one.  A table that is present is
    # still replaced outright, including a present but empty one, which is how
    # deleting the last row still travels.  The difference is only between
    # "here is nothing" and "I did not mention it".
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
                    # A snapshot from a newer version.  Skip the column rather
                    # than refuse the whole restore, since the alternative is a
                    # node that cannot take over at all.
                    continue
                if name in SECRET_COLUMNS and value:
                    value = encrypt(value)
                values[name] = _coerce(model, name, value)
            session.add(model(**values))
        written[key] = len(rows)
        session.flush()

    # Accounts last, and by their own route.  They are merged rather than
    # replaced, so they cannot ride along with the loop above.
    written["users"] = _restore_users(session, (data or {}).get("users"))

    session.commit()

    # Sign in settings, after the commit and by their own route, because they
    # live in a key and value table rather than in one of the models above.
    #
    # Only written when the snapshot actually carries them.  A snapshot from a
    # node on older code says nothing about them, and "said nothing" has to
    # keep meaning "leave it alone" here for the same reason it does for the
    # tables: the alternative is a rolling upgrade quietly clearing how the
    # fleet signs in.
    if "settings" in (data or {}):
        from app.core import settings_store
        written["settings"] = settings_store.restore_fleet(data.get("settings"))

    log.warning("restored the config from a snapshot: %s",
                ", ".join(f"{k}={v}" for k, v in written.items() if v))
    return written


def capture_users(session) -> list:
    """
    Just the accounts, for the sync that does not wait on a config change.

    Accounts ride along in the full snapshot too, which covers a node being
    promoted or catching up.  It cannot be the only route though: a snapshot only
    travels when the rendered nginx config changes, and changing a password does
    not change a line of nginx config.  Without this an account change would sit
    on one node until somebody happened to edit a site.
    """
    return _capture_users(session)


def restore_users(session, rows) -> dict:
    """Take on a set of accounts.  See `_restore_users` for the rules."""
    return _restore_users(session, rows)


GSLB_TABLES = ("gslb_zones", "gslb_records", "gslb_answers")


def capture_gslb(session) -> dict:
    """
    Just the DNS zones, for the sync that does not wait on a config change.

    Same reasoning as the accounts above, and the consequence is worse.  Zones
    ride along in the full snapshot, and a full snapshot only travels when the
    **rendered nginx config** changes.  A zone renders no nginx config at all:
    it is answered by the manager's own listener, not by nginx.  So a zone
    could be created, edited or deleted and never reach the other node, and the
    fleet would look like it had two nameservers while it had one.

    That is the whole point of global load balancing, so it has to converge on
    its own timer rather than on somebody happening to edit a site.
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
    Take on the fleet's DNS zones.

    Replaces rather than merges, and the order matters both ways: children go
    before parents on the way out, parents before children on the way in, or a
    record is left pointing at a zone that is not there yet.

    Deleting the last zone has to work, so an empty set is normally applied.
    The one case it is refused is the promoted standby with nothing in it: a
    node that came up empty, won an election and pushed its emptiness would
    take the fleet's DNS away, which is the same accident the mass deletion
    guard exists for on the sites side.

    Those two are told apart by `sender_has_config`, which the sender fills in
    from whether it has any config objects at all.  A node deleting its last
    zone still has sites and pools; a node that came up with nothing has none
    of it.
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
    Has this node got no config of its own.

    The question a promoted standby asks before deciding whether to put a
    snapshot back.  Sites and pools only: zones and access lists can legitimately
    be empty on a working fleet, so counting them would call a real config empty.
    """
    return (session.query(VirtualHost).count() == 0
            and session.query(Pool).count() == 0)
