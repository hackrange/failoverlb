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

TOTP seeds and peer HMAC keys are not here.  Those belong to the node and the
person, not to the config, and a standby has its own.
"""
import logging
from datetime import datetime

from app.core.crypto import decrypt, encrypt
from app.models import (
    AccessList,
    CacheZone,
    Certificate,
    ConnLimitZone,
    Location,
    MapBlock,
    Pool,
    PoolMember,
    RateLimitZone,
    StreamServer,
    VirtualHost,
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
    ("certificates", Certificate),
    ("pools", Pool),
    ("pool_members", PoolMember),
    ("hosts", VirtualHost),
    ("locations", Location),
    ("streams", StreamServer),
]

# Encrypted at rest with a key that belongs to one node, so they have to be
# turned back into plain values to travel and re-sealed at the other end.
SECRET_COLUMNS = {
    "token_encrypted",
    "token_next_encrypted",
    "token_previous_encrypted",
    "dns_credentials_encrypted",
    "uploaded_privkey_encrypted",
}


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

    return out


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

    # Clear in reverse order so children go before their parents.
    for key, model in reversed(TABLES):
        session.query(model).delete()
    session.flush()

    for key, model in TABLES:
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

    session.commit()
    log.warning("restored the config from a snapshot: %s",
                ", ".join(f"{k}={v}" for k, v in written.items() if v))
    return written


def is_empty(session) -> bool:
    """
    Has this node got no config of its own.

    The question a promoted standby asks before deciding whether to put a
    snapshot back.  Sites and pools only: zones and access lists can legitimately
    be empty on a working fleet, so counting them would call a real config empty.
    """
    return (session.query(VirtualHost).count() == 0
            and session.query(Pool).count() == 0)
