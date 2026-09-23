"""
Database setup.

We use sqlite on purpose.  Every node keeps its own full copy of the config and
the nodes sync to each other, so there is no shared database to lose.  Adding
postgres would mean one more thing that has to be up for your load balancers to
be manageable, and that is exactly backwards.  If the database server is down
you still need to get in and fix nginx.
"""

import logging
from contextlib import contextmanager

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models import Base

log = logging.getLogger("nfm.db")

_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is not None:
        return _engine

    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    _engine = create_engine(
        settings.db_url,
        # sqlite normally refuses to be used from a thread other than the one
        # that opened it.  We hand connections around between the web workers
        # and the background jobs, and the pool below already keeps two threads
        # off the same connection, so this check is just in the way.
        connect_args={"check_same_thread": False, "timeout": 30},
        pool_pre_ping=True,
        echo=False,
    )

    @event.listens_for(_engine, "connect")
    def _set_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()

        # WAL lets readers keep reading while somebody writes.  Without it the
        # health checker writing member state blocks every page load, and the
        # GUI feels broken even though nothing is actually wrong.
        cur.execute("PRAGMA journal_mode=WAL")

        # NORMAL still survives a process crash.  FULL also survives the power
        # going out, but it fsyncs on every commit, and the health checker
        # commits constantly.  The database is a cache of state we can rebuild
        # from the peers anyway, so the trade is worth it.
        cur.execute("PRAGMA synchronous=NORMAL")

        # Foreign keys are off by default in sqlite, which surprises everybody.
        # Without this our ondelete rules quietly do nothing.
        cur.execute("PRAGMA foreign_keys=ON")

        # Wait instead of instantly failing when another writer has the lock.
        cur.execute("PRAGMA busy_timeout=30000")

        cur.execute("PRAGMA temp_store=MEMORY")
        cur.close()

    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            expire_on_commit=False,
        )
    return _SessionFactory


@contextmanager
def session_scope():
    """
    A session that commits if things went fine and rolls back if they did not.

    Use this everywhere instead of making sessions by hand.  It is the one
    place that guarantees a failed request cannot leave half a change behind.
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db():
    """FastAPI dependency version of the same thing."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def ensure_schema():
    """
    Add any columns the models have that the database does not.

    create_all only makes tables that are missing.  It looks at an existing
    table, sees the name is there, and moves on without checking the columns.
    So adding a field to a model does nothing at all to a database that already
    exists, and the first query touching it dies with "no such column".

    On a fresh install nobody notices, because the table gets created complete.
    It only shows up when somebody upgrades, which is the worst time to find it.

    This walks the models, compares them to what is really there, and adds what
    is missing.  Additive only, on purpose:

      - a new column is safe and is what almost every change actually is
      - renaming, dropping or retyping a column needs a decision about the data
        in it, and quietly guessing is how you lose somebody's config

    Anything beyond adding a column wants a real migration written by hand.  If
    that day comes, alembic is already in the requirements.
    """
    engine = get_engine()
    added = []

    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            rows = conn.execute(text(f"PRAGMA table_info({table.name})")).fetchall()
            if not rows:
                # No such table yet.  create_all handles that case.
                continue

            existing = {r[1] for r in rows}

            for column in table.columns:
                if column.name in existing:
                    continue

                # sqlite will not add a column that is NOT NULL without a
                # default, because it has no idea what to put in the rows that
                # are already there.  Nothing we would add fits that shape, but
                # skip it loudly rather than blowing up on startup.
                ddl_type = column.type.compile(engine.dialect)
                parts = [f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {ddl_type}']

                default = column.default
                if default is not None and getattr(default, "is_scalar", False):
                    value = default.arg
                    if isinstance(value, bool):
                        parts.append(f"DEFAULT {1 if value else 0}")
                    elif isinstance(value, (int, float)):
                        parts.append(f"DEFAULT {value}")
                    elif isinstance(value, str):
                        escaped = value.replace("'", "''")
                        parts.append(f"DEFAULT '{escaped}'")
                elif not column.nullable:
                    log.error(
                        "cannot add %s.%s automatically, it is NOT NULL with no default",
                        table.name, column.name,
                    )
                    continue

                statement = " ".join(parts)
                try:
                    conn.execute(text(statement))
                    added.append(f"{table.name}.{column.name}")
                except Exception as exc:
                    log.error("could not add %s.%s: %s", table.name, column.name, exc)

        conn.commit()

    if added:
        log.warning("added missing columns to the database: %s", ", ".join(added))


def pin_existing_tls_versions():
    """
    Write down what existing sites already serve, before the default moves.

    New sites now default to TLS 1.3 only, which is what makes the post quantum
    key exchange the normal case rather than something somebody has to know to
    ask for.  X25519MLKEM768 is a 1.3 group; leave 1.2 on and a client that
    prefers it never gets near it.

    The danger is entirely in the sites that already exist.  A site that never
    set a version renders from a fallback, so moving that fallback would drop
    TLS 1.2 from every one of them on the next apply, on sites nobody touched,
    breaking whichever old clients they were quietly still serving, with no
    change anybody made to point at.

    So this pins them first.  Every site with no explicit setting gets the pair
    it is serving today written down, and after that the default can move
    without touching a single existing site.  Idempotent, and it does nothing
    at all on a fresh install because there is nothing to pin.
    """
    from app.models import VirtualHost, json_get, json_set

    engine = get_engine()
    pinned = 0

    with Session(engine) as session:
        for host in session.query(VirtualHost).all():
            settings = json_get(host.settings, {})
            if "ssl_protocols" in settings:
                continue
            settings["ssl_protocols"] = ["TLSv1.2", "TLSv1.3"]
            host.settings = json_set(settings)
            pinned += 1
        if pinned:
            session.commit()

    if pinned:
        log.warning("pinned the TLS versions on %d existing sites, so the new "
                    "1.3 only default changes nothing they already serve", pinned)


def pin_existing_security_headers():
    """
    Write down the security headers existing sites already serve.

    Same shape as pin_existing_tls_versions above, and the same reason.

    X-Frame-Options and Referrer-Policy are dropdowns whose "do not send the
    header" option is the empty string, and the GUI does not send an empty
    value: it reads it as the setting having been cleared and leaves the key
    out.  The renderer used to fall back to SAMEORIGIN and
    strict-origin-when-cross-origin when the key was missing, so choosing not to
    send either header stored nothing, rendered the default, and the header was
    back on the next apply.  Neither could be turned off at all.

    The fix is for a missing key to mean no header, which is what the person
    choosing that option is asking for.  The danger is entirely in the sites
    that already exist: every one of them is missing both keys and is serving
    both headers from the fallback, so moving it would quietly strip two
    security headers off the whole fleet on the next apply, on sites nobody
    touched.

    So they get written down first, from the catalog, which is where the old
    fallback values came from.  After that the fallback can mean nothing without
    changing a single existing site.  Idempotent, and it does nothing on a fresh
    install because there is nothing to pin.
    """
    from app.catalog import get_feature
    from app.models import VirtualHost, json_get, json_set

    engine = get_engine()
    pinned = 0

    with Session(engine) as session:
        for host in session.query(VirtualHost).all():
            settings = json_get(host.settings, {})
            changed = False
            for key in ("x_frame_options", "referrer_policy"):
                if key in settings:
                    continue
                feature = get_feature(key)
                if feature is None:          # a key retired from the catalog
                    continue
                settings[key] = feature.default
                changed = True
            if changed:
                host.settings = json_set(settings)
                pinned += 1
        if pinned:
            session.commit()

    if pinned:
        log.warning("pinned the security headers on %d existing sites, so an "
                    "absent setting can now mean the header is off without "
                    "changing what they already serve", pinned)


def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
    ensure_schema()
    pin_existing_tls_versions()
    pin_existing_security_headers()

    with engine.connect() as conn:
        conn.execute(text("PRAGMA optimize"))
        conn.commit()

    log.info("database ready at %s", get_settings().db_path)


def vacuum():
    """
    Tidy up the database file.

    The health events and audit rows pile up.  Deleting old ones frees pages
    inside the file but does not shrink the file itself, so we run this after
    the cleanup job.
    """
    engine = get_engine()
    with engine.connect() as conn:
        conn.execute(text("VACUUM"))
        conn.commit()
