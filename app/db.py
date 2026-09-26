"""
Database setup.

SQLite on purpose: every node keeps a full copy of the config and the nodes
sync to each other, so there is no shared database server that has to be up
before you can fix nginx.
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
        # Connections move between web workers and background jobs; the
        # pool already keeps two threads off one connection.
        connect_args={"check_same_thread": False, "timeout": 30},
        pool_pre_ping=True,
        echo=False,
    )

    @event.listens_for(_engine, "connect")
    def _set_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()

        # WAL so the health checker's writes do not block page loads.
        cur.execute("PRAGMA journal_mode=WAL")

        # NORMAL survives a process crash but not power loss. FULL would
        # fsync on every health checker commit, and the state can be rebuilt
        # from peers anyway.
        cur.execute("PRAGMA synchronous=NORMAL")

        # Off by default in sqlite; without it ondelete rules do nothing.
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
    """Session that commits on success and rolls back on error.

    Prefer this to making sessions by hand so a failure never leaves half a
    change behind.
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
    """FastAPI dependency that yields a session."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def ensure_schema():
    """Add columns the models have that an existing database lacks.

    create_all only creates missing tables, never missing columns, so without
    this a new model field breaks upgraded installs with "no such column".

    Additive only on purpose. Renaming, dropping or retyping a column needs a
    decision about the data and should be a hand-written migration (alembic
    is already in the requirements).
    """
    engine = get_engine()
    added = []

    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            rows = conn.execute(text(f"PRAGMA table_info({table.name})")).fetchall()
            if not rows:
                # Table does not exist yet; create_all handles it.
                continue

            existing = {r[1] for r in rows}

            for column in table.columns:
                if column.name in existing:
                    continue

                # sqlite cannot add a NOT NULL column without a default.
                # Skip those with an error rather than failing startup.
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
    """Pin TLS 1.2 + 1.3 on existing sites that never set a version.

    New sites default to TLS 1.3 only so the post quantum group
    (X25519MLKEM768, 1.3 only) is the normal case. Sites without an explicit
    setting render from the fallback, so changing it would silently drop
    TLS 1.2 from untouched sites on the next apply. Idempotent; a no-op on a
    fresh install.
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
    """Pin X-Frame-Options and Referrer-Policy on existing sites.

    Same idea as pin_existing_tls_versions. The GUI omits the key when "do
    not send" is chosen, and the renderer used to fill in a default for a
    missing key, so neither header could be turned off. A missing key now
    means no header, so existing sites get the old catalog defaults written
    down first or they would lose both headers on the next apply.
    Idempotent; a no-op on a fresh install.
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
    """Shrink the file after the cleanup job deletes old rows."""
    engine = get_engine()
    with engine.connect() as conn:
        conn.execute(text("VACUUM"))
        conn.commit()
