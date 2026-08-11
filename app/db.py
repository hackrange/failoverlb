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
from sqlalchemy.orm import sessionmaker

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


def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)

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
