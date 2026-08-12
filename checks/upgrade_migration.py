"""
Upgrade a database that was made by an older version, and check nothing is lost.

This is the one piece of code that a fresh install never runs.  Every install we
have ever tested created its tables complete, so the path that adds a missing
column to an existing table has only ever executed on somebody else's box, on
the day they upgraded, with their config in it.

So this makes a database the way an older version would have, upgrades it, and
looks at what happened to the rows that were already there.

Done on a copy in a temporary folder.  The real database is never opened for
writing, and the copy is deleted at the end whether this passes or not.

    docker exec -i nginx-fleet-manager python < checks/upgrade_migration.py
"""
import os
import shutil
import sqlite3
import sys
import tempfile

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")


# Columns added over the life of this project, newest first.  An older database
# is simulated by dropping these back out again, which is as close as we can get
# to what an install from before them actually looked like.
RECENT = {
    "config_versions": ["user_checksum"],
    "certificates": ["dns_ok", "dns_warning", "dns_checked_at"],
    "pools": ["backend_kind", "backend_tls", "backend_tls_set",
              "backend_tls_verify", "backend_tls_ca", "backend_tls_name"],
}


def older_copy(source, folder):
    """
    A copy of the database with the newer columns taken back out.

    sqlite cannot drop a column on older versions, so the table is rebuilt
    without them, which is also what an older schema genuinely looked like.
    """
    path = os.path.join(folder, "fleet.db")
    shutil.copy(source, path)

    conn = sqlite3.connect(path)
    removed = {}
    for table, columns in RECENT.items():
        present = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        keep = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")
                if r[1] not in columns]
        dropping = [c for c in columns if c in present]
        if not dropping:
            continue
        joined = ", ".join(f'"{c}"' for c in keep)
        conn.execute(f"CREATE TABLE _old AS SELECT {joined} FROM {table}")
        conn.execute(f"DROP TABLE {table}")
        conn.execute(f"ALTER TABLE _old RENAME TO {table}")
        removed[table] = dropping
    conn.commit()
    conn.close()
    return path, removed


def main():
    live = "/data/fleet.db"
    if not os.path.exists(live):
        print("    no database to copy, run this on a node that has one")
        return 1

    folder = tempfile.mkdtemp(prefix="upgrade-check-")
    try:
        path, removed = older_copy(live, folder)
        print("  built a database the shape an older version would have made")
        for table, columns in removed.items():
            print(f"    {table}: took out {', '.join(columns)}")
        if not removed:
            print("    nothing to take out, so this proved nothing.  Update RECENT.")
            return 1

        # What was in it before the upgrade, so we can prove it survived.
        conn = sqlite3.connect(path)
        before = {}
        for table in ("pools", "virtual_hosts", "certificates", "users", "nodes"):
            try:
                before[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error:
                before[table] = None
        pool_names = [r[0] for r in conn.execute("SELECT name FROM pools ORDER BY name")]
        conn.close()

        print()
        print("  running the upgrade against it")
        os.environ["NFM_DATA_DIR"] = folder

        # The engine is built once and cached, so it has to be reset or the
        # upgrade runs against the real database instead of the copy.  Getting
        # this wrong would migrate the live fleet, which is exactly the thing
        # this check must never do.
        import app.db as db
        db._engine = None
        db._SessionFactory = None
        from app.config import get_settings
        get_settings.cache_clear()

        engine = db.get_engine()
        url = str(engine.url)
        if folder not in url:
            check("the upgrade ran against the copy, not the live database", False,
                  f"engine points at {url}, refusing to go on")
            return 1
        check("the upgrade ran against the copy, not the live database", True)

        db.init_db()

        print()
        print("  what the upgrade did")
        conn = sqlite3.connect(path)
        for table, columns in removed.items():
            now = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            missing = [c for c in columns if c not in now]
            check(f"{table} got its columns back", not missing,
                  f"still missing: {missing}")

        after = {}
        for table in before:
            try:
                after[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error:
                after[table] = None
        names_after = [r[0] for r in conn.execute("SELECT name FROM pools ORDER BY name")]
        conn.close()

        for table, count in before.items():
            check(f"{table} still has its {count} row(s)", after.get(table) == count,
                  f"was {count}, now {after.get(table)}")

        check("the pools are still the same pools", names_after == pool_names,
              f"was {pool_names}, now {names_after}")

        print()
        print("  and it is safe to run twice, which is what a restart does")
        db.init_db()
        conn = sqlite3.connect(path)
        second = [r[0] for r in conn.execute("SELECT name FROM pools ORDER BY name")]
        conn.close()
        check("running it again changes nothing", second == pool_names,
              f"was {pool_names}, now {second}")

    finally:
        shutil.rmtree(folder, ignore_errors=True)
        os.environ.pop("NFM_DATA_DIR", None)

    print()
    failed = [name for name, ok, _ in results if not ok]
    print(f"  {len(results) - len(failed)} of {len(results)} passed")
    print()
    print("  what this does not cover:")
    print("    - an upgrade that needs a column renamed or retyped, which is")
    print("      deliberately not automatic and wants a migration written by hand")
    print("    - the container image changing under a running fleet")
    print()
    print("  RESULT:", "an older database upgrades cleanly" if not failed
          else f"{len(failed)} PROBLEMS: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
