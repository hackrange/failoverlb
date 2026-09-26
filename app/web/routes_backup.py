"""
Taking a backup out of the system, and putting one back in.

Both halves ask for the password again.  Not as ceremony: the archive is
encrypted with it, and the only copy this system holds is a hash, so there is
no way to build or open one without being told.  That it also proves whoever
is at the keyboard is the account they are logged in as is a happy side
effect, and a welcome one for an operation that hands out every private key
the fleet owns.
"""
import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response

from app.auth.service import verify_password
from app.config import get_settings
from app.core import audit, backup
from app.db import session_scope
from app.models import utcnow
from app.web.routes_api import ObjectGuard, changing, guard

log = logging.getLogger("nfm.backup.web")

router = APIRouter()

# A backup is every key the fleet has.  Anything less than the top role reading
# one is a way around every other permission in the system.
NEEDED = "manage_cluster"

# Enough for a fleet's configuration many times over, and small enough that an
# upload cannot be used to fill the disk.
MAX_ARCHIVE = 64 * 1024 * 1024


def _check_password(user, password: str):
    if not password:
        raise HTTPException(status_code=400,
                            detail="your password is what encrypts the backup")
    if not verify_password(user.password_hash, password):
        # Deliberately the same wording as signing in.  There is nothing to be
        # gained by telling somebody which half they got wrong.
        raise HTTPException(status_code=403, detail="that password is not right")


@router.post("/api/backup/export")
async def export_backup(request: Request, g: ObjectGuard = Depends(guard)):
    """Everything, as one encrypted zip, streamed straight back."""
    g.require(NEEDED)

    payload = await request.json()
    password = str(payload.get("password") or "")
    _check_password(g.user, password)

    settings = get_settings()
    with session_scope() as session:
        blob, summary = await backup.build(session, password,
                                           node_name=settings.node_name)

    stamp = utcnow().strftime("%Y-%m-%d-%H%M")
    name = f"failover-lb-backup-{stamp}.zip"

    audit.record("backup.export", user=g.user, object_type="backup",
                 object_name=name)
    log.info("%s took a backup, %s", g.user.username, summary.get("counts"))

    return Response(
        content=blob,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            # So the page can say what went in without opening the file it
            # just downloaded.
            "X-Backup-Summary": str(summary.get("counts")),
        },
    )


@router.post("/api/backup/inspect")
async def inspect_backup(file: UploadFile = File(...), password: str = Form(...),
                         g: ObjectGuard = Depends(guard)):
    """
    What is in an archive, without putting any of it back.

    Restoring replaces a working configuration, so there is a step in between
    where somebody can see what they are about to overwrite it with, and find
    out here rather than afterwards that they have the wrong file or the wrong
    password.
    """
    g.require(NEEDED)
    _check_password(g.user, password)

    blob = await file.read()
    if len(blob) > MAX_ARCHIVE:
        raise HTTPException(status_code=413, detail="that file is too big to be a backup")

    try:
        data = backup.read_archive(blob, password)
    except backup.BadArchive as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    counts = {name: len(rows) for name, rows in (data.get("tables") or {}).items() if rows}
    counts["users"] = len(data.get("users") or [])
    counts["settings"] = len(data.get("settings") or [])
    counts["certificate files"] = len(data.get("cert_bundles") or {})

    return {
        "taken_at": data.get("taken_at"),
        "taken_from": data.get("taken_from"),
        "nodes_seen": data.get("nodes_seen") or [],
        "counts": counts,
        "certificates_without_files": data.get("certificates_without_files") or [],
    }


@router.post("/api/backup/import")
async def import_backup(file: UploadFile = File(...), password: str = Form(...),
                        confirm: str = Form(""),
                        g: ObjectGuard = Depends(changing)):
    """
    Put a backup back, and push it to every node.

    The confirmation is typed rather than clicked.  This replaces the running
    configuration of a fleet, and a dialog somebody can dismiss by reflex is
    not the right amount of friction in front of that.
    """
    g.require(NEEDED)
    _check_password(g.user, password)

    if confirm.strip().lower() != "restore":
        raise HTTPException(
            status_code=400,
            detail="type restore to confirm.  This replaces the configuration "
                   "on every node in this fleet.")

    blob = await file.read()
    if len(blob) > MAX_ARCHIVE:
        raise HTTPException(status_code=413, detail="that file is too big to be a backup")

    try:
        data = backup.read_archive(blob, password)
    except backup.BadArchive as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    audit.record("backup.import", user=g.user, object_type="backup",
                 object_name=str(data.get("taken_at") or "unknown"))

    result = await backup.restore_all(data, author=g.user.username)
    log.warning("%s restored a backup taken at %s",
                g.user.username, data.get("taken_at"))
    return result
