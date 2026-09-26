"""
Backup export, inspect and restore.

Both directions ask for the password again.  The archive is encrypted with
it and we only store a hash, so there is no other way to build or open one.
It also re-proves the person at the keyboard, which is welcome for an
operation that hands out every private key the fleet owns.
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

# A backup holds every key in the fleet, so only the top role gets one.
NEEDED = "manage_cluster"

# Plenty for any real fleet, small enough that uploads cannot fill the disk.
MAX_ARCHIVE = 64 * 1024 * 1024


def _check_password(user, password: str):
    if not password:
        raise HTTPException(status_code=400,
                            detail="your password is what encrypts the backup")
    if not verify_password(user.password_hash, password):
        # Same wording as the login page on purpose.
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
            # Lets the page show what went in without opening the file.
            "X-Backup-Summary": str(summary.get("counts")),
        },
    )


@router.post("/api/backup/inspect")
async def inspect_backup(file: UploadFile = File(...), password: str = Form(...),
                         g: ObjectGuard = Depends(guard)):
    """
    Show what is in an archive without restoring it.

    Lets someone catch the wrong file or wrong password before a restore
    overwrites a working configuration.
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
    Restore a backup and push it to every node.

    The confirmation is typed rather than clicked, since this replaces the
    running configuration of the whole fleet.
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
