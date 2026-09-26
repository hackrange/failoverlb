"""
The audit log.

Append only.  Nothing in this app updates or deletes a row here, on purpose:
an audit log you can quietly edit is not worth having.

Two rules:

  Never log a secret.  Passwords, TOTP seeds, DNS API tokens and private keys
  are replaced with a marker before anything is written.  Audit logs get
  exported and mailed around.

  Log the attempt, not just the success.  A failed login or a refused change
  is often the more interesting line.
"""

import json
import logging

from app.db import session_scope
from app.models import AuditLog

log = logging.getLogger("nfm.audit")

# Any field whose name contains one of these gets its value hidden.  Matching
# on the name means a new secret field is covered without editing this list.
SECRET_HINTS = (
    "password", "secret", "token", "key", "credential", "totp",
    "privkey", "private", "hmac", "passphrase", "seed",
)

REDACTED = "***hidden***"


def scrub(value):
    """Walk a value and hide anything that looks like a secret."""
    if isinstance(value, dict):
        cleaned = {}
        for k, v in value.items():
            if any(hint in str(k).lower() for hint in SECRET_HINTS):
                cleaned[k] = REDACTED
            else:
                cleaned[k] = scrub(v)
        return cleaned

    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in value]

    if isinstance(value, str):
        # A PEM block in a log is a private key that just escaped.
        if "PRIVATE KEY" in value:
            return REDACTED
        if len(value) > 2000:
            return value[:2000] + f"... ({len(value)} chars)"

    return value


def record(action: str, user=None, source_ip: str = None, object_type: str = None,
           object_name: str = None, changes: dict = None, result: str = "success",
           detail: str = None, config_version: int = None, node_name: str = None):
    """
    Write one line to the audit log.

    Never raises.  A failed audit write must not take down the change it was
    recording, so it is logged as a warning and the change still goes through.
    """
    try:
        with session_scope() as session:
            session.add(AuditLog(
                username=getattr(user, "username", None) or (user if isinstance(user, str) else None),
                user_role=getattr(getattr(user, "role", None), "value", None),
                source_ip=source_ip,
                node_name=node_name,
                action=action[:64],
                object_type=object_type[:64] if object_type else None,
                object_name=str(object_name)[:255] if object_name else None,
                changes=json.dumps(scrub(changes))[:65536] if changes else None,
                result=result[:20],
                detail=str(detail)[:65536] if detail else None,
                config_version=config_version,
            ))
    except Exception:
        log.exception("could not write an audit entry for %s", action)


def diff_fields(before: dict, after: dict) -> dict:
    """
    Return only the fields that changed between two versions of an object,
    so the log stays small and readable.
    """
    changed = {}
    for key in set(before) | set(after):
        old = before.get(key)
        new = after.get(key)
        if old != new:
            changed[key] = {"from": old, "to": new}
    return changed
