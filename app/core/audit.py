"""
The audit log.

Append only.  Nothing in this app updates or deletes a row here, and that is on
purpose.  When somebody asks why the site went down at 2am, this is the answer,
and an audit log you can quietly edit is not worth having.

Two rules that matter:

  Never log a secret.  Passwords, TOTP seeds, DNS API tokens and private keys
  get replaced with a marker before anything is written.  An audit log is
  exactly the kind of thing that gets exported and mailed around, so a password
  in here has a long life.

  Log the attempt, not just the success.  A failed login and a refused change
  are more interesting than the ones that worked.
"""

import json
import logging

from app.db import session_scope
from app.models import AuditLog

log = logging.getLogger("nfm.audit")

# Any field whose name contains one of these gets its value hidden.  Matching on
# the name rather than the value means a new secret field is covered the moment
# somebody adds it, without anybody having to remember to come here.
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

    Never raises.  An audit write that fails must not take down the thing it was
    auditing, so a broken log is a warning and the change still goes through.
    Losing an audit line is bad.  Refusing to fix nginx because we could not
    write the audit line is worse.
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
    Work out what actually changed between two versions of an object.

    Only the fields that moved go in the log.  Storing the whole object twice on
    every save makes the log enormous and makes the one line you care about
    hard to find.
    """
    changed = {}
    for key in set(before) | set(after):
        old = before.get(key)
        new = after.get(key)
        if old != new:
            changed[key] = {"from": old, "to": new}
    return changed
