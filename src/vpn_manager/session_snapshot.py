"""Read a bounded, recent snapshot without access to the VPN control socket."""
import os
import stat
from datetime import timedelta
from pathlib import Path

from pydantic import ValidationError

from .models import VpnConnectionSnapshot
from .security import utc_now

SNAPSHOT_MAX_BYTES = 256 * 1024
SNAPSHOT_OWNER = 0
SNAPSHOT_MAX_AGE = timedelta(seconds=45)
SNAPSHOT_CLOCK_TOLERANCE = timedelta(seconds=5)


def read_session_snapshot(path: Path | None) -> VpnConnectionSnapshot | None:
    if path is None:
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as snapshot_file:
            info = os.fstat(snapshot_file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != SNAPSHOT_OWNER or info.st_mode & 0o037:
                return None
            data = snapshot_file.read(SNAPSHOT_MAX_BYTES + 1)
        if len(data) > SNAPSHOT_MAX_BYTES:
            return None
        snapshot = VpnConnectionSnapshot.model_validate_json(data)
    except (OSError, ValidationError):
        return None
    age = utc_now() - snapshot.sampled_at
    if not -SNAPSHOT_CLOCK_TOLERANCE <= age <= SNAPSHOT_MAX_AGE:
        return None
    session_ids = {session.session_id for session in snapshot.sessions}
    return snapshot if len(session_ids) == len(snapshot.sessions) else None
