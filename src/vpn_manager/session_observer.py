"""Read-only IKEv2 session snapshot collector.

This file is intentionally standalone: the oneshot may copy it without the
management application or its credentials.
"""
from __future__ import annotations

import argparse
import datetime as dt
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
from typing import Any

MAX_SAS = 4096
MAX_SESSIONS = 512
ACCOUNT = re.compile(r"account-([a-z][a-z0-9_-]{0,63})")
SESSION_ID = re.compile(r"[0-9]{1,20}")


class ObserverError(Exception):
    pass


def _text(value: Any) -> str | None:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return value if isinstance(value, str) and len(value) <= 256 else None


def _address(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return str(ip_address(text))
    except ValueError:
        return None


def _number(value: Any, maximum: int, *, minimum: int = 0) -> int | None:
    text = _text(value)
    if text is None or not text.isascii() or not text.isdecimal() or len(text) > 10:
        return None
    number = int(text)
    return number if minimum <= number <= maximum else None


def collect(vici_session: Any, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Use strongSwan's list-sas schema; emit one entry per active IKE SA."""
    sampled_at = now or dt.datetime.now(dt.timezone.utc)
    sessions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for count, entry in enumerate(vici_session.list_sas(), start=1):
        if count > MAX_SAS:
            raise ObserverError("too_many_sas")
        for name, data in entry.items():
            match = ACCOUNT.fullmatch(_text(name) or "")
            if match is None or _text(data.get("state")) not in {"ESTABLISHED", "REKEYING"}:
                continue
            username = match.group(1)
            # VICI omits remote-eap-id when it equals remote-id.
            identity = _text(data.get("remote-eap-id", data.get("remote-id")))
            if identity != username:
                continue
            if not any(_text(child.get("state")) == "INSTALLED" for child in data["child-sas"].values()):
                continue

            session_id = _text(data.get("uniqueid"))
            if not session_id or not SESSION_ID.fullmatch(session_id) or session_id in seen:
                raise ObserverError("invalid_session_id")
            seen.add(session_id)

            virtual_ips = data.get("remote-vips", [])
            if len(virtual_ips) > 16:
                raise ObserverError("too_many_virtual_ips")
            virtual_addresses = sorted({address for value in virtual_ips if (address := _address(value))})
            established = _number(data.get("established"), 3153600000)
            connected_at = sampled_at - dt.timedelta(seconds=established) if established is not None else None
            sessions.append({
                "username": username,
                "session_id": session_id,
                "remote_address": _address(data.get("remote-host")),
                "remote_port": _number(data.get("remote-port"), 65535, minimum=1),
                "virtual_addresses": virtual_addresses,
                "connected_at": connected_at.isoformat() if connected_at else None,
            })
            if len(sessions) > MAX_SESSIONS:
                raise ObserverError("too_many_sessions")
    sessions.sort(key=lambda session: (session["username"], int(session["session_id"])))
    return {"sampled_at": sampled_at.isoformat(), "sessions": sessions}


def _safe_socket(path: Path) -> None:
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or str(path.resolve()) in {"/run/charon.vici", "/var/run/charon.vici"}:
        raise ObserverError("unsafe_vici_socket")


def _safe_dir(path: Path) -> None:
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ObserverError("unsafe_snapshot_directory")


def write_snapshot(path: Path, payload: dict[str, Any]) -> None:
    fd, name = tempfile.mkstemp(prefix=".sessions.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o640)
            json.dump(payload, output, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vici-socket", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        _safe_socket(args.vici_socket)
        _safe_dir(args.snapshot.parent)
        import vici

        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(3)
            peer.connect(str(args.vici_socket))
            payload = collect(vici.Session(peer))
        write_snapshot(args.snapshot, payload)
    except Exception:
        # Service failure stays observable without exposing peer identities.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
