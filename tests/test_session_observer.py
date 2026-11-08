import datetime as dt
import json
import stat

from vpn_manager.session_observer import collect, write_snapshot


class FakeVici:
    def __init__(self, sas):
        self.sas = sas

    def list_sas(self):
        yield from self.sas


def test_collect_uses_vici_identity_and_retains_each_active_ike_session():
    connected = {
        "uniqueid": b"11",
        "state": b"ESTABLISHED",
        "remote-eap-id": b"alice",
        "remote-id": b"@client",
        "remote-host": b"198.51.100.4",
        "remote-port": b"4500",
        "established": b"60",
        "remote-vips": [b"10.77.64.2"],
        "child-sas": {"first": {"state": b"INSTALLED"}, "second": {"state": b"INSTALLED"}},
    }
    sas = [
        {"account-alice": connected},
        {"account-alice": {**connected, "uniqueid": b"12", "remote-port": b"4501", "remote-vips": [b"10.77.64.3"]}},
        {"account-alice": {**connected, "uniqueid": b"13", "state": b"REKEYED"}},
        {"account-alice": {**connected, "uniqueid": b"14", "remote-eap-id": b"mallory"}},
        {"account-alice": {**connected, "uniqueid": b"15", "child-sas": {"first": {"state": b"REKEYED"}}}},
        {"other": connected},
        {"account-bob": {"uniqueid": b"16", "state": b"ESTABLISHED", "remote-id": b"bob",
                         "child-sas": {"first": {"state": b"INSTALLED"}}}},
    ]
    result = collect(FakeVici(sas), now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
    assert result["sampled_at"] == "2026-01-01T00:00:00+00:00"
    assert [session["session_id"] for session in result["sessions"]] == ["11", "12", "16"]
    assert result["sessions"][0] == {
        "username": "alice",
        "session_id": "11",
        "remote_address": "198.51.100.4",
        "remote_port": 4500,
        "virtual_addresses": ["10.77.64.2"],
        "connected_at": "2025-12-31T23:59:00+00:00",
    }
    assert result["sessions"][1]["remote_port"] == 4501
    assert result["sessions"][2]["username"] == "bob"
    assert result["sessions"][2]["connected_at"] is None


def test_snapshot_is_atomic_json_and_group_readable(tmp_path):
    target = tmp_path / "sessions.json"
    payload = {"sampled_at": "2026-01-01T00:00:00+00:00", "sessions": []}
    write_snapshot(target, payload)
    assert json.loads(target.read_text()) == payload
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
