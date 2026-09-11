"""Normalization tests: field mapping, timestamps, and traceability."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from src import normalize
from src import schemas


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------


def test_iso_timestamp_with_z_suffix():
    parsed = normalize.parse_timestamp("2026-09-10T10:01:12Z", "iso")
    assert parsed == datetime(2026, 9, 10, 10, 1, 12, tzinfo=timezone.utc)


def test_iso_timestamp_with_numeric_offset_is_converted_to_utc():
    parsed = normalize.parse_timestamp("2026-09-10T12:01:12+02:00", "iso")
    assert parsed == datetime(2026, 9, 10, 10, 1, 12, tzinfo=timezone.utc)


def test_naive_timestamp_is_read_as_utc():
    """Endpoint logs carry no zone. Reading them as UTC is a stated choice."""
    parsed = normalize.parse_timestamp("2026-09-10 10:04:00", "naive")
    assert parsed == datetime(2026, 9, 10, 10, 4, 0, tzinfo=timezone.utc)


def test_epoch_timestamp_is_converted():
    moment = datetime(2026, 9, 10, 10, 5, 0, tzinfo=timezone.utc)
    parsed = normalize.parse_timestamp(int(moment.timestamp()), "epoch")
    assert parsed == moment


def test_all_sources_agree_on_the_same_moment():
    """The same instant written four ways must normalize to one value."""
    moment = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    assert normalize.parse_timestamp("2026-09-10T10:00:00Z", "iso") == moment
    assert normalize.parse_timestamp("2026-09-10T10:00:00+00:00", "iso") == moment
    assert normalize.parse_timestamp("2026-09-10 10:00:00", "naive") == moment
    assert normalize.parse_timestamp(moment.timestamp(), "epoch") == moment


@pytest.mark.parametrize("value", ["not-a-timestamp", "", None, "2026-13-45"])
def test_unparseable_timestamps_raise(value):
    with pytest.raises(normalize.NormalizationError):
        normalize.parse_timestamp(value, "iso")


def test_unparseable_epoch_raises():
    with pytest.raises(normalize.NormalizationError):
        normalize.parse_timestamp("not-a-timestamp", "epoch")


# --------------------------------------------------------------------------
# Field mapping
# --------------------------------------------------------------------------


def test_authentication_fields_are_mapped():
    record = {
        "timestamp": "2026-09-10T10:01:12Z",
        "username": "analyst_demo",
        "source_ip": "198.51.100.23",
        "action": "login",
        "status": "failure",
        "host": "WS-001",
    }
    event = normalize.normalize_record(record, "authentication")

    assert event["user"] == "analyst_demo"      # username -> user
    assert event["src_ip"] == "198.51.100.23"   # source_ip -> src_ip
    assert event["event_type"] == schemas.EVENT_TYPE_AUTHENTICATION
    assert event["status"] == schemas.STATUS_FAILURE
    # A failed login is worth more than an informational record in a timeline.
    assert event["severity"] == schemas.SEVERITY_LOW


def test_endpoint_process_fields_are_mapped():
    record = {
        "timestamp": "2026-09-10 10:04:00",
        "host": "WS-001",
        "user": "analyst_demo",
        "process": "PowerShell.exe",
        "command_line": "powershell.exe -EncodedCommand <DEMO_ONLY>",
        "action": "process_start",
    }
    event = normalize.normalize_record(record, "endpoint")

    assert event["event_type"] == schemas.EVENT_TYPE_PROCESS
    assert event["process_name"] == "powershell.exe"  # lower-cased
    assert "-EncodedCommand" in event["command_line"]


def test_endpoint_file_events_get_their_own_event_type():
    record = {
        "timestamp": "2026-09-10 10:07:00",
        "host": "WS-001",
        "user": "analyst_demo",
        "process": "powershell.exe",
        "action": "file_create",
        "file_path": "C:\\Temp\\demo_payload.bin",
    }
    event = normalize.normalize_record(record, "endpoint")

    assert event["event_type"] == schemas.EVENT_TYPE_FILE
    assert event["action"] == "file_create"
    assert event["file_path"] == "C:\\Temp\\demo_payload.bin"


def test_dns_query_maps_to_domain():
    record = {
        "timestamp": 1789041900,
        "host": "WS-001",
        "user": "analyst_demo",
        "query": "Demo-Suspicious.Example",
        "action": "query",
    }
    event = normalize.normalize_record(record, "dns")

    assert event["domain"] == "demo-suspicious.example"  # case standardized
    assert event["event_type"] == schemas.EVENT_TYPE_DNS
    assert event["action"] == "dns_query"


def test_network_fields_are_mapped():
    record = {
        "timestamp": "2026-09-10T10:06:00+00:00",
        "host": "WS-001",
        "user": "analyst_demo",
        "destination_ip": "203.0.113.50",
        "destination_port": "443",
        "action": "allow",
    }
    event = normalize.normalize_record(record, "network")

    assert event["dst_ip"] == "203.0.113.50"
    assert event["dst_port"] == 443          # coerced from string
    assert event["action"] == "connection_allowed"


def test_blocked_connection_is_marked_as_a_failure():
    record = {
        "timestamp": "2026-09-10T10:06:00+00:00",
        "host": "WS-001",
        "user": "analyst_demo",
        "destination_ip": "203.0.113.50",
        "destination_port": 443,
        "action": "deny",
    }
    event = normalize.normalize_record(record, "network")

    assert event["action"] == "connection_blocked"
    assert event["status"] == schemas.STATUS_FAILURE


# --------------------------------------------------------------------------
# Standardization of empty values
# --------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "   ", "null", "None", "-", "N/A"])
def test_empty_markers_collapse_to_one_value(value):
    assert normalize.clean_text(value) == schemas.EMPTY_VALUE


@pytest.mark.parametrize("value", ["not-a-port", None, "", 99999, -1])
def test_unusable_ports_become_none(value):
    assert normalize.clean_port(value) is None


def test_fields_that_do_not_apply_are_empty_not_missing():
    """Every event carries every column, so queries never hit a missing key."""
    record = {
        "timestamp": 1789041900,
        "host": "WS-001",
        "user": "analyst_demo",
        "query": "updates.example.com",
        "action": "query",
    }
    event = normalize.normalize_record(record, "dns")

    assert set(event) == set(schemas.NORMALIZED_COLUMNS)
    assert event["process_name"] == schemas.EMPTY_VALUE
    assert event["dst_ip"] == schemas.EMPTY_VALUE


# --------------------------------------------------------------------------
# Identity and traceability
# --------------------------------------------------------------------------


def test_event_id_is_stable_for_identical_records():
    record = {
        "timestamp": "2026-09-10T10:01:12Z",
        "username": "analyst_demo",
        "source_ip": "198.51.100.23",
        "action": "login",
        "status": "failure",
        "host": "WS-001",
    }
    first = normalize.normalize_record(record, "authentication")
    second = normalize.normalize_record(dict(record), "authentication")

    assert first["event_id"] == second["event_id"]


def test_event_id_changes_when_the_record_changes():
    record = {
        "timestamp": "2026-09-10T10:01:12Z",
        "username": "analyst_demo",
        "source_ip": "198.51.100.23",
        "action": "login",
        "status": "failure",
        "host": "WS-001",
    }
    first = normalize.normalize_record(record, "authentication")
    second = normalize.normalize_record({**record, "host": "WS-002"}, "authentication")

    assert first["event_id"] != second["event_id"]


def test_key_order_does_not_affect_identity():
    """Identity must depend on content, not on how the JSON was written."""
    record = {"a": 1, "b": 2}
    assert normalize.canonical_json(record) == normalize.canonical_json({"b": 2, "a": 1})


def test_original_record_is_preserved_for_audit():
    record = {
        "timestamp": "2026-09-10T10:01:12Z",
        "username": "analyst_demo",
        "source_ip": "198.51.100.23",
        "action": "login",
        "status": "failure",
        "host": "WS-001",
        "auth_method": "password",
    }
    event = normalize.normalize_record(record, "authentication")
    restored = json.loads(event["raw_message"])

    assert restored == record
    # Including a field the common model does not have a column for.
    assert restored["auth_method"] == "password"


def test_unknown_source_type_is_refused():
    with pytest.raises(normalize.NormalizationError):
        normalize.normalize_record({"timestamp": "2026-09-10T10:00:00Z"}, "carrier-pigeon")


def test_normalization_only_emits_the_declared_vocabulary():
    """The event-type list in schemas.py is a contract, not a comment.

    Anything downstream that filters on event_type depends on this, so a new
    source mapper inventing its own label should fail here rather than quietly
    producing events no rule will ever match.
    """
    records = [
        ({"timestamp": "2026-09-10T10:00:00Z", "username": "u", "source_ip": "10.0.0.1",
          "action": "login", "status": "success", "host": "WS-001"}, "authentication"),
        ({"timestamp": "2026-09-10 10:00:00", "host": "WS-001", "user": "u",
          "process": "chrome.exe", "action": "process_start"}, "endpoint"),
        ({"timestamp": "2026-09-10 10:00:00", "host": "WS-001", "user": "u",
          "process": "chrome.exe", "action": "file_create"}, "endpoint"),
        ({"timestamp": 1789041600, "host": "WS-001", "user": "u",
          "query": "a.example.com", "action": "query"}, "dns"),
        ({"timestamp": "2026-09-10T10:00:00+00:00", "host": "WS-001", "user": "u",
          "destination_ip": "203.0.113.7", "destination_port": 443,
          "action": "allow"}, "network"),
    ]
    produced = {
        normalize.normalize_record(record, source)["event_type"]
        for record, source in records
    }

    assert produced.issubset(set(schemas.EVENT_TYPES))
    # Every declared type is actually reachable; none is dead vocabulary.
    assert produced == set(schemas.EVENT_TYPES)


def test_normalization_only_emits_the_declared_status_values():
    record = {
        "timestamp": "2026-09-10T10:00:00Z",
        "username": "u",
        "source_ip": "10.0.0.1",
        "action": "login",
        "status": "something-unexpected",
        "host": "WS-001",
    }
    event = normalize.normalize_record(record, "authentication")
    assert event["status"] == schemas.STATUS_UNKNOWN


def test_important_missing_fields_are_reported():
    event = {"timestamp": None, "host": "", "user": "u", "event_type": "dns"}
    missing = normalize.missing_important_fields(event)

    assert "timestamp" in missing and "host" in missing
    assert "user" not in missing
