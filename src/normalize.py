"""Normalization: many raw shapes in, one common event model out.

Each telemetry source names its fields differently, formats timestamps
differently, and describes actions in its own vocabulary. Analysts should not
have to remember which is which, so everything is mapped onto the single
schema declared in ``schemas.NORMALIZED_COLUMNS``.

Two properties matter more than convenience here:

* **Traceability.** The complete original record is kept verbatim in
  ``raw_message``, so any normalized event can be checked against its source.
* **Stable identity.** ``event_id`` is a hash of the source type plus the
  original record, so re-running the pipeline over the same input produces the
  same identifiers. That is what makes the pipeline safe to run repeatedly.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from . import schemas

logger = logging.getLogger(__name__)


class NormalizationError(ValueError):
    """Raised when a record cannot be mapped onto the common event model."""


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def canonical_json(record: dict) -> str:
    """Serialize a record so that equal records always produce equal text."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def make_event_id(record: dict, source_type: str) -> str:
    """Derive a deterministic event identifier from the raw record."""
    digest = hashlib.sha256(
        (source_type + "|" + canonical_json(record)).encode("utf-8")
    ).hexdigest()
    return "EVT-" + digest[:16]


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------


def parse_timestamp(value, timestamp_format: str) -> datetime:
    """Parse a source-specific timestamp into an aware UTC datetime.

    Sources disagree about format on purpose in this project: ISO with a Z,
    a bare "YYYY-MM-DD HH:MM:SS", an ISO string with a numeric offset, and
    Unix epoch seconds. Anything without zone information is read as UTC,
    which is stated explicitly rather than left to the local machine.
    """
    if value is None or value == "":
        raise NormalizationError("missing timestamp")

    if timestamp_format == "epoch":
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (TypeError, ValueError, OSError, OverflowError) as exc:
            raise NormalizationError(f"unparseable epoch timestamp: {value!r}") from exc

    if not isinstance(value, str):
        raise NormalizationError(f"unparseable timestamp: {value!r}")

    text = value.strip()
    # datetime.fromisoformat accepts a trailing Z from Python 3.11 onward, but
    # normalizing it keeps the intent obvious.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
    except ValueError as exc:
        raise NormalizationError(f"unparseable timestamp: {value!r}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Value cleaning
# --------------------------------------------------------------------------


def clean_text(value) -> str:
    """Collapse None, missing and whitespace-only values to one empty marker."""
    if value is None:
        return schemas.EMPTY_VALUE
    text = str(value).strip()
    if text.lower() in ("", "none", "null", "-", "n/a"):
        return schemas.EMPTY_VALUE
    return text


def clean_port(value) -> int | None:
    """Return a port as an integer, or None when it is absent or unusable."""
    if value is None or value == "":
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _blank_event() -> dict:
    """A normalized event with every text field set to the empty marker."""
    event = {column: schemas.EMPTY_VALUE for column in schemas.NORMALIZED_COLUMNS}
    event["timestamp"] = None
    event["dst_port"] = None
    return event


# --------------------------------------------------------------------------
# Per-source mappers
# --------------------------------------------------------------------------


def _normalize_authentication(record: dict, event: dict) -> dict:
    action = clean_text(record.get("action")).lower() or "login"
    status = clean_text(record.get("status")).lower()
    if status in ("success", "succeeded", "ok"):
        status = schemas.STATUS_SUCCESS
    elif status in ("failure", "failed", "fail", "denied"):
        status = schemas.STATUS_FAILURE
    else:
        status = schemas.STATUS_UNKNOWN

    event["host"] = clean_text(record.get("host"))
    event["user"] = clean_text(record.get("username"))
    event["src_ip"] = clean_text(record.get("source_ip"))
    event["event_type"] = schemas.EVENT_TYPE_AUTHENTICATION
    event["action"] = action
    event["status"] = status
    # A failed login is not an alert on its own, but it is worth more than an
    # informational record when an analyst scans a timeline.
    event["severity"] = (
        schemas.SEVERITY_LOW if status == schemas.STATUS_FAILURE else schemas.SEVERITY_INFO
    )
    return event


def _normalize_endpoint(record: dict, event: dict) -> dict:
    raw_action = clean_text(record.get("action")).lower()
    if raw_action in ("file_create", "file_write", "file_created"):
        action = "file_create"
        event_type = schemas.EVENT_TYPE_FILE
    else:
        action = "process_start"
        event_type = schemas.EVENT_TYPE_PROCESS

    event["host"] = clean_text(record.get("host"))
    event["user"] = clean_text(record.get("user"))
    event["event_type"] = event_type
    event["action"] = action
    event["process_name"] = clean_text(record.get("process")).lower()
    event["command_line"] = clean_text(record.get("command_line"))
    event["file_path"] = clean_text(record.get("file_path"))
    event["status"] = schemas.STATUS_SUCCESS
    event["severity"] = schemas.SEVERITY_INFO
    return event


def _normalize_dns(record: dict, event: dict) -> dict:
    event["host"] = clean_text(record.get("host"))
    event["user"] = clean_text(record.get("user"))
    event["event_type"] = schemas.EVENT_TYPE_DNS
    event["action"] = "dns_query"
    event["domain"] = clean_text(record.get("query")).lower()
    response_code = clean_text(record.get("response_code")).upper()
    event["status"] = (
        schemas.STATUS_SUCCESS if response_code in ("", "NOERROR") else schemas.STATUS_FAILURE
    )
    event["severity"] = schemas.SEVERITY_INFO
    return event


def _normalize_network(record: dict, event: dict) -> dict:
    raw_action = clean_text(record.get("action")).lower()
    if raw_action in ("deny", "block", "blocked", "drop"):
        action = "connection_blocked"
        status = schemas.STATUS_FAILURE
    else:
        action = "connection_allowed"
        status = schemas.STATUS_SUCCESS

    event["host"] = clean_text(record.get("host"))
    event["user"] = clean_text(record.get("user"))
    event["event_type"] = schemas.EVENT_TYPE_NETWORK
    event["action"] = action
    event["dst_ip"] = clean_text(record.get("destination_ip"))
    event["dst_port"] = clean_port(record.get("destination_port"))
    event["status"] = status
    event["severity"] = schemas.SEVERITY_INFO
    return event


_MAPPERS = {
    "authentication": _normalize_authentication,
    "endpoint": _normalize_endpoint,
    "dns": _normalize_dns,
    "network": _normalize_network,
}


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def normalize_record(record: dict, source_type: str) -> dict:
    """Map one raw record onto the common event model.

    Raises NormalizationError when the record cannot be mapped; callers are
    expected to count those rather than let them abort a whole ingest run.
    """
    schema = schemas.RAW_SCHEMAS.get(source_type)
    if schema is None:
        raise NormalizationError(f"unknown source type: {source_type}")
    if not isinstance(record, dict):
        raise NormalizationError("record is not an object")

    mapper = _MAPPERS[source_type]

    event = _blank_event()
    event["event_id"] = make_event_id(record, source_type)
    event["source_type"] = source_type
    event["timestamp"] = parse_timestamp(
        record.get(schema.timestamp_field), schema.timestamp_format
    )
    event = mapper(record, event)
    # The untouched original record, so every normalized field can be audited.
    event["raw_message"] = canonical_json(record)
    return event


def missing_important_fields(event: dict) -> list[str]:
    """Report normalized fields that are empty but matter for investigation."""
    missing = []
    for name in schemas.IMPORTANT_FIELDS:
        value = event.get(name)
        if value is None or value == schemas.EMPTY_VALUE:
            missing.append(name)
    return missing
