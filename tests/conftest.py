"""Shared fixtures.

The fixtures build small, hand-written event sets rather than loading the
generated dataset. Tests that depend on a generator are really testing the
generator; these ones test the logic under examination and nothing else.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import ingest  # noqa: E402
from src import schemas  # noqa: E402

#: A fixed reference moment, so every assertion about ordering is exact.
BASE_TIME = datetime(2026, 9, 10, 10, 0, 0)


def make_event(
    event_id: str,
    offset_seconds: int = 0,
    host: str = "WS-001",
    user: str = "analyst_demo",
    source_type: str = "authentication",
    event_type: str = schemas.EVENT_TYPE_AUTHENTICATION,
    action: str = "login",
    status: str = schemas.STATUS_FAILURE,
    src_ip: str = "",
    dst_ip: str = "",
    dst_port=None,
    domain: str = "",
    process_name: str = "",
    command_line: str = "",
    file_path: str = "",
    severity: str = schemas.SEVERITY_INFO,
) -> dict:
    """Build one normalized event with sensible defaults."""
    return {
        "event_id": event_id,
        "timestamp": BASE_TIME + timedelta(seconds=offset_seconds),
        "host": host,
        "user": user,
        "source_type": source_type,
        "event_type": event_type,
        "action": action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "domain": domain,
        "process_name": process_name,
        "command_line": command_line,
        "file_path": file_path,
        "status": status,
        "severity": severity,
        "raw_message": "{}",
    }


def make_frame(events: list[dict]) -> pd.DataFrame:
    """Build a typed event DataFrame the way the ingest stage would."""
    return ingest.events_to_frame(events)


@pytest.fixture
def base_time() -> datetime:
    return BASE_TIME


@pytest.fixture
def storyline_events() -> pd.DataFrame:
    """A miniature version of the demo incident.

    Six failed logins, a success, encoded PowerShell, a watchlisted DNS
    lookup, a watchlisted destination, and a file write - enough for all five
    rules to fire and for correlation to have something to group.
    """
    events = []
    for index, offset in enumerate([72, 82, 91, 104, 118, 129]):
        events.append(
            make_event(
                f"EVT-fail{index}",
                offset_seconds=offset,
                src_ip="198.51.100.23",
                status=schemas.STATUS_FAILURE,
                severity=schemas.SEVERITY_LOW,
            )
        )
    events.append(
        make_event(
            "EVT-success",
            offset_seconds=151,
            src_ip="198.51.100.23",
            status=schemas.STATUS_SUCCESS,
        )
    )
    events.append(
        make_event(
            "EVT-powershell",
            offset_seconds=240,
            source_type="endpoint",
            event_type=schemas.EVENT_TYPE_PROCESS,
            action="process_start",
            status=schemas.STATUS_SUCCESS,
            process_name="powershell.exe",
            command_line="powershell.exe -NoProfile -EncodedCommand <DEMO_ONLY>",
        )
    )
    events.append(
        make_event(
            "EVT-dns",
            offset_seconds=300,
            source_type="dns",
            event_type=schemas.EVENT_TYPE_DNS,
            action="dns_query",
            status=schemas.STATUS_SUCCESS,
            domain="demo-suspicious.example",
        )
    )
    events.append(
        make_event(
            "EVT-network",
            offset_seconds=360,
            source_type="network",
            event_type=schemas.EVENT_TYPE_NETWORK,
            action="connection_allowed",
            status=schemas.STATUS_SUCCESS,
            dst_ip="203.0.113.50",
            dst_port=443,
        )
    )
    events.append(
        make_event(
            "EVT-file",
            offset_seconds=420,
            source_type="endpoint",
            event_type=schemas.EVENT_TYPE_FILE,
            action="file_create",
            status=schemas.STATUS_SUCCESS,
            process_name="powershell.exe",
            file_path="C:\\Temp\\demo_payload.bin",
        )
    )
    return make_frame(events)


@pytest.fixture
def quiet_events() -> pd.DataFrame:
    """Ordinary activity that should not trip any rule."""
    events = [
        make_event(
            "EVT-ok1",
            offset_seconds=0,
            status=schemas.STATUS_SUCCESS,
            src_ip="10.10.0.15",
        ),
        make_event(
            "EVT-ok2",
            offset_seconds=60,
            source_type="endpoint",
            event_type=schemas.EVENT_TYPE_PROCESS,
            action="process_start",
            status=schemas.STATUS_SUCCESS,
            process_name="chrome.exe",
            command_line="chrome.exe --profile-directory=Default",
        ),
        make_event(
            "EVT-ok3",
            offset_seconds=120,
            source_type="dns",
            event_type=schemas.EVENT_TYPE_DNS,
            action="dns_query",
            status=schemas.STATUS_SUCCESS,
            domain="updates.example.com",
        ),
    ]
    return make_frame(events)
