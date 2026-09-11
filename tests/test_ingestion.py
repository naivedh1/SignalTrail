"""Ingestion tests: validation, rejection, deduplication and metrics."""

from __future__ import annotations

import json

from src import ingest
from src import schemas


VALID_AUTH = {
    "timestamp": "2026-09-10T10:01:12Z",
    "username": "analyst_demo",
    "source_ip": "198.51.100.23",
    "action": "login",
    "status": "failure",
    "host": "WS-001",
}

VALID_DNS = {
    "timestamp": 1789041600,
    "host": "WS-001",
    "user": "analyst_demo",
    "query": "demo-suspicious.example",
    "action": "query",
}


def write_sources(tmp_path, **sources):
    """Write raw JSON files and return the mapping run_ingestion expects."""
    paths = {}
    for source_type, records in sources.items():
        path = tmp_path / f"{source_type}.json"
        path.write_text(json.dumps(records), encoding="utf-8")
        paths[source_type] = path
    return paths


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def test_valid_record_passes_validation():
    assert schemas.validate_raw_record(VALID_AUTH, "authentication") == []


def test_missing_required_field_is_reported():
    record = {k: v for k, v in VALID_AUTH.items() if k != "host"}
    problems = schemas.validate_raw_record(record, "authentication")
    assert any("host" in problem for problem in problems)


def test_empty_required_field_is_reported():
    problems = schemas.validate_raw_record({**VALID_AUTH, "username": ""}, "authentication")
    assert any("username" in problem for problem in problems)


def test_whitespace_only_required_field_is_reported():
    """A blank host is as unusable as a missing one, so it is rejected too.

    Normalization strips whitespace to the empty marker. Accepting the record
    would produce an event with no host - unusable for investigation, but
    without the rejection that explains why.
    """
    for blank in ("   ", "\t", "\n"):
        problems = schemas.validate_raw_record({**VALID_AUTH, "host": blank}, "authentication")
        assert any("host" in problem for problem in problems), blank


def test_non_string_required_values_are_still_accepted():
    """Only blanks are rejected - a numeric or false-y value is real data."""
    assert schemas.validate_raw_record({**VALID_AUTH, "host": 0}, "authentication") == []
    assert schemas.validate_raw_record({**VALID_AUTH, "host": False}, "authentication") == []


def test_non_object_record_is_reported():
    assert schemas.validate_raw_record(["not", "a", "dict"], "authentication")


def test_non_integer_port_is_reported():
    record = {
        "timestamp": "2026-09-10T10:06:00+00:00",
        "host": "WS-001",
        "user": "analyst_demo",
        "destination_ip": "203.0.113.50",
        "destination_port": "not-a-port",
        "action": "allow",
    }
    problems = schemas.validate_raw_record(record, "network")
    assert any("destination_port" in problem for problem in problems)


def test_unknown_source_type_is_reported():
    assert schemas.validate_raw_record(VALID_AUTH, "carrier-pigeon")


# --------------------------------------------------------------------------
# Ingestion behaviour
# --------------------------------------------------------------------------


def test_valid_records_are_ingested(tmp_path):
    sources = write_sources(tmp_path, authentication=[VALID_AUTH], dns=[VALID_DNS])
    frame, metrics = ingest.run_ingestion(sources)

    assert metrics.raw_records == 2
    assert metrics.valid_records == 2
    assert metrics.invalid_records == 0
    assert metrics.normalized_records == 2
    assert len(frame) == 2
    assert list(frame.columns) == list(schemas.NORMALIZED_COLUMNS)


def test_malformed_records_are_rejected_without_stopping_the_run(tmp_path):
    """One bad record must not cost us the good ones around it."""
    broken_missing_field = {k: v for k, v in VALID_AUTH.items() if k != "host"}
    broken_timestamp = {**VALID_DNS, "timestamp": "not-a-timestamp"}

    sources = write_sources(
        tmp_path,
        authentication=[VALID_AUTH, broken_missing_field],
        dns=[VALID_DNS, broken_timestamp],
    )
    frame, metrics = ingest.run_ingestion(sources)

    assert metrics.raw_records == 4
    assert metrics.valid_records == 2
    assert metrics.invalid_records == 2
    assert len(frame) == 2
    assert len(metrics.rejections) == 2


def test_duplicate_records_are_counted_not_stored(tmp_path):
    """Identical raw records hash to one event id, so only one is kept."""
    sources = write_sources(tmp_path, authentication=[VALID_AUTH, dict(VALID_AUTH)])
    frame, metrics = ingest.run_ingestion(sources)

    assert metrics.valid_records == 2
    assert metrics.duplicate_event_ids == 1
    assert len(frame) == 1


def test_events_are_returned_in_time_order(tmp_path):
    later = {**VALID_AUTH, "timestamp": "2026-09-10T11:00:00Z"}
    earlier = {**VALID_AUTH, "timestamp": "2026-09-10T09:00:00Z"}
    sources = write_sources(tmp_path, authentication=[later, earlier])
    frame, _ = ingest.run_ingestion(sources)

    assert frame["timestamp"].is_monotonic_increasing


def test_missing_source_file_is_survivable(tmp_path):
    sources = {"authentication": tmp_path / "does-not-exist.json"}
    frame, metrics = ingest.run_ingestion(sources)

    assert frame.empty
    assert metrics.raw_records == 0
    assert list(frame.columns) == list(schemas.NORMALIZED_COLUMNS)


def test_invalid_json_file_is_survivable(tmp_path):
    path = tmp_path / "authentication.json"
    path.write_text("{ this is not json", encoding="utf-8")
    frame, metrics = ingest.run_ingestion({"authentication": path})

    assert frame.empty
    assert metrics.raw_records == 0


def test_metrics_summary_mentions_every_counter(tmp_path):
    sources = write_sources(tmp_path, authentication=[VALID_AUTH])
    _, metrics = ingest.run_ingestion(sources)
    rendered = metrics.render()

    for label in ("Raw records", "Valid records", "Invalid records", "Duplicates", "Normalized"):
        assert label in rendered


def test_empty_frame_keeps_its_column_types():
    """An empty result still has to load into DuckDB, so dtypes must hold."""
    frame = ingest.events_to_frame([])
    assert list(frame.columns) == list(schemas.NORMALIZED_COLUMNS)
    assert str(frame["dst_port"].dtype) == "Int64"
