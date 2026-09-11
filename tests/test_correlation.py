"""Correlation and investigation tests.

These cover the step that turns a list of alerts into something worth a
person's attention, and the query layer analysts and the AI layer both use.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd

import pytest

from conftest import BASE_TIME, make_event, make_frame

from src import ai_investigator
from src import correlate
from src import database
from src import detections
from src import investigate
from src import schemas


@pytest.fixture
def storyline_alerts(storyline_events):
    return detections.run_detections(storyline_events)


@pytest.fixture
def loaded_db(tmp_path, storyline_events, storyline_alerts):
    """A populated database on a throwaway path."""
    incidents = correlate.correlate_alerts(storyline_alerts, storyline_events)
    path = tmp_path / "test.duckdb"
    conn = database.connect(path)
    database.initialize(conn)
    database.load_events(conn, storyline_events)
    database.load_alerts(conn, storyline_alerts)
    database.load_incidents(conn, incidents)
    yield conn
    conn.close()


# --------------------------------------------------------------------------
# Grouping
# --------------------------------------------------------------------------


def test_storyline_becomes_one_incident(storyline_alerts, storyline_events):
    """The whole point: five alerts, one thing to investigate."""
    incidents = correlate.correlate_alerts(storyline_alerts, storyline_events)

    assert len(incidents) == 1
    incident = incidents.iloc[0]
    assert incident["host"] == "WS-001"
    assert incident["user"] == "analyst_demo"
    assert set(incident["rule_ids"].split(",")) == set(detections.RULES)


def test_incident_spans_the_whole_sequence(storyline_alerts, storyline_events):
    incidents = correlate.correlate_alerts(storyline_alerts, storyline_events)
    incident = incidents.iloc[0]

    assert incident["start_time"] == storyline_events["timestamp"].min()
    assert incident["end_time"] == storyline_events["timestamp"].max()


def test_successful_login_is_pulled_in_as_context(storyline_alerts, storyline_events):
    """No rule fires on the success, but an analyst needs to see it."""
    incidents = correlate.correlate_alerts(storyline_alerts, storyline_events)
    attached = incidents.iloc[0]["evidence_event_ids"].split(",")

    assert "EVT-success" in attached


def test_activity_on_different_hosts_is_not_merged(storyline_events):
    """Two unrelated machines must not become one incident."""
    other = storyline_events.copy()
    other["host"] = "WS-009"
    other["event_id"] = other["event_id"] + "-b"
    combined = make_frame(
        storyline_events.to_dict("records") + other.to_dict("records")
    )
    alerts = detections.run_detections(combined)
    incidents = correlate.correlate_alerts(alerts, combined)

    assert len(incidents) == 2
    assert set(incidents["host"]) == {"WS-001", "WS-009"}


def test_alerts_far_apart_in_time_become_separate_incidents():
    events = []
    for index in range(6):
        events.append(
            make_event(f"EVT-a{index}", offset_seconds=index * 10,
                       src_ip="198.51.100.23", status=schemas.STATUS_FAILURE)
        )
    for index in range(6):
        events.append(
            make_event(f"EVT-b{index}", offset_seconds=86400 + index * 10,
                       src_ip="198.51.100.23", status=schemas.STATUS_FAILURE)
        )
    frame = make_frame(events)
    incidents = correlate.correlate_alerts(detections.run_detections(frame), frame)

    assert len(incidents) == 2


def test_correlation_gap_is_configurable(storyline_alerts, storyline_events):
    """A one-second gap tolerance splits the storyline into its parts."""
    split = correlate.correlate_alerts(
        storyline_alerts, storyline_events, gap_minutes=0
    )
    assert len(split) > 1


def test_correlation_is_repeatable(storyline_alerts, storyline_events):
    first = correlate.correlate_alerts(storyline_alerts, storyline_events)
    second = correlate.correlate_alerts(storyline_alerts, storyline_events)
    assert first["incident_id"].tolist() == second["incident_id"].tolist()


def test_no_alerts_produces_an_empty_typed_frame(storyline_events):
    empty = detections.alerts_to_frame([])
    incidents = correlate.correlate_alerts(empty, storyline_events)

    assert incidents.empty
    assert list(incidents.columns) == list(schemas.INCIDENT_COLUMNS)


# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------


def test_multi_rule_incident_is_escalated(storyline_alerts, storyline_events):
    """Escalation is earned by independent detections agreeing, not by one rule."""
    incidents = correlate.correlate_alerts(storyline_alerts, storyline_events)
    assert incidents.iloc[0]["severity"] == schemas.SEVERITY_CRITICAL


def test_single_rule_incident_is_not_escalated():
    events = make_frame(
        [
            make_event(f"EVT-f{index}", offset_seconds=index * 10,
                       src_ip="198.51.100.23", status=schemas.STATUS_FAILURE)
            for index in range(6)
        ]
    )
    incidents = correlate.correlate_alerts(detections.run_detections(events), events)

    assert incidents.iloc[0]["severity"] == schemas.SEVERITY_MEDIUM


def test_summary_states_it_is_not_a_conclusion(storyline_alerts, storyline_events):
    incidents = correlate.correlate_alerts(storyline_alerts, storyline_events)
    summary = incidents.iloc[0]["summary"].lower()

    assert "not a confirmed cause" in summary or "not a confirmed" in summary


# --------------------------------------------------------------------------
# Investigation queries
# --------------------------------------------------------------------------


def test_timeline_is_in_chronological_order(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    timeline = investigate.build_incident_timeline(loaded_db, incident_id)

    assert timeline["timestamp"].is_monotonic_increasing


def test_timeline_reconstructs_the_full_sequence(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    timeline = investigate.build_incident_timeline(loaded_db, incident_id)

    ordered_types = timeline["event_type"].tolist()
    # Failed logins first, then execution, resolution, connection and the file.
    assert ordered_types[0] == schemas.EVENT_TYPE_AUTHENTICATION
    assert ordered_types[-1] == schemas.EVENT_TYPE_FILE
    for event_type in (
        schemas.EVENT_TYPE_PROCESS,
        schemas.EVENT_TYPE_DNS,
        schemas.EVENT_TYPE_NETWORK,
    ):
        assert event_type in ordered_types


def test_timeline_separates_evidence_from_context(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    timeline = investigate.build_incident_timeline(loaded_db, incident_id)

    roles = dict(zip(timeline["event_id"], timeline["role"]))
    assert roles["EVT-powershell"] == "evidence"
    assert roles["EVT-success"] == "context"


def test_timeline_rows_keep_their_identifying_fields(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    timeline = investigate.build_incident_timeline(loaded_db, incident_id)

    for column in ("timestamp", "event_id", "host", "user", "source_type", "event_type"):
        assert column in timeline.columns
        assert timeline[column].notna().all()


def test_search_by_host(loaded_db):
    assert len(investigate.events_by_host(loaded_db, "WS-001")) == 11
    assert investigate.events_by_host(loaded_db, "WS-999").empty


def test_search_by_user(loaded_db):
    assert len(investigate.events_by_user(loaded_db, "analyst_demo")) == 11


def test_search_by_ip_matches_either_direction(loaded_db):
    """An analyst chasing an address does not know which end it was."""
    assert len(investigate.events_by_ip(loaded_db, "198.51.100.23")) == 7  # source
    assert len(investigate.events_by_ip(loaded_db, "203.0.113.50")) == 1   # destination


def test_search_by_domain(loaded_db):
    assert len(investigate.events_by_domain(loaded_db, "demo-suspicious.example")) == 1


def test_search_by_process(loaded_db):
    assert len(investigate.events_by_process(loaded_db, "powershell")) == 2


def test_time_window_search(loaded_db, base_time):
    window = investigate.events_in_window(
        loaded_db, base_time, base_time + timedelta(seconds=200)
    )
    assert len(window) == 7  # six failures and the success


def test_free_text_hunt_finds_an_indicator_anywhere(loaded_db):
    assert len(investigate.hunt(loaded_db, "203.0.113.50")) == 1
    assert len(investigate.hunt(loaded_db, "analyst_demo")) == 11
    assert investigate.hunt(loaded_db, "").empty


def test_hunt_is_case_insensitive(loaded_db):
    assert len(investigate.hunt(loaded_db, "PowerShell.EXE")) == 2


def test_hunt_does_not_execute_injected_sql(loaded_db):
    """Search terms are parameters, never SQL text."""
    before = database.table_counts(loaded_db)["security_events"]
    investigate.hunt(loaded_db, "'; DROP TABLE security_events; --")
    assert database.table_counts(loaded_db)["security_events"] == before


def test_alert_evidence_is_retrievable(loaded_db):
    alerts = investigate.list_alerts(loaded_db)
    alert_id = alerts[alerts["rule_id"] == "RULE-001"].iloc[0]["alert_id"]
    evidence = investigate.get_alert_evidence(loaded_db, alert_id)

    assert len(evidence) == 6
    assert (evidence["status"] == schemas.STATUS_FAILURE).all()


def test_incident_evidence_is_retrievable(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    evidence = investigate.get_incident_evidence(loaded_db, incident_id)
    assert len(evidence) == 11


def test_incident_alerts_are_retrievable(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    assert len(investigate.get_incident_alerts(loaded_db, incident_id)) == 5


def test_unknown_ids_return_empty_not_an_error(loaded_db):
    assert investigate.get_incident(loaded_db, "INC-nope") is None
    assert investigate.get_alert(loaded_db, "ALR-nope") is None
    assert investigate.get_incident_evidence(loaded_db, "INC-nope").empty
    assert investigate.build_incident_timeline(loaded_db, "INC-nope").empty


def test_incident_summary_collects_indicators(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    context = investigate.summarize_incident(loaded_db, incident_id)

    assert context["indicators"]["source_ips"] == ["198.51.100.23"]
    assert context["indicators"]["destination_ips"] == ["203.0.113.50"]
    assert context["indicators"]["domains"] == ["demo-suspicious.example"]
    assert context["indicators"]["processes"] == ["powershell.exe"]


# --------------------------------------------------------------------------
# Storage guarantees
# --------------------------------------------------------------------------


def test_reloading_does_not_duplicate_rows(loaded_db, storyline_events):
    """Running the pipeline twice must not double the contents of the store."""
    before = database.table_counts(loaded_db)
    database.load_events(loaded_db, storyline_events)
    assert database.table_counts(loaded_db) == before


def test_event_ids_are_unique_in_the_store(loaded_db):
    total, distinct = loaded_db.execute(
        "SELECT count(*), count(DISTINCT event_id) FROM security_events"
    ).fetchone()
    assert total == distinct


# --------------------------------------------------------------------------
# AI investigation layer
# --------------------------------------------------------------------------


def test_investigation_falls_back_without_a_local_model(loaded_db, monkeypatch):
    """The project has to work with no model service running."""
    monkeypatch.setattr(ai_investigator, "ollama_available", lambda *a, **k: False)
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    result = ai_investigator.investigate_incident(loaded_db, incident_id)

    assert result["mode"] == ai_investigator.MODE_DETERMINISTIC
    assert result["notice"]
    for heading in (
        "Incident summary",
        "Observed evidence",
        "Likely sequence",
        "Risk assessment",
        "Recommended investigation steps",
        "Evidence gaps",
    ):
        assert heading in result["text"]


def test_model_failure_falls_back_rather_than_raising(loaded_db, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(ai_investigator, "ollama_available", lambda *a, **k: True)
    monkeypatch.setattr(ai_investigator, "query_ollama", explode)

    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    result = ai_investigator.investigate_incident(loaded_db, incident_id)

    assert result["mode"] == ai_investigator.MODE_DETERMINISTIC
    assert "connection reset" in result["notice"]


def test_ai_path_is_used_when_a_model_answers(loaded_db, monkeypatch):
    monkeypatch.setattr(ai_investigator, "ollama_available", lambda *a, **k: True)
    monkeypatch.setattr(ai_investigator, "query_ollama", lambda *a, **k: "notes")

    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    result = ai_investigator.investigate_incident(loaded_db, incident_id)

    assert result["mode"] == ai_investigator.MODE_AI
    assert result["text"] == "notes"


def test_empty_model_response_falls_back(loaded_db, monkeypatch):
    monkeypatch.setattr(ai_investigator, "ollama_available", lambda *a, **k: True)
    monkeypatch.setattr(ai_investigator, "query_ollama", lambda *a, **k: "")

    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    result = ai_investigator.investigate_incident(loaded_db, incident_id)
    assert result["mode"] == ai_investigator.MODE_DETERMINISTIC


def test_evidence_package_contains_only_stored_evidence(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    package = ai_investigator.build_evidence_package(loaded_db, incident_id)
    rendered = ai_investigator.render_evidence_text(package)

    assert package["incident_id"] == incident_id
    assert "198.51.100.23" in rendered
    assert "demo-suspicious.example" in rendered
    assert len(package["timeline"]) == 11


def test_prompt_constrains_the_model(loaded_db):
    incident_id = investigate.list_incidents(loaded_db).iloc[0]["incident_id"]
    package = ai_investigator.build_evidence_package(loaded_db, incident_id)
    prompt = ai_investigator.build_investigation_prompt(package)
    system = ai_investigator.SYSTEM_PROMPT.lower()

    assert "never invent" in system
    assert "only the evidence" in system
    assert "do not output commands" in system
    assert "EVIDENCE PACKAGE" in prompt


def test_unknown_incident_is_handled(loaded_db):
    result = ai_investigator.investigate_incident(loaded_db, "INC-nope")
    assert result["mode"] == ai_investigator.MODE_DETERMINISTIC
    assert "No incident found" in result["text"]


# --------------------------------------------------------------------------
# Regressions
# --------------------------------------------------------------------------


def test_evidence_ids_survive_every_null_flavour():
    """A null evidence list must read as "no evidence", never as an id.

    pandas' NA raises on bool() and stringifies to "<NA>", so a naive split
    produced a bogus identifier that matched no event - losing the evidence
    silently rather than erroring.
    """
    for value in (None, "", pd.NA, float("nan"), pd.NaT):
        assert schemas.split_ids(value) == []
        assert investigate.split_ids(value) == []

    assert schemas.split_ids("a,b,,c") == ["a", "b", "c"]
    assert schemas.split_ids("single") == ["single"]


def test_correlation_handles_alerts_with_no_evidence_list():
    """Correlation must not crash on an alert whose evidence list is null."""
    alerts = detections.alerts_to_frame(
        [
            {
                "alert_id": "ALR-x",
                "created_at": BASE_TIME,
                "rule_id": "RULE-001",
                "rule_name": "Repeated authentication failures",
                "host": "WS-001",
                "user": "analyst_demo",
                "event_id": "EVT-x",
                "evidence_event_ids": None,
                "evidence_count": 0,
                "severity": schemas.SEVERITY_MEDIUM,
                "reason": "r",
                "status": schemas.STATUS_OPEN,
                "technique_id": "T1110",
                "technique_name": "Brute Force",
            }
        ]
    )
    incidents = correlate.correlate_alerts(alerts, make_frame([]))
    assert len(incidents) == 1
    assert incidents.iloc[0]["evidence_count"] == 0


def test_search_terms_match_literally_not_as_wildcards(loaded_db):
    """LIKE metacharacters in a search term must not widen the search.

    Account names here contain underscores (analyst_demo, svc_backup), and an
    unescaped "_" matches any single character - so this is a live source of
    wrong results, not a theoretical one.
    """
    total = database.table_counts(loaded_db)["security_events"]

    # A bare wildcard is a literal that matches nothing in this data.
    assert len(investigate.hunt(loaded_db, "%")) == 0
    assert len(investigate.hunt(loaded_db, "analyst%demo")) == 0
    # The underscore in the real account name still matches it.
    assert len(investigate.hunt(loaded_db, "analyst_demo")) == total
    # "WS-00_" is not a real hostname, so it must not match WS-001.
    assert len(investigate.hunt(loaded_db, "WS-00_")) == 0
    assert len(investigate.hunt(loaded_db, "WS-001")) == total

    # Field filters use the same escaping.
    assert len(investigate.search_events(loaded_db, domain="%")) == 0
    assert len(investigate.search_events(loaded_db, process="%")) == 0
    assert len(investigate.search_events(loaded_db, process="powershell")) == 2


def test_backslashes_in_search_terms_are_matched_literally(loaded_db):
    """Windows paths are full of backslashes - the escape char itself."""
    assert len(investigate.hunt(loaded_db, r"C:\Temp\demo_payload.bin")) == 1
    assert len(investigate.hunt(loaded_db, "\\")) == 1
    # A path that differs only where the escape char sits must not match.
    assert len(investigate.hunt(loaded_db, r"C:\Temp\demo%payload.bin")) == 0


def test_mixed_offset_timestamps_converge_instead_of_vanishing():
    """Two spellings of one instant must land on one value, not on NaT.

    Converting a timestamp column without `utc=True` cannot produce a single
    dtype when the values carry different offsets, so `errors="coerce"` turns
    the odd one out into NaT - the finding survives with its time silently
    erased. Every alert and incident timestamp goes through the same
    conversion for that reason.
    """
    from datetime import timezone

    utc = BASE_TIME.replace(tzinfo=timezone.utc)
    plus_two = (BASE_TIME + timedelta(hours=2)).replace(
        tzinfo=timezone(timedelta(hours=2))
    )

    def alert(alert_id, created_at):
        return {
            "alert_id": alert_id,
            "created_at": created_at,
            "rule_id": "RULE-001",
            "rule_name": "Repeated authentication failures",
            "host": "WS-001",
            "user": "analyst_demo",
            "event_id": "EVT-x",
            "evidence_event_ids": "EVT-x",
            "evidence_count": 1,
            "severity": schemas.SEVERITY_MEDIUM,
            "reason": "r",
            "status": schemas.STATUS_OPEN,
            "technique_id": "T1110",
            "technique_name": "Brute Force",
        }

    frame = detections.alerts_to_frame([alert("ALR-a", utc), alert("ALR-b", plus_two)])

    assert frame["created_at"].notna().all(), "a timestamp was coerced away"
    assert frame["created_at"].nunique() == 1, "the same instant produced two values"
    assert frame["created_at"].iloc[0] == pd.Timestamp(BASE_TIME)


def test_naive_timestamps_are_left_alone():
    """The conversion reads naive input as UTC; it must not shift it."""
    assert schemas.to_naive_utc(pd.Series([BASE_TIME])).iloc[0] == pd.Timestamp(BASE_TIME)
    assert pd.isna(schemas.to_naive_utc(pd.Series(["not-a-time"])).iloc[0])
