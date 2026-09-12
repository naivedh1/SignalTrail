"""Tests for the analyst console.

Two kinds of check live here, and the split matters.

The first kind tests the presentation layer directly. Those functions return
markup from data, so they can be asserted on without a browser: that a
severity badge always carries its label as text, that database values are
escaped before they reach the page, that the attack sequence orders stages by
evidence rather than by a preferred story.

The second kind runs the whole app through Streamlit's ``AppTest`` and asserts
that every section renders without an exception - in the four states the
dashboard actually has to survive: a populated database, an empty one, a
missing one, and a search that matches nothing. A console that throws on an
empty result is worse than one that looks plain.

Nothing here reaches the network. The local model probe is stubbed in every
app test, because whether Ollama happens to be running on the machine running
the tests must not change the result.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import ai_investigator  # noqa: E402
from src import config  # noqa: E402
from src import correlate  # noqa: E402
from src import database  # noqa: E402
from src import detections  # noqa: E402
from src import schemas  # noqa: E402
from src import ui  # noqa: E402

DASHBOARD = PROJECT_ROOT / "src" / "dashboard.py"
CONFIG_TOML = PROJECT_ROOT / ".streamlit" / "config.toml"

#: Section names, matching src/dashboard.py. Duplicated deliberately: if a
#: section is renamed, this list should have to be updated too.
SECTIONS = [
    "Overview",
    "Detection",
    "Investigation",
    "Threat Hunting",
    "AI Investigation",
    "Anomalies",
]
NAV_KEY = "sgt_page"

#: Model scoring and the first DuckDB read are slower than AppTest's default.
APP_TIMEOUT = 60


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def offline_model(monkeypatch):
    """Keep every test hermetic by declaring the local model unreachable.

    The AI section probes Ollama on render. Whether a developer happens to
    have it running must not decide whether the tests pass, so the probe is
    stubbed for all of them and re-stubbed explicitly where the connected
    path is what is under test.
    """
    monkeypatch.setattr(ai_investigator, "ollama_available", lambda *a, **k: False)
    monkeypatch.setattr(ai_investigator, "available_models", lambda *a, **k: [])


def _write_database(path: Path, events: pd.DataFrame) -> None:
    """Build a database the way run_pipeline.py does, at test scale."""
    with database.connection(path) as conn:
        database.initialize(conn)
        database.load_events(conn, events)
        alerts = detections.run_detections(events)
        database.load_alerts(conn, alerts)
        incidents = correlate.correlate_alerts(alerts, events)
        database.load_incidents(conn, incidents)


@pytest.fixture
def populated_db(tmp_path, storyline_events, monkeypatch) -> Path:
    """A database with events, alerts and a correlated incident."""
    path = tmp_path / "signaltrail.duckdb"
    _write_database(path, storyline_events)
    monkeypatch.setattr(config, "DB_PATH", path)
    return path


@pytest.fixture
def busy_db(tmp_path, storyline_events, monkeypatch) -> Path:
    """A database with enough activity windows for the anomaly model to fit.

    The storyline on its own is seven minutes of one host, which is fewer
    behaviour windows than the model has features - a state the Anomalies
    section reports rather than scores. This adds quiet background traffic so
    the scored path is exercised as well.
    """
    from conftest import make_event, make_frame

    hosts = ["WS-002", "WS-003", "SRV-001"]
    users = ["j.rivera", "m.chen", "k.osei"]
    background = [
        make_event(
            f"EVT-bg{index}",
            offset_seconds=600 + index * 180,
            host=hosts[index % 3],
            user=users[index % 3],
            source_type="dns",
            event_type=schemas.EVENT_TYPE_DNS,
            action="dns_query",
            status=schemas.STATUS_SUCCESS,
            domain=f"service{index % 7}.example.com",
        )
        for index in range(60)
    ]
    events = pd.concat(
        [storyline_events, make_frame(background)], ignore_index=True
    ).sort_values("timestamp", ignore_index=True)

    path = tmp_path / "busy.duckdb"
    _write_database(path, events)
    monkeypatch.setattr(config, "DB_PATH", path)
    return path


@pytest.fixture
def empty_db(tmp_path, monkeypatch) -> Path:
    """A database whose tables exist but hold nothing."""
    path = tmp_path / "empty.duckdb"
    with database.connection(path) as conn:
        database.initialize(conn)
    monkeypatch.setattr(config, "DB_PATH", path)
    return path


@pytest.fixture
def missing_db(tmp_path, monkeypatch) -> Path:
    """A path where no database has been created."""
    path = tmp_path / "absent.duckdb"
    monkeypatch.setattr(config, "DB_PATH", path)
    return path


def run_section(section: str = "Overview", **session) -> AppTest:
    """Render one section of the dashboard and return the finished app."""
    app = AppTest.from_file(str(DASHBOARD), default_timeout=APP_TIMEOUT)
    app.session_state[NAV_KEY] = section
    for key, value in session.items():
        app.session_state[key] = value
    return app.run()


def page_text(app: AppTest) -> str:
    """Everything the app rendered as markdown, as one searchable string."""
    return "\n".join(block.value for block in app.markdown)


# --------------------------------------------------------------------------
# The visual system
# --------------------------------------------------------------------------


def test_palette_is_mirrored_into_the_streamlit_theme():
    """The two definitions of the palette have to agree.

    Streamlit themes its own widgets from config.toml and the custom markup is
    themed from ui.PALETTE. If those drift, tables stop matching the panels
    they sit in - which looks like a bug and is invisible in code review.
    """
    theme = tomllib.loads(CONFIG_TOML.read_text(encoding="utf-8"))["theme"]
    assert theme["backgroundColor"] == ui.PALETTE["bg"]
    assert theme["secondaryBackgroundColor"] == ui.PALETTE["panel"]
    assert theme["textColor"] == ui.PALETTE["text"]
    assert theme["primaryColor"] == ui.PALETTE["accent"]
    assert theme["borderColor"] == ui.PALETTE["border"]
    assert theme["base"] == "dark"


def test_every_severity_has_a_distinct_colour():
    colours = [ui.severity_color(level) for level in schemas.SEVERITY_ORDER]
    assert len(set(colours)) == len(schemas.SEVERITY_ORDER)


def test_severity_badge_names_the_level_in_text():
    """Colour is reinforcement, never the only channel."""
    for level in schemas.SEVERITY_ORDER:
        badge = ui.severity_badge(level)
        assert level in badge
        assert ui._slug(level) in badge


def test_severity_badge_tolerates_an_unknown_level():
    badge = ui.severity_badge("NONSENSE")
    assert "NONSENSE" in badge


def test_markup_escapes_values_taken_from_the_database():
    """Hostnames and file paths are rendered as text, never as markup."""
    hostile = '<img src=x onerror="alert(1)">'
    card = ui.render_indicator_card("Files", [hostile])
    assert "<img" not in card
    assert "&lt;img" in card

    kpi = ui.render_kpi_card("Events", hostile, note=hostile)
    assert "<img" not in kpi
    assert "onerror" not in kpi or "&quot;" in kpi


def test_indicator_card_reports_the_full_count_when_truncated():
    card = ui.render_indicator_card("Domains", [f"d{i}.example" for i in range(9)], limit=4)
    assert ">9<" in card  # the count is of everything, not of what is shown
    assert "+5 more" in card


def test_indicator_card_says_when_nothing_was_recorded():
    assert "none recorded" in ui.render_indicator_card("Files", [])


def test_formatters():
    assert ui.fmt_int(1225) == "1,225"
    assert ui.fmt_int(None) == "0"
    assert ui.fmt_time(pd.Timestamp("2026-09-10 10:01:12")) == "2026-09-10 10:01:12"
    assert ui.fmt_time(None) == ""
    start = pd.Timestamp("2026-09-10 10:00:00")
    assert ui.fmt_duration(start, start + pd.Timedelta(minutes=6)) == "6 min"
    assert ui.fmt_duration(start, start + pd.Timedelta(seconds=20)) == "< 1 min"
    assert ui.fmt_duration(start, start + pd.Timedelta(hours=2, minutes=5)) == "2 h 05 m"
    assert ui.fmt_duration(None, None) == "unknown"


def test_style_severity_column_keeps_the_underlying_values():
    frame = pd.DataFrame({"Severity": ["HIGH", "LOW"], "Host": ["WS-001", "WS-002"]})
    styled = ui.style_severity_column(frame)
    assert list(styled.data["Severity"]) == ["HIGH", "LOW"]


def test_style_severity_column_passes_through_an_empty_frame():
    frame = pd.DataFrame({"Severity": []})
    assert ui.style_severity_column(frame) is frame


# --------------------------------------------------------------------------
# Presentation models
# --------------------------------------------------------------------------


def test_attack_sequence_orders_stages_by_their_evidence(storyline_events):
    alerts = detections.run_detections(storyline_events)
    stages = ui.attack_sequence(alerts, storyline_events)

    names = [stage["name"] for stage in stages]
    assert "Authentication failures" in names
    assert "Encoded PowerShell" in names
    # Ordering comes from the evidence, not from a template of what an attack
    # "should" look like.
    times = [stage["time"] for stage in stages]
    assert times == sorted(times)


def test_attack_sequence_reports_an_observed_successful_login(storyline_events):
    alerts = detections.run_detections(storyline_events)
    stages = ui.attack_sequence(alerts, storyline_events)
    login = [stage for stage in stages if stage["name"] == "Successful login"]
    assert len(login) == 1
    assert login[0]["kind"] == "Observed"


def test_attack_sequence_invents_nothing_from_nothing():
    empty = pd.DataFrame(columns=["rule_id", "rule_name", "severity", "created_at"])
    assert ui.attack_sequence(empty, pd.DataFrame()) == []


def test_investigation_notes_split_into_their_six_sections(storyline_events):
    """The deterministic notes are the contract the section view relies on."""
    path_free_package = {
        "incident_id": "INC-test",
        "title": "Test incident",
        "severity": schemas.SEVERITY_HIGH,
        "host": "WS-001",
        "user": "analyst_demo",
        "start_time": pd.Timestamp("2026-09-10 10:00:00"),
        "end_time": pd.Timestamp("2026-09-10 10:07:00"),
        "evidence_count": 11,
        "deterministic_summary": "A summary.",
        "rule_ids": ["RULE-001"],
        "alerts": detections.run_detections(storyline_events),
        "timeline": pd.DataFrame(),
        "indicators": {
            "source_ips": ["198.51.100.23"],
            "destination_ips": [],
            "domains": [],
            "processes": ["powershell.exe"],
            "files": [],
        },
    }
    text = ai_investigator.deterministic_investigation(path_free_package)
    sections = ui.split_notes_sections(text)
    headings = [heading for heading, _ in sections]
    assert headings == ui.NOTE_HEADINGS
    assert all(body.strip() for _, body in sections)


def test_unstructured_model_output_still_renders_as_one_section():
    sections = ui.split_notes_sections("The model ignored the format entirely.")
    assert sections == [("", "The model ignored the format entirely.")]


def test_numbered_list_items_are_not_mistaken_for_headings():
    text = "## 1. Incident summary\n\n1. Check the account owner.\n2. Then the host."
    sections = ui.split_notes_sections(text)
    assert len(sections) == 1
    assert "2. Then the host." in sections[0][1]


def test_empty_notes_produce_no_sections():
    assert ui.split_notes_sections("") == []
    assert ui.split_notes_sections(None) == []


# --------------------------------------------------------------------------
# The app: a populated database
# --------------------------------------------------------------------------


@pytest.mark.parametrize("section", SECTIONS)
def test_every_section_renders_with_data(populated_db, section):
    app = run_section(section)
    assert not app.exception


def test_overview_shows_the_headline_counts(populated_db):
    app = run_section("Overview")
    assert not app.exception
    text = page_text(app)
    assert "Events" in text
    assert "High / critical" in text
    assert "Incidents" in text
    assert "Incident snapshot" in text


def test_sidebar_reports_what_is_loaded(populated_db):
    app = run_section("Overview")
    sidebar = "\n".join(block.value for block in app.sidebar.markdown)
    assert "SignalTrail" in sidebar
    assert "Events" in sidebar
    assert "Alerts" in sidebar
    assert "Incidents" in sidebar
    assert "Range (UTC)" in sidebar


def test_navigation_switches_section(populated_db):
    app = run_section("Overview")
    app.button("sgtnav-detection").click().run()
    assert not app.exception
    assert app.session_state[NAV_KEY] == "Detection"


def test_every_section_is_reachable_from_the_sidebar(populated_db):
    app = run_section("Overview")
    keys = {button.key for button in app.button}
    for section in SECTIONS:
        assert "sgtnav-" + section.lower().replace(" ", "-") in keys


def test_overview_can_hand_an_incident_to_the_investigation(populated_db):
    """The drill-down has to carry the incident, not just the section."""
    app = run_section("Overview")
    opens = [
        button
        for button in app.button
        if button.key and button.key.startswith("open_INC-")
    ]
    assert opens, "the incident snapshot should offer a way into the investigation"
    incident_id = opens[0].key.removeprefix("open_")

    opens[0].click().run()
    assert not app.exception
    assert app.session_state[NAV_KEY] == "Investigation"
    # The incident that was clicked is the one now on screen, identified by
    # the id the investigation header prints.
    assert incident_id in page_text(app)


def test_detection_filters_narrow_the_alert_table(populated_db):
    app = run_section("Detection")
    assert not app.exception
    total = len(app.multiselect("detect_rule").options)
    app.multiselect("detect_rule").select("RULE-002").run()
    assert not app.exception
    assert total > 1
    assert "1 of " in page_text(app)


def test_detection_filter_with_no_matches_explains_itself(populated_db):
    """Two filters that never co-occur should say so, not render a blank table."""
    app = run_section("Detection")
    app.multiselect("detect_severity").select(schemas.SEVERITY_HIGH).run()
    app.multiselect("detect_rule").select("RULE-001").run()
    assert not app.exception
    text = page_text(app)
    assert "No alerts match the current filters" in text
    assert "Remove one filter at a time" in text


def test_investigation_shows_the_sequence_timeline_and_indicators(populated_db):
    app = run_section("Investigation")
    assert not app.exception
    text = page_text(app)
    assert "Attack sequence" in text
    assert "Timeline" in text
    assert "Indicators" in text
    assert "Evidence records" in text
    # Certainty is never asserted on the analyst's behalf.
    assert "Observed" in text


def test_threat_hunting_reports_a_real_result(populated_db):
    app = run_section("Threat Hunting")
    assert not app.exception
    app.text_input("hunt_term").set_value("WS-001").run()
    assert not app.exception
    text = page_text(app)
    assert "Result summary" in text
    assert "Matching events" in text


def test_threat_hunting_with_no_matches_shows_a_useful_empty_state(populated_db):
    app = run_section("Threat Hunting")
    app.text_input("hunt_term").set_value("no-such-indicator-anywhere").run()
    assert not app.exception
    text = page_text(app)
    assert "No matching events" in text
    # An empty state that does not say what to try next is just an error.
    assert "case-insensitive" in text or "shorter fragment" in text
    assert "Something went wrong" not in text


def test_anomalies_rank_without_claiming_certainty(busy_db):
    app = run_section("Anomalies")
    assert not app.exception
    text = page_text(app)
    assert "Windows analysed" in text
    assert "Top anomalous activity windows" in text
    # The ranking is never dressed up as a verdict.
    assert "investigation aid" in text
    assert "does not confirm" in text
    assert "% malicious" not in text


def test_anomalies_say_when_there_is_too_little_to_score(populated_db):
    """Too few windows is a stated limit of the model, not a failure."""
    app = run_section("Anomalies")
    assert not app.exception
    assert "Not enough activity windows to score" in page_text(app)


def test_ai_section_states_that_the_model_is_unavailable(populated_db):
    app = run_section("AI Investigation")
    assert not app.exception
    text = page_text(app)
    assert "Not available" in text
    assert "supported state" in text


def test_ai_section_falls_back_to_the_deterministic_notes(populated_db):
    app = run_section("AI Investigation")
    app.button("ai_generate").click().run()
    assert not app.exception
    text = page_text(app)
    assert "Evidence summary" in text
    assert "Observed evidence" in text
    assert "Evidence gaps" in text


def test_ai_section_renders_model_output_in_sections(populated_db, monkeypatch):
    """The connected path, without a model: the UI must not require one."""
    monkeypatch.setattr(ai_investigator, "ollama_available", lambda *a, **k: True)
    monkeypatch.setattr(ai_investigator, "available_models", lambda *a, **k: ["test"])
    monkeypatch.setattr(
        ai_investigator,
        "query_ollama",
        lambda *a, **k: (
            "## 1. Incident summary\nA short summary.\n\n"
            "## 2. Observed evidence\nSome evidence.\n\n"
            "## 6. Evidence gaps\nSome gaps."
        ),
    )
    app = run_section("AI Investigation")
    assert not app.exception
    assert "Connected" in page_text(app)

    app.button("ai_generate").click().run()
    assert not app.exception
    text = page_text(app)
    assert "Local model" in text
    assert "A short summary." in text
    assert "Some gaps." in text


def test_reload_button_is_available(populated_db):
    app = run_section("Overview")
    app.button("reload_db").click().run()
    assert not app.exception


# --------------------------------------------------------------------------
# The app: degraded states
# --------------------------------------------------------------------------


@pytest.mark.parametrize("section", SECTIONS)
def test_every_section_survives_an_empty_database(empty_db, section):
    """An empty database is a state, not a fault."""
    app = run_section(section)
    assert not app.exception


def test_empty_database_explains_what_to_run(empty_db):
    app = run_section("Overview")
    text = page_text(app)
    assert "The database is empty" in text
    assert "run_pipeline.py" in text


def test_empty_database_still_offers_navigation(empty_db):
    app = run_section("Overview")
    keys = {button.key for button in app.button}
    assert "sgtnav-detection" in keys


@pytest.mark.parametrize("section", SECTIONS)
def test_missing_database_never_throws(missing_db, section):
    app = run_section(section)
    assert not app.exception


def test_missing_database_says_how_to_create_one(missing_db):
    app = run_section("Overview")
    text = page_text(app)
    assert "No database found" in text
    assert any("run_pipeline.py" in block.value for block in app.code)


def test_missing_database_keeps_the_sidebar(missing_db):
    app = run_section("Overview")
    sidebar = "\n".join(block.value for block in app.sidebar.markdown)
    assert "SignalTrail" in sidebar
    assert "not found" in sidebar
