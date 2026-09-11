"""Streamlit dashboard: the analyst-facing view of SignalTrail.

The layout follows the questions an analyst actually asks, in order: what
happened, where, who, when, why was it flagged, what evidence supports it,
and what to check next. Each section answers one of those and hands off to the
next, reached from a persistent left rail rather than a row of tabs - one
section renders per run, which is also why the page stays quick with a
thousand events loaded.

Design choices worth stating, because they were deliberate:

* Evidence is never more than one click away. Every alert and incident view
  can expand to the underlying records, including the original raw message.
* Confidence is never fabricated. Severities are labels with defined meaning;
  there are no invented percentages or risk scores presented as certainty.
* The AI tab is clearly marked as optional and shows the evidence package the
  text was generated from, so the reader can check it.
* Nothing in this module decides what anything looks like. Colour, spacing and
  markup come from ``src/ui.py``; this file arranges the data.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Streamlit runs this file as a script, so the project root is not
# automatically importable. Adding it keeps "streamlit run src/dashboard.py"
# working from a clean checkout without an install step.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd  # noqa: E402
import plotly.express as px  # noqa: E402
import streamlit as st  # noqa: E402

from src import ai_investigator  # noqa: E402
from src import analytics  # noqa: E402
from src import anomaly as anomaly_module  # noqa: E402
from src import config  # noqa: E402
from src import database  # noqa: E402
from src import detections  # noqa: E402
from src import investigate  # noqa: E402
from src import schemas  # noqa: E402
from src import ui  # noqa: E402

st.set_page_config(
    page_title="SignalTrail",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

#: Re-exported so the palette has one import path for anything outside the UI
#: module that needs it.
SEVERITY_COLORS = ui.SEVERITY_COLORS

#: The normalized fields an analyst scans first, in reading order. Columns
#: that are entirely empty for a given result set are dropped from the view -
#: a DNS-only result has no ports or file paths worth six columns of blanks -
#: and the complete record stays available beneath every table.
EVENT_TABLE_COLUMNS = [
    "timestamp",
    "host",
    "user",
    "source_type",
    "event_type",
    "action",
    "status",
    "src_ip",
    "dst_ip",
    "dst_port",
    "domain",
    "process_name",
    "file_path",
]

#: Columns kept even when empty, because their absence would make rows
#: ambiguous rather than merely sparse.
ALWAYS_VISIBLE_COLUMNS = {
    "timestamp",
    "host",
    "user",
    "source_type",
    "event_type",
    "action",
    "status",
}

# Column presentation for the normalized event model. Widths are fixed so a
# long command line cannot push the table into horizontal scrolling; the full
# value is still in the cell, and in the raw record beneath it.
EVENT_COLUMN_CONFIG = {
    "timestamp": st.column_config.DatetimeColumn(
        "Time", format=ui.TIMESTAMP_COLUMN_FORMAT, width=150
    ),
    "host": st.column_config.TextColumn("Host", width=80),
    "user": st.column_config.TextColumn("User", width=104),
    "source_type": st.column_config.TextColumn("Source", width=100),
    "event_type": st.column_config.TextColumn("Type", width=100),
    "action": st.column_config.TextColumn("Action", width=132),
    "status": st.column_config.TextColumn("Status", width=76),
    "src_ip": st.column_config.TextColumn("Source IP", width=116),
    "dst_ip": st.column_config.TextColumn("Dest IP", width=116),
    # No format string: Streamlit renders a null through "%d" as the
    # literal word "None", and most events have no port.
    "dst_port": st.column_config.NumberColumn("Port", width=64),
    "domain": st.column_config.TextColumn("Domain", width=176),
    "process_name": st.column_config.TextColumn("Process", width=128),
    "file_path": st.column_config.TextColumn("File", width=200),
    "command_line": st.column_config.TextColumn("Command line", width=260),
    "event_id": st.column_config.TextColumn("Event ID", width=152),
    "severity": st.column_config.TextColumn("Severity", width=84),
    "raw_message": st.column_config.TextColumn("Raw record", width=300),
    "details": st.column_config.TextColumn("Detail", width=340),
    "role": st.column_config.TextColumn("Role", width=104),
}

PAGE_OVERVIEW = "Overview"
PAGE_DETECTION = "Detection"
PAGE_INVESTIGATION = "Investigation"
PAGE_HUNTING = "Threat Hunting"
PAGE_AI = "AI Investigation"
PAGE_ANOMALIES = "Anomalies"

PAGES = [
    PAGE_OVERVIEW,
    PAGE_DETECTION,
    PAGE_INVESTIGATION,
    PAGE_HUNTING,
    PAGE_AI,
    PAGE_ANOMALIES,
]

#: Session keys. The navigation key is deliberately *not* a widget key: a
#: widget's value cannot be assigned once that widget has been created in the
#: current run, which is exactly what a "open this incident" button needs to do.
NAV_KEY = "sgt_page"
PENDING_INCIDENT_KEY = "sgt_pending_incident"

LOCK_ADVICE = (
    "The database is currently locked by another process - most likely "
    "`run_pipeline.py` is writing to it. Wait for the pipeline to finish, then "
    "use **Reload from database** in the sidebar."
)


# --------------------------------------------------------------------------
# Data access
# --------------------------------------------------------------------------


@st.cache_data(show_spinner=False)
def load_tables(db_path: str) -> dict[str, pd.DataFrame]:
    """Read the three tables once per session.

    The dashboard only ever reads, so every connection it opens is read-only -
    it cannot modify the database even by mistake.

    DuckDB takes a file lock, so a single database file cannot be open in two
    processes at once. Connections here are therefore short-lived: opened for
    one query and closed again, rather than held for the session. Running the
    pipeline while the dashboard is idle works; a genuine collision surfaces
    as the notice in `guarded_connection` rather than a traceback.
    """
    with database.connection(db_path, read_only=True) as conn:
        return {
            "events": database.read_table(conn, database.EVENTS_TABLE),
            "alerts": database.read_table(conn, database.ALERTS_TABLE),
            "incidents": database.read_table(conn, database.INCIDENTS_TABLE),
        }


@st.cache_data(show_spinner=False)
def load_entity_options(db_path: str) -> dict[str, list[str]]:
    """Distinct hosts, users, event types and processes for the hunt filters."""
    with database.connection(db_path, read_only=True) as conn:
        return investigate.entity_options(conn)


@st.cache_data(show_spinner=False)
def score_behaviour(events: pd.DataFrame) -> pd.DataFrame:
    """Anomaly scoring, cached so switching pages does not refit the model."""
    return anomaly_module.run_anomaly_detection(events)


@contextmanager
def guarded_connection():
    """Open a read-only connection, or explain why it could not be opened.

    The realistic failure is someone re-running the pipeline with this page
    open: DuckDB's writer holds the file lock and the read fails. That is a
    recoverable situation and deserves an instruction, not a stack trace.
    """
    try:
        conn = database.connect(str(config.DB_PATH), read_only=True)
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a notice
        st.warning(f"{LOCK_ADVICE}\n\n`{exc}`")
        yield None
        return
    try:
        yield conn
    finally:
        conn.close()


def database_ready() -> bool:
    return Path(config.DB_PATH).exists()


def clear_caches() -> None:
    """Drop every cached read, so the next run re-reads the database."""
    load_tables.clear()
    load_entity_options.clear()
    score_behaviour.clear()


# --------------------------------------------------------------------------
# Navigation
# --------------------------------------------------------------------------


def current_page() -> str:
    page = st.session_state.get(NAV_KEY, PAGE_OVERVIEW)
    return page if page in PAGES else PAGE_OVERVIEW


def go_to(page: str, incident_id: str | None = None) -> None:
    """Switch section, optionally opening a specific incident on arrival."""
    st.session_state[NAV_KEY] = page
    if incident_id is not None:
        st.session_state[PENDING_INCIDENT_KEY] = incident_id
    st.rerun()


# --------------------------------------------------------------------------
# Shared rendering helpers
# --------------------------------------------------------------------------


def severity_badge(severity: str) -> str:
    """Severity as a labelled chip. Kept here as the module's public name."""
    return ui.severity_badge(severity)


def _has_values(series: pd.Series) -> bool:
    """Whether a column holds anything worth a column of screen width."""
    try:
        if series.isna().all():
            return False
        text = series.astype("string").fillna("").str.strip()
        return bool((text != "").any())
    except (TypeError, ValueError):
        return True


def visible_event_columns(frame: pd.DataFrame) -> list[str]:
    """The event columns worth showing for this particular result set."""
    columns = []
    for name in EVENT_TABLE_COLUMNS:
        if name not in frame.columns:
            continue
        if name in ALWAYS_VISIBLE_COLUMNS or _has_values(frame[name]):
            columns.append(name)
    return columns


def show_events_table(
    frame: pd.DataFrame,
    height: int = 320,
    *,
    empty_title: str = "No matching events",
    empty_body: str = "Nothing in the loaded telemetry matches this selection.",
    empty_hints: tuple[str, ...] = (),
    details: bool = True,
    key: str | None = None,
) -> None:
    """Render an event table with the columns analysts scan first.

    Columns that are empty for this result set are dropped, and the complete
    record - every normalized field plus the raw source message - stays one
    expander away. Nothing is removed from the data; only the default view is
    narrowed to what is legible.
    """
    if frame.empty:
        ui.render_empty_state(empty_title, empty_body, empty_hints)
        return

    columns = visible_event_columns(frame)
    st.dataframe(
        frame[columns],
        width="stretch",
        height=height,
        hide_index=True,
        column_config=EVENT_COLUMN_CONFIG,
        key=key,
    )
    hidden = [c for c in frame.columns if c not in columns]
    if details and hidden:
        with st.expander(f"All normalized fields ({len(frame.columns)} columns)"):
            st.caption(
                "The same rows with every stored field, including the ones "
                "left out above: " + ", ".join(hidden) + "."
            )
            st.dataframe(
                frame,
                width="stretch",
                height=ui.table_height(len(frame)),
                hide_index=True,
                column_config=EVENT_COLUMN_CONFIG,
            )


def show_timeline(timeline: pd.DataFrame) -> None:
    """Render a timeline, marking which rows a rule actually fired on."""
    if timeline.empty:
        ui.render_empty_state(
            "No events in this timeline",
            "This incident has no evidence events attached to it.",
        )
        return

    ui.render_timeline(timeline)
    ui.render_note(
        "Filled markers are events a rule fired on. Hollow markers are context "
        "that correlation attached because it shares the host, account and "
        "time window."
    )

    display = timeline.copy()
    display["role"] = display["role"].map(
        {"evidence": "rule evidence", "context": "context"}
    )
    with st.expander("Timeline as a table"):
        st.dataframe(
            display[
                ["timestamp", "role", "host", "user", "event_type", "action", "details"]
            ],
            width="stretch",
            hide_index=True,
            column_config=EVENT_COLUMN_CONFIG,
            height=ui.table_height(len(display), cap=520),
        )


def show_raw_evidence(events: pd.DataFrame) -> None:
    """Expose the original source record behind each normalized event."""
    if events.empty:
        return
    with st.expander("Original source records"):
        st.caption(
            "Every normalized event keeps the record it came from, so any "
            "field shown above can be checked against its source."
        )
        for row in events.itertuples(index=False):
            st.markdown(
                f"**{row.timestamp:%Y-%m-%d %H:%M:%S}** &nbsp; `{row.event_id}` "
                f"&nbsp; {row.source_type}"
            )
            st.code(row.raw_message, language="json")


def incident_for_alert(incidents: pd.DataFrame) -> dict[str, str]:
    """Map each alert to the incident that grouped it, if any."""
    mapping: dict[str, str] = {}
    if incidents.empty:
        return mapping
    for incident in incidents.itertuples(index=False):
        for alert_id in schemas.split_ids(incident.alert_ids):
            mapping[alert_id] = incident.incident_id
    return mapping


def incident_choices(incidents: pd.DataFrame) -> dict[str, str]:
    """Selectbox labels for incidents, most recent first."""
    ordered = incidents.sort_values("start_time", ascending=False)
    return {
        f"{row.severity} | {row.start_time:%Y-%m-%d %H:%M} | {row.title}": row.incident_id
        for row in ordered.itertuples(index=False)
    }


def take_pending_incident(choices: dict[str, str], widget_key: str) -> None:
    """Apply a "open this incident" request made from another section.

    The value has to be written before the selectbox is created, which is why
    the request is parked in its own key and consumed here rather than being
    assigned to the widget directly.
    """
    incident_id = st.session_state.pop(PENDING_INCIDENT_KEY, None)
    if incident_id is None:
        return
    for label, candidate in choices.items():
        if candidate == incident_id:
            st.session_state[widget_key] = label
            return


# --------------------------------------------------------------------------
# A. Overview
# --------------------------------------------------------------------------


def render_overview(tables: dict[str, pd.DataFrame]) -> None:
    events, alerts, incidents = tables["events"], tables["alerts"], tables["incidents"]
    metrics = analytics.overview_metrics(events, alerts, incidents)

    open_alerts = (
        int((alerts["status"] == schemas.STATUS_OPEN).sum()) if not alerts.empty else 0
    )
    rules_fired = int(alerts["rule_id"].nunique()) if not alerts.empty else 0
    alerted_hosts = int(alerts["host"].nunique()) if not alerts.empty else 0
    alerted_users = int(alerts["user"].nunique()) if not alerts.empty else 0
    top_severity = (
        schemas.max_severity(incidents["severity"]) if not incidents.empty else ""
    )

    if events.empty:
        span_note = "no telemetry loaded"
    else:
        days = max((events["timestamp"].max() - events["timestamp"].min()).days, 0) + 1
        span_note = f"{days} day(s) of telemetry"

    ui.render_kpi_row(
        [
            {
                "label": "Events",
                "value": ui.fmt_int(metrics["total_events"]),
                "note": span_note,
            },
            {
                "label": "Hosts",
                "value": ui.fmt_int(metrics["hosts"]),
                "note": f"{alerted_hosts} with alerts",
            },
            {
                "label": "Users",
                "value": ui.fmt_int(metrics["users"]),
                "note": f"{alerted_users} with alerts",
            },
            {
                "label": "Alerts",
                "value": ui.fmt_int(metrics["alerts"]),
                "note": f"{rules_fired} rule(s) triggered",
                "tone": "accent" if metrics["alerts"] else "",
            },
            {
                "label": "High / critical",
                "value": ui.fmt_int(metrics["high_severity_alerts"]),
                "note": f"of {metrics['alerts']} alert(s)",
                "tone": (
                    schemas.SEVERITY_HIGH if metrics["high_severity_alerts"] else ""
                ),
            },
            {
                "label": "Incidents",
                "value": ui.fmt_int(metrics["incidents"]),
                "note": f"{open_alerts} open alert(s)",
                "tone": top_severity,
            },
        ]
    )

    if events.empty and alerts.empty and incidents.empty:
        ui.render_empty_state(
            "The database is empty",
            "SignalTrail is connected, but no telemetry has been ingested yet.",
            (
                "Run python run_pipeline.py to generate and load the synthetic "
                "dataset.",
                "Use Reload from database in the sidebar once it finishes.",
            ),
        )
        return

    left, right = st.columns([3, 2], gap="medium")

    with left:
        ui.render_section_header("Event activity", "events per hour, all sources")
        volume = analytics.events_over_time(events)
        if volume.empty:
            ui.render_empty_state(
                "No events to plot",
                "Ingest telemetry to see activity over time.",
            )
        else:
            figure = px.area(volume, x="bucket", y="events")
            figure.update_traces(
                line_color=ui.PALETTE["accent"],
                line_width=1.6,
                fillcolor=ui.rgba(ui.PALETTE["accent"], 0.16),
                hovertemplate="%{x|%Y-%m-%d %H:%M}<br>%{y} events<extra></extra>",
            )
            figure.update_layout(xaxis_title=None, yaxis_title="events / hour")
            ui.plotly_panel(ui.style_figure(figure, height=248), key="overview_volume")

    with right:
        ui.render_section_header("Alert and incident summary", "by severity")
        by_severity = analytics.alerts_by_severity(alerts)
        if by_severity.empty:
            ui.render_empty_state(
                "No alerts raised",
                "Nothing in the loaded telemetry matched a detection rule.",
            )
        else:
            ordered = by_severity.iloc[::-1]
            figure = px.bar(
                ordered,
                x="alerts",
                y="severity",
                orientation="h",
                color="severity",
                color_discrete_map=ui.SEVERITY_COLORS,
            )
            figure.update_traces(
                hovertemplate="%{y}: %{x} alert(s)<extra></extra>", width=0.62
            )
            figure.update_layout(xaxis_title=None, yaxis_title=None)
            ui.plotly_panel(
                ui.style_figure(figure, height=138, ygrid=False), key="overview_sev"
            )
        ui.render_fact_strip(
            [
                ("Incidents", metrics["incidents"]),
                ("High risk", metrics["high_severity_alerts"]),
                ("Open alerts", open_alerts),
                ("Rules fired", rules_fired),
            ]
        )

    left, right = st.columns([3, 2], gap="medium")

    with left:
        ui.render_section_header(
            "Recent detection activity", f"latest of {len(alerts)} alert(s)"
        )
        ui.render_alert_rows(alerts, limit=8)

    with right:
        ui.render_section_header("Top hosts and indicators", "most frequent first")
        ui.render_indicator_grid(
            {
                "Hosts by alerts": _counted(analytics.alerts_by_host(alerts), "host", "alerts"),
                "Top domains": _counted(analytics.top_values(events, "domain", 5), "domain", "count"),
                "Top destinations": _counted(analytics.top_values(events, "dst_ip", 5), "dst_ip", "count"),
                "Top processes": _counted(
                    analytics.top_values(events, "process_name", 5), "process_name", "count"
                ),
            },
            limit=4,
            columns=2,
        )

    ui.render_section_header(
        "Incident snapshot", f"{len(incidents)} correlated incident(s)"
    )
    if incidents.empty:
        ui.render_empty_state(
            "No incidents correlated",
            "Correlation groups alerts that share a host, an account and a "
            "time window. None of the current alerts group together.",
        )
        return

    ordered = incidents.copy()
    ordered["rank"] = ordered["severity"].map(schemas.SEVERITY_RANK).fillna(0)
    ordered = ordered.sort_values(["rank", "start_time"], ascending=[False, False])

    for incident in ordered.head(6).itertuples(index=False):
        card, action = st.columns([12, 2], gap="small", vertical_alignment="center")
        with card:
            ui.render_incident_card(
                incident._asdict(), len(schemas.split_ids(incident.alert_ids))
            )
        with action:
            if st.button(
                "Investigate",
                key=f"open_{incident.incident_id}",
                width="stretch",
                help="Open this incident in the Investigation section",
            ):
                go_to(PAGE_INVESTIGATION, incident.incident_id)

    if len(ordered) > 6:
        ui.render_note(
            f"Showing the 6 highest-severity incidents of {len(ordered)}. "
            "The Investigation section lists them all."
        )


def _counted(frame: pd.DataFrame, name: str, count: str) -> list[str]:
    """Format a "value / count" aggregate as indicator card lines."""
    if frame.empty or name not in frame.columns:
        return []
    return [f"{row[0]}  ({int(row[1])})" for row in frame[[name, count]].itertuples(index=False)]


# --------------------------------------------------------------------------
# B. Detection
# --------------------------------------------------------------------------

#: Column order for the alert table: what fired, where, when, then the
#: supporting text an analyst reads once they have picked a row.
ALERT_COLUMN_CONFIG = {
    "Severity": st.column_config.TextColumn("Severity", width=82),
    "Rule": st.column_config.TextColumn("Rule", width=215),
    "Host": st.column_config.TextColumn("Host", width=76),
    "User": st.column_config.TextColumn("User", width=96),
    "Created": st.column_config.DatetimeColumn(
        "Created", format=ui.TIMESTAMP_COLUMN_FORMAT, width=138
    ),
    "Status": st.column_config.TextColumn("Status", width=70),
    "Evidence": st.column_config.NumberColumn(
        "Evidence", width=70, format="%d", help="Events attached to this alert"
    ),
    "MITRE": st.column_config.TextColumn(
        "MITRE", width=84, help="Technique the rule suggests - a hypothesis, not a finding"
    ),
    "Reason": st.column_config.TextColumn(
        "Reason",
        width=240,
        help="Why the rule fired. The full text is in the alert detail below.",
    ),
}


def alert_table_frame(alerts: pd.DataFrame) -> pd.DataFrame:
    """Reshape alerts into the analyst-facing column order."""
    return pd.DataFrame(
        {
            "Severity": alerts["severity"],
            "Rule": alerts["rule_id"] + "  " + alerts["rule_name"],
            "Host": alerts["host"],
            "User": alerts["user"],
            "Created": alerts["created_at"],
            "Status": alerts["status"],
            "Evidence": alerts["evidence_count"],
            "MITRE": alerts["technique_id"],
            "Reason": alerts["reason"],
        }
    )


def render_detection(tables: dict[str, pd.DataFrame]) -> None:
    alerts = tables["alerts"]
    events = tables["events"]
    incidents = tables["incidents"]

    if alerts.empty:
        ui.render_empty_state(
            "No alerts have been raised",
            "Detection runs as part of the pipeline; there is nothing to "
            "triage until it has been run against ingested telemetry.",
            (
                "Run python run_pipeline.py to ingest, detect and correlate.",
                "The Anomalies section still works without alerts, and ranks "
                "unusual activity windows.",
            ),
        )
        with st.expander("Rule catalogue"):
            st.dataframe(detections.rule_catalogue(), width="stretch", hide_index=True)
        return

    high = int(alerts["severity"].isin(
        {schemas.SEVERITY_HIGH, schemas.SEVERITY_CRITICAL}
    ).sum())
    open_count = int((alerts["status"] == schemas.STATUS_OPEN).sum())

    ui.render_kpi_row(
        [
            {"label": "Total alerts", "value": ui.fmt_int(len(alerts))},
            {
                "label": "High / critical",
                "value": ui.fmt_int(high),
                "tone": schemas.SEVERITY_HIGH if high else "",
            },
            {"label": "Open", "value": ui.fmt_int(open_count), "note": "awaiting triage"},
            {
                "label": "Rules triggered",
                "value": ui.fmt_int(alerts["rule_id"].nunique()),
                "note": f"of {len(detections.RULES)} defined",
            },
        ]
    )

    ui.render_section_header("Filters", "combined with AND; empty means no filter")
    filter_columns = st.columns([1, 1, 1], gap="small")
    severities = filter_columns[0].multiselect(
        "Severity",
        [s for s in schemas.SEVERITY_ORDER if s in set(alerts["severity"])],
        default=[],
        placeholder="Any severity",
        key="detect_severity",
    )
    rules = filter_columns[1].multiselect(
        "Rule",
        sorted(alerts["rule_id"].unique()),
        default=[],
        placeholder="Any rule",
        key="detect_rule",
    )
    hosts = filter_columns[2].multiselect(
        "Host",
        sorted(alerts["host"].unique()),
        default=[],
        placeholder="Any host",
        key="detect_host",
    )

    filtered = alerts
    if severities:
        filtered = filtered[filtered["severity"].isin(severities)]
    if rules:
        filtered = filtered[filtered["rule_id"].isin(rules)]
    if hosts:
        filtered = filtered[filtered["host"].isin(hosts)]

    ui.render_section_header(
        "Alerts", f"{len(filtered)} of {len(alerts)} shown, newest last"
    )
    if filtered.empty:
        ui.render_empty_state(
            "No alerts match the current filters",
            "The filters above are combined, so a severity and a rule that "
            "never occur together will return nothing.",
            (
                "Remove one filter at a time to find the one excluding "
                "everything.",
                "Clear all three to see every alert again.",
            ),
        )
        return

    st.dataframe(
        ui.style_severity_column(alert_table_frame(filtered)),
        width="stretch",
        hide_index=True,
        column_config=ALERT_COLUMN_CONFIG,
        height=ui.table_height(len(filtered)),
    )

    ui.render_section_header("Alert detail")
    choices = {
        f"{row.severity} | {row.created_at:%Y-%m-%d %H:%M:%S} | {row.rule_id} | {row.host}": row.alert_id
        for row in filtered.itertuples(index=False)
    }
    selected_label = st.selectbox(
        "Select an alert to inspect", list(choices), key="detection_alert"
    )
    alert_id = choices[selected_label]
    alert = filtered[filtered["alert_id"] == alert_id].iloc[0]
    rule = detections.RULES.get(alert["rule_id"])
    related_incident = incident_for_alert(incidents).get(alert_id)

    ui.render_record_header(alert["severity"], alert["rule_id"], alert["rule_name"])
    technique = (
        f"{alert['technique_id']} {alert['technique_name']}"
        if alert["technique_id"]
        else "none mapped"
    )
    ui.render_fact_strip(
        [
            ("Host", alert["host"]),
            ("Account", alert["user"]),
            ("Created", ui.fmt_time(alert["created_at"])),
            ("Status", alert["status"]),
            ("Evidence", int(alert["evidence_count"])),
            ("MITRE", technique),
            ("Incident", related_incident or "not correlated"),
        ]
    )

    st.markdown(f"**Why this fired.** {alert['reason']}")

    if related_incident:
        if st.button(
            "Open the correlated incident",
            key=f"detect_open_{related_incident}",
            help="Switch to the Investigation section with this incident selected",
        ):
            go_to(PAGE_INVESTIGATION, related_incident)

    if rule:
        detail = st.columns(2, gap="medium")
        with detail[0]:
            st.markdown("**Rule logic**")
            st.write(rule.logic)
            st.markdown("**Inputs**")
            st.write(", ".join(rule.inputs))
        with detail[1]:
            if rule.technique_id:
                st.markdown("**Possible ATT&CK technique**")
                st.write(
                    f"{rule.technique_id} - {rule.technique_name} ({rule.tactic})"
                )
                st.caption(
                    "A hypothesis suggested by the rule, not a confirmed "
                    "classification of this activity."
                )
        if rule.false_positives:
            st.markdown("**Benign explanations to rule out first**")
            for cause in rule.false_positives:
                st.markdown(f"- {cause}")

    ui.render_section_header("Evidence", f"{int(alert['evidence_count'])} event(s)")
    evidence_ids = investigate.split_ids(alert["evidence_event_ids"])
    evidence = events[events["event_id"].isin(evidence_ids)].sort_values("timestamp")
    show_events_table(
        evidence,
        height=ui.table_height(len(evidence), cap=320),
        empty_title="No evidence events found",
        empty_body=(
            "The alert references event identifiers that are not in the "
            "loaded events table. Re-run the pipeline to rebuild both together."
        ),
    )
    show_raw_evidence(evidence)

    with st.expander("Rule catalogue"):
        st.caption(
            "Every rule, its logic, the telemetry it needs and its known "
            "benign causes. Detection metadata is kept with the rule so it "
            "can be reviewed without reading code."
        )
        st.dataframe(detections.rule_catalogue(), width="stretch", hide_index=True)


# --------------------------------------------------------------------------
# C. Investigation
# --------------------------------------------------------------------------

RELATED_ALERT_CONFIG = {
    "Severity": st.column_config.TextColumn("Severity", width=82),
    "Rule": st.column_config.TextColumn("Rule", width=190),
    "Created": st.column_config.DatetimeColumn(
        "Created", format=ui.TIMESTAMP_COLUMN_FORMAT, width=138
    ),
    "Evidence": st.column_config.NumberColumn("Evidence", width=70, format="%d"),
    "MITRE": st.column_config.TextColumn("MITRE", width=84),
    "Reason": st.column_config.TextColumn("Reason", width=300),
}

INDICATOR_LABELS = {
    "source_ips": "Source IPs",
    "destination_ips": "Destination IPs",
    "domains": "Domains",
    "processes": "Processes",
    "files": "Files",
}


def render_investigation(tables: dict[str, pd.DataFrame]) -> None:
    incidents = tables["incidents"]
    if incidents.empty:
        ui.render_empty_state(
            "No incidents have been correlated",
            "Correlation groups alerts that share a host, an account and a "
            "time window into one incident. With no alerts, or none that "
            "group, there is nothing to investigate here.",
            (
                "Run python run_pipeline.py to ingest, detect and correlate.",
                "Individual alerts are still reviewable in the Detection "
                "section.",
            ),
        )
        return

    choices = incident_choices(incidents)
    take_pending_incident(choices, "investigation_incident")
    selected_label = st.selectbox(
        "Incident", list(choices), key="investigation_incident"
    )
    incident_id = choices[selected_label]

    with guarded_connection() as conn:
        if conn is None:
            return
        context = investigate.summarize_incident(conn, incident_id)

    if not context:
        ui.render_empty_state(
            "That incident could not be loaded",
            "The incident exists in the loaded table but its record could not "
            "be read back from the database.",
            ("Use Reload from database in the sidebar and try again.",),
        )
        return

    incident = context["incident"]
    alerts = context["alerts"]
    evidence = context["evidence"]

    ui.render_incident_header(incident)
    ui.render_fact_strip(
        [
            ("Host", incident["host"]),
            ("Account", incident["user"]),
            ("Alerts", len(alerts)),
            ("Evidence events", int(incident["evidence_count"])),
            ("Duration", ui.fmt_duration(incident["start_time"], incident["end_time"])),
            ("Status", incident["status"]),
        ]
    )
    ui.render_note(
        f"Window {ui.fmt_time(incident['start_time'])} to "
        f"{ui.fmt_time(incident['end_time'])} UTC - "
        f"{len(context['rule_ids'])} distinct rule(s) fired."
    )

    st.markdown("**Summary**")
    st.write(incident["summary"])

    ui.render_section_header("Attack sequence", "ordered by first supporting event")
    ui.render_attack_sequence(ui.attack_sequence(alerts, evidence))
    ui.render_note(
        "Each stage is something the stored evidence contains. Ordering shows "
        "what followed what; it does not by itself establish that one step "
        "caused another, and a rule firing is not proof of an attack."
    )

    ui.render_section_header("Timeline", f"{len(context['timeline'])} event(s)")
    show_timeline(context["timeline"])

    ui.render_section_header("Related alerts", f"{len(alerts)} in this incident")
    if alerts.empty:
        ui.render_empty_state(
            "No alerts attached",
            "This incident has no alerts recorded against it.",
        )
    else:
        related = pd.DataFrame(
            {
                "Severity": alerts["severity"],
                "Rule": alerts["rule_id"] + "  " + alerts["rule_name"],
                "Created": alerts["created_at"],
                "Evidence": alerts["evidence_count"],
                "MITRE": alerts["technique_id"],
                "Reason": alerts["reason"],
            }
        )
        st.dataframe(
            ui.style_severity_column(related),
            width="stretch",
            hide_index=True,
            column_config=RELATED_ALERT_CONFIG,
            height=ui.table_height(len(related), cap=300),
        )

    ui.render_section_header("Indicators", "observed in this incident's evidence")
    ui.render_indicator_grid(
        {
            INDICATOR_LABELS.get(label, label.replace("_", " ").title()): values
            for label, values in context["indicators"].items()
        }
    )

    ui.render_section_header("Evidence records", f"{len(evidence)} event(s)")
    show_events_table(
        evidence,
        height=ui.table_height(len(evidence)),
        empty_title="No evidence records",
        empty_body="No events are attached to this incident.",
    )
    show_raw_evidence(evidence)

    ui.render_section_header("Widen the window", "same host, all activity")
    ui.render_note(
        "Correlation attaches only events on the same host and account. Widen "
        "the window to see what else the host was doing around the incident."
    )
    minutes = st.slider(
        "Minutes either side of the incident start",
        5,
        180,
        30,
        step=5,
        key="investigation_window",
    )
    with guarded_connection() as conn:
        if conn is None:
            return
        surrounding = investigate.build_host_timeline(
            conn,
            incident["host"],
            incident["start_time"],
            minutes=minutes,
        )
    if surrounding.empty:
        ui.render_empty_state(
            "No surrounding activity recorded",
            f"Nothing else was logged for {incident['host']} within "
            f"{minutes} minutes of the incident start.",
            ("Increase the window above to look further either side.",),
        )
    else:
        st.dataframe(
            surrounding[
                ["timestamp", "host", "user", "event_type", "action", "details"]
            ],
            width="stretch",
            hide_index=True,
            column_config=EVENT_COLUMN_CONFIG,
            height=300,
        )


# --------------------------------------------------------------------------
# D. Threat hunting
# --------------------------------------------------------------------------

#: Row caps on the two hunting queries. A hunt is meant to be read, so an
#: unbounded result would be useless as well as slow - but a truncated result
#: reported as a total is worse than either, so the cap is always stated.
HUNT_TEXT_LIMIT = 500
HUNT_FILTER_LIMIT = 1000

EMPTY_OPTIONS = {"hosts": [], "users": [], "event_types": [], "processes": []}


def hunt_options() -> dict[str, list[str]]:
    """Filter values, or empty lists with a notice if the database is locked."""
    try:
        return load_entity_options(str(config.DB_PATH))
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a notice
        st.warning(f"{LOCK_ADVICE}\n\n`{exc}`")
        return EMPTY_OPTIONS


def render_hunting() -> None:
    ui.render_section_header(
        "Hunt across security telemetry", "every normalized event, not only alerts"
    )
    ui.render_note(
        "Free text searches every field worth pivoting on - paste an address, "
        "a domain, an account or a process name. The filters below describe a "
        "pattern instead, and are used when the search box is empty."
    )

    options = hunt_options()

    term = st.text_input(
        "Search any indicator",
        placeholder="203.0.113.50, demo-suspicious.example, analyst_demo, WS-001, powershell.exe",
        icon=":material/search:",
        key="hunt_term",
    )

    filters = st.columns(3, gap="small")
    host = filters[0].selectbox("Host", ["(any)"] + options["hosts"], key="hunt_host")
    user = filters[1].selectbox("User", ["(any)"] + options["users"], key="hunt_user")
    event_type = filters[2].selectbox(
        "Event type", ["(any)"] + options["event_types"], key="hunt_event_type"
    )

    filters = st.columns(3, gap="small")
    ip = filters[0].text_input("IP address (source or destination)", key="hunt_ip")
    domain = filters[1].text_input("Domain contains", key="hunt_domain")
    process = filters[2].text_input("Process contains", key="hunt_process")

    searching = bool(term.strip())
    if searching:
        ui.render_note(
            "A free-text search is active, so the six filters above are not "
            "applied. Clear the search box to filter instead."
        )

    with guarded_connection() as conn:
        if conn is None:
            return
        if searching:
            limit = HUNT_TEXT_LIMIT
            results = investigate.hunt(conn, term.strip(), limit=limit)
        else:
            limit = HUNT_FILTER_LIMIT
            results = investigate.search_events(
                conn,
                host=None if host == "(any)" else host,
                user=None if user == "(any)" else user,
                ip=ip.strip() or None,
                domain=domain.strip() or None,
                process=process.strip() or None,
                event_type=None if event_type == "(any)" else event_type,
                limit=limit,
            )

    # A capped result reported as a total would misstate how much matched, so
    # say which of the two it is.
    truncated = len(results) >= limit

    ui.render_section_header(
        "Result summary",
        f"free-text search for '{term.strip()}'" if searching else "filtered search",
    )
    ui.render_kpi_row(
        [
            {
                "label": "Matching events",
                "value": ui.fmt_int(len(results)),
                "note": f"capped at {limit}" if truncated else "complete result",
                "tone": schemas.SEVERITY_MEDIUM if truncated else "accent",
            },
            {
                "label": "Hosts involved",
                "value": ui.fmt_int(
                    results["host"].nunique() if not results.empty else 0
                ),
            },
            {
                "label": "Accounts involved",
                "value": ui.fmt_int(
                    results["user"].nunique() if not results.empty else 0
                ),
            },
            {
                "label": "Event types",
                "value": ui.fmt_int(
                    results["event_type"].nunique() if not results.empty else 0
                ),
            },
        ]
    )

    if truncated:
        st.warning(
            f"Showing the first {len(results)} results. The query was capped "
            f"at {limit} rows, so there may be more - narrow the search to see "
            "the full set."
        )

    ui.render_section_header("Results", "oldest first")
    if results.empty:
        first_hint = (
            "Matching is case-insensitive but literal - check the spelling of "
            "the indicator."
            if searching
            else "Filters are combined with AND; set one back to '(any)' at a "
            "time to find the one excluding everything."
        )
        ui.render_empty_state(
            "No matching events",
            "Nothing in the loaded telemetry matches this "
            + ("search term." if searching else "combination of filters."),
            (
                first_hint,
                "Try a shorter fragment: a domain suffix or the first octets "
                "of an address.",
                "Confirm the period you expect is loaded - the sidebar shows "
                "the range currently in the database.",
            ),
        )
        return

    show_events_table(results, height=420, key="hunt_results")

    ui.render_section_header("Hunt context", "what the matching events involve")
    summary = st.columns(3, gap="medium")
    breakdowns = [
        ("Hosts involved", "host", "Host"),
        ("Accounts involved", "user", "Account"),
        ("Event types", "event_type", "Event type"),
    ]
    for column, (title, field, label) in zip(summary, breakdowns):
        with column:
            counts = analytics.top_values(results, field)
            st.markdown(f"**{title}**")
            st.dataframe(
                counts,
                width="stretch",
                hide_index=True,
                height=ui.table_height(len(counts), cap=260),
                column_config={
                    field: st.column_config.TextColumn(label),
                    "count": st.column_config.NumberColumn("Events", width=80),
                },
            )
    show_raw_evidence(results.head(25))


# --------------------------------------------------------------------------
# E. AI investigation
# --------------------------------------------------------------------------


def render_ai(tables: dict[str, pd.DataFrame]) -> None:
    incidents = tables["incidents"]

    available = ai_investigator.ollama_available()
    models = ai_investigator.available_models() if available else []

    ui.render_section_header("AI investigation", "optional, local, and never required")
    if available:
        ui.render_status_panel(
            "Local model",
            "Connected",
            f"Reachable at {config.OLLAMA_URL}"
            + (f" - models: {', '.join(models)}" if models else ""),
            state="ok",
        )
    else:
        ui.render_status_panel(
            "Local model",
            "Not available",
            f"No local model service is reachable at {config.OLLAMA_URL}. This "
            "is a supported state, not a fault: SignalTrail writes the same "
            "six sections deterministically from the stored evidence, and "
            "those notes are reproducible in a way model output is not.",
            state="off",
        )

    ui.render_note(
        "The model is given only the evidence package for the selected "
        "incident and is instructed to separate observation from inference, "
        "to avoid inventing detail, and to recommend investigative steps "
        "rather than actions. It has no access to the database and cannot run "
        "anything."
    )

    if incidents.empty:
        ui.render_empty_state(
            "No incidents to investigate",
            "Investigation notes are written about a correlated incident, and "
            "there are none loaded.",
            ("Run python run_pipeline.py to ingest, detect and correlate.",),
        )
        return

    choices = incident_choices(incidents)
    take_pending_incident(choices, "ai_incident")
    selected_label = st.selectbox("Incident", list(choices), key="ai_incident")
    incident_id = choices[selected_label]
    incident = incidents[incidents["incident_id"] == incident_id].iloc[0]

    ui.render_fact_strip(
        [
            ("Incident", incident_id),
            ("Severity", incident["severity"]),
            ("Host", incident["host"]),
            ("Evidence events", int(incident["evidence_count"])),
            ("Alerts", len(schemas.split_ids(incident["alert_ids"]))),
            ("Notes from", "local model" if available else "evidence summary"),
        ]
    )

    controls = st.columns([3, 5, 7], gap="small")
    use_ai = controls[0].toggle(
        "Use local model",
        key="ai_use_model",
        value=available,
        disabled=not available,
        help=(
            "Generate the notes with the local model."
            if available
            else "No local model service is reachable, so notes are written "
            "deterministically from the evidence."
        ),
    )
    run = controls[1].button(
        "Generate investigation notes",
        key="ai_generate",
        type="primary",
        width="stretch",
    )

    if not run:
        ui.render_note(
            "Select an incident and generate the notes. Nothing is sent "
            "anywhere: generation either runs against the local model service "
            "or is built from the stored evidence."
        )
        return

    # With no service to talk to the toggle is disabled, so its value is not a
    # choice the analyst made. Asking for the AI path anyway makes the notice
    # below state the real reason for the fallback - "no model service
    # reachable" - rather than "not requested".
    requested = use_ai if available else True

    with st.spinner("Building investigation notes..."):
        with guarded_connection() as conn:
            if conn is None:
                return
            result = ai_investigator.investigate_incident(
                conn, incident_id, use_ai=requested
            )

    generated = result["mode"] == ai_investigator.MODE_AI
    ui.render_status_panel(
        "Notes written by",
        "Local model" if generated else "Evidence summary",
        result["notice"],
        state="ok" if generated else "warn",
    )

    sections = ui.split_notes_sections(result["text"])
    if len(sections) <= 1:
        st.markdown(result["text"])
    else:
        for heading, body in sections:
            if heading:
                ui.render_section_header(heading)
            if body:
                st.markdown(body)

    package = result.get("package") or {}
    if package:
        with st.expander("Evidence package supplied to the model"):
            st.caption(
                "This is the complete input. Anything in the notes above that "
                "is not here was not supported by evidence."
            )
            st.code(ai_investigator.render_evidence_text(package), language=None)


# --------------------------------------------------------------------------
# F. Anomalies (supporting signal)
# --------------------------------------------------------------------------

ANOMALY_COLUMN_CONFIG = {
    "Risk": st.column_config.ProgressColumn(
        "Risk signal",
        width=140,
        format="%.0f",
        min_value=0,
        max_value=100,
        help="Relative ranking within this dataset. Not a probability, not a confidence.",
    ),
    "Host": st.column_config.TextColumn("Host", width=80),
    "Time": st.column_config.DatetimeColumn(
        "Window start", format=ui.TIMESTAMP_COLUMN_FORMAT, width=146
    ),
    "Failed logins": st.column_config.NumberColumn("Failed logins", width=104, format="%d"),
    "DNS": st.column_config.NumberColumn("DNS", width=64, format="%d"),
    "Outbound": st.column_config.NumberColumn("Outbound", width=84, format="%d"),
    "Unique destinations": st.column_config.NumberColumn(
        "Unique dest.", width=96, format="%d"
    ),
    "Processes": st.column_config.NumberColumn("Processes", width=86, format="%d"),
    "Rare process": st.column_config.NumberColumn("Rare proc.", width=82, format="%d"),
    "Note": st.column_config.TextColumn("Note", width=320),
}


def render_anomalies(tables: dict[str, pd.DataFrame]) -> None:
    ui.render_section_header(
        "Behavioural anomalies", "Isolation Forest over per-host activity windows"
    )

    if not anomaly_module.SKLEARN_AVAILABLE:
        ui.render_status_panel(
            "Anomaly model",
            "Not installed",
            "scikit-learn is not installed, so anomaly scoring is unavailable. "
            "It is an optional dependency; everything else in SignalTrail "
            "works without it.",
            state="off",
        )
        return

    events = tables["events"]
    if events.empty:
        ui.render_empty_state(
            "No events loaded",
            "Anomaly scoring summarises activity into per-host time windows, "
            "and there is no activity to summarise.",
            ("Run python run_pipeline.py to generate and load telemetry.",),
        )
        return

    with st.spinner("Scoring behaviour windows..."):
        scored = score_behaviour(events)

    if scored.empty or scored["risk_signal"].isna().all():
        ui.render_empty_state(
            "Not enough activity windows to score",
            "The model needs more behaviour windows than it has features "
            f"({len(anomaly_module.FEATURE_COLUMNS)}) before its ranking means "
            "anything.",
            ("Load a longer period of telemetry, then reload the database.",),
        )
        return

    outliers = int(scored["is_outlier"].sum()) if "is_outlier" in scored else 0
    highest = scored.iloc[0]

    ui.render_kpi_row(
        [
            {
                "label": "Windows analysed",
                "value": ui.fmt_int(len(scored)),
                "note": f"{config.ANOMALY_BUCKET_MINUTES} minute buckets",
            },
            {
                "label": "Hosts analysed",
                "value": ui.fmt_int(scored["host"].nunique()),
            },
            {
                "label": "Flagged as outliers",
                "value": ui.fmt_int(outliers),
                "note": f"{config.ANOMALY_CONTAMINATION:.0%} contamination setting",
                "tone": schemas.SEVERITY_MEDIUM if outliers else "",
            },
            {
                "label": "Highest risk signal",
                "value": f"{highest['risk_signal']:.0f}",
                "note": f"{highest['host']} at {ui.fmt_time(highest['bucket'])[5:16]}",
                "tone": "accent",
            },
        ]
    )

    ui.render_note(
        "Anomaly ranking is an investigation aid. It does not confirm "
        "malicious activity, does not raise alerts and does not create "
        "incidents - unusual and malicious are different things, and on a "
        "dataset this size a quiet host or a backup window ranks as highly as "
        "anything worth a look."
    )

    ui.render_section_header("Risk signal distribution", "all scored windows")
    figure = px.histogram(scored, x="risk_signal", nbins=24)
    figure.update_traces(
        marker_color=ui.PALETTE["accent"],
        marker_line_color=ui.PALETTE["bg"],
        marker_line_width=1,
        hovertemplate="risk %{x}<br>%{y} window(s)<extra></extra>",
    )
    figure.update_layout(
        xaxis_title="risk signal (0-100, relative)", yaxis_title="windows"
    )
    ui.plotly_panel(ui.style_figure(figure, height=200), key="anomaly_hist")

    # The table is ten columns wide and the last of them - the note explaining
    # why a window stood out - is the one worth reading, so it gets the full
    # width rather than sharing a row with the chart.
    ui.render_section_header(
        "Top anomalous activity windows", "highest relative signal first"
    )
    top = scored.head(25).copy()
    top["note"] = top.apply(anomaly_module.describe_bucket, axis=1)
    display = pd.DataFrame(
        {
            "Risk": top["risk_signal"],
            "Host": top["host"],
            "Time": top["bucket"],
            "Failed logins": top["failed_logins"],
            "DNS": top["dns_requests"],
            "Outbound": top["outbound_connections"],
            "Unique destinations": top["unique_destinations"],
            "Processes": top["process_count"],
            "Rare process": top["rare_process_indicator"],
            "Note": top["note"],
        }
    )
    st.dataframe(
        display,
        width="stretch",
        hide_index=True,
        column_config=ANOMALY_COLUMN_CONFIG,
        height=ui.table_height(len(display), cap=460),
    )

    ui.render_note(
        "The risk signal rescales the model score to 0-100 within this run, so "
        "the top window always reads as 100. The counts beside it are the "
        "behaviour the window actually contained."
    )


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------

PAGE_RENDERERS = {
    PAGE_OVERVIEW: render_overview,
    PAGE_DETECTION: render_detection,
    PAGE_INVESTIGATION: render_investigation,
    PAGE_AI: render_ai,
    PAGE_ANOMALIES: render_anomalies,
}


def render_navigation() -> None:
    """The left rail: brand, sections, and what is loaded behind them."""
    ui.render_nav_label("Sections")
    active = current_page()
    for page in PAGES:
        key = "sgtnav-" + page.lower().replace(" ", "-")
        if st.button(
            page,
            key=key,
            type="primary" if page == active else "secondary",
            width="stretch",
        ) and page != active:
            st.session_state[NAV_KEY] = page
            st.rerun()


def render_sidebar(tables: dict[str, pd.DataFrame] | None) -> None:
    with st.sidebar:
        if tables is None:
            ui.render_brand(state="warn", state_text="No database")
            render_navigation()
            ui.render_nav_label("Data")
            ui.render_sidebar_stats([("Database", "not found")])
            ui.render_sidebar_footer(
                [f"Expected at {config.DB_PATH.name}.", "All data is synthetic."]
            )
            return

        events = tables["events"]
        ui.render_brand(state="ok", state_text="Local session")
        render_navigation()

        ui.render_nav_label("Data")
        if events.empty:
            span = "no events"
        else:
            span = (
                f"{events['timestamp'].min():%Y-%m-%d} to "
                f"{events['timestamp'].max():%Y-%m-%d}"
            )
        ui.render_sidebar_stats(
            [
                ("Database", "connected"),
                ("Events", ui.fmt_int(len(events))),
                ("Alerts", ui.fmt_int(len(tables["alerts"]))),
                ("Incidents", ui.fmt_int(len(tables["incidents"]))),
                ("Range (UTC)", span),
            ]
        )

        if st.button("Reload from database", key="reload_db", width="stretch"):
            clear_caches()
            st.rerun()

        ui.render_sidebar_footer(
            [
                f"Source: {config.DB_PATH.name}",
                "Read-only connection. All data in this project is synthetic.",
            ]
        )


def header_meta(tables: dict[str, pd.DataFrame] | None) -> list[str]:
    """The status chips shown on the right of the top header."""
    now = datetime.now(timezone.utc)
    chips = [
        ui.chip(
            f"{ui.status_dot('ok')}LOCAL &middot; OFFLINE",
            tone="ok",
            title="Everything runs on this machine; no telemetry leaves it.",
        )
    ]
    if tables is None:
        chips.append(ui.chip("<b>No database</b>", tone="warn"))
    else:
        chips.append(
            ui.chip(
                f"<b>{ui.fmt_int(len(tables['events']))}</b> events &middot; "
                f"<b>{ui.fmt_int(len(tables['alerts']))}</b> alerts &middot; "
                f"<b>{ui.fmt_int(len(tables['incidents']))}</b> incidents"
            )
        )
    chips.append(
        ui.chip(
            now.strftime("%Y-%m-%d %H:%M UTC"),
            mono=True,
            title="Time this page was rendered.",
        )
    )
    return chips


def main() -> None:
    ui.inject_theme()

    if not database_ready():
        render_sidebar(None)
        ui.render_top_header("No database", meta=header_meta(None))
        ui.render_empty_state(
            "No database found",
            f"SignalTrail expects a DuckDB file at {config.DB_PATH}. The "
            "pipeline creates it on its first run.",
            (
                "Run the pipeline, then reload this page.",
                "Every section below depends on it, so nothing is loaded yet.",
            ),
        )
        st.code("python run_pipeline.py", language=None)
        return

    try:
        tables = load_tables(str(config.DB_PATH))
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a notice
        # DuckDB holds a file lock, so the usual cause is run_pipeline.py
        # writing to the database while this page loads.
        render_sidebar(None)
        ui.render_top_header("Database unavailable", meta=header_meta(None))
        ui.render_empty_state(
            "Could not read the database",
            "It is most likely locked by another process - DuckDB allows one "
            "writer at a time, and the pipeline holds that lock while it runs.",
            (
                "Check whether run_pipeline.py is still running.",
                "When it finishes, use Reload from database in the sidebar.",
            ),
        )
        st.caption(str(exc))
        return

    render_sidebar(tables)

    page = current_page()
    ui.render_top_header(page, meta=header_meta(tables))

    if page == PAGE_HUNTING:
        render_hunting()
    else:
        PAGE_RENDERERS[page](tables)


main()
