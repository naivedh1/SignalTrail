"""Streamlit dashboard: the analyst-facing view of SignalTrail.

The layout follows the questions an analyst actually asks, in order: what
happened, where, who, when, why was it flagged, what evidence supports it,
and what to check next. Each tab answers one of those and hands off to the
next.

Design choices worth stating, because they were deliberate:

* Evidence is never more than one click away. Every alert and incident view
  can expand to the underlying records, including the original raw message.
* Confidence is never fabricated. Severities are labels with defined meaning;
  there are no invented percentages or risk scores presented as certainty.
* The AI tab is clearly marked as optional and shows the evidence package the
  text was generated from, so the reader can check it.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
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

st.set_page_config(
    page_title="SignalTrail",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# A restrained palette: severity is the only thing that gets colour weight.
SEVERITY_COLORS = {
    schemas.SEVERITY_INFO: "#7f8c9b",
    schemas.SEVERITY_LOW: "#5b8fc9",
    schemas.SEVERITY_MEDIUM: "#d9a441",
    schemas.SEVERITY_HIGH: "#d1663a",
    schemas.SEVERITY_CRITICAL: "#b23b3b",
}

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
        st.warning(
            "The database is currently locked by another process - most "
            "likely `run_pipeline.py` is writing to it. Wait for the pipeline "
            "to finish, then use **Reload from database** in the sidebar.\n\n"
            f"`{exc}`"
        )
        yield None
        return
    try:
        yield conn
    finally:
        conn.close()


def database_ready() -> bool:
    return Path(config.DB_PATH).exists()


# --------------------------------------------------------------------------
# Shared rendering helpers
# --------------------------------------------------------------------------


def severity_badge(severity: str) -> str:
    """Severity as a coloured label. Labels only - no numeric confidence."""
    color = SEVERITY_COLORS.get(severity, "#7f8c9b")
    return (
        f"<span style='background:{color};color:#fff;padding:2px 8px;"
        f"border-radius:3px;font-size:0.78rem;font-weight:600;"
        f"letter-spacing:0.03em'>{severity}</span>"
    )


def show_events_table(frame: pd.DataFrame, height: int = 320) -> None:
    """Render an event table with the columns analysts scan first."""
    if frame.empty:
        st.info("No matching events.")
        return
    columns = [c for c in EVENT_TABLE_COLUMNS if c in frame.columns]
    st.dataframe(
        frame[columns], width="stretch", height=height, hide_index=True
    )


def show_timeline(timeline: pd.DataFrame) -> None:
    """Render a timeline, marking which rows a rule actually fired on."""
    if timeline.empty:
        st.info("No events in this timeline.")
        return

    display = timeline.copy()
    display["role"] = display["role"].map(
        {"evidence": "rule evidence", "context": "context"}
    )
    display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(
        display[
            ["timestamp", "role", "host", "user", "event_type", "action", "details"]
        ],
        width="stretch",
        hide_index=True,
        height=min(80 + 35 * len(display), 520),
    )
    st.caption(
        "Rows marked 'rule evidence' caused a detection to fire. Rows marked "
        "'context' were added by correlation because they share the host, "
        "account and time window."
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


# --------------------------------------------------------------------------
# A. Overview
# --------------------------------------------------------------------------


def render_overview(tables: dict[str, pd.DataFrame]) -> None:
    events, alerts, incidents = tables["events"], tables["alerts"], tables["incidents"]
    metrics = analytics.overview_metrics(events, alerts, incidents)

    columns = st.columns(6)
    labels = [
        ("Events", metrics["total_events"]),
        ("Hosts", metrics["hosts"]),
        ("Users", metrics["users"]),
        ("Alerts", metrics["alerts"]),
        ("High / critical", metrics["high_severity_alerts"]),
        ("Incidents", metrics["incidents"]),
    ]
    for column, (label, value) in zip(columns, labels):
        column.metric(label, value)

    st.divider()

    left, right = st.columns([3, 2])

    with left:
        st.subheader("Events over time")
        volume = analytics.events_over_time(events)
        if volume.empty:
            st.info("No events loaded.")
        else:
            figure = px.area(volume, x="bucket", y="events")
            figure.update_traces(line_color="#5b8fc9", fillcolor="rgba(91,143,201,0.2)")
            figure.update_layout(
                height=280,
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis_title=None,
                yaxis_title="events / hour",
            )
            st.plotly_chart(figure, width="stretch")

    with right:
        st.subheader("Events by type")
        by_type = analytics.events_by_type(events)
        if by_type.empty:
            st.info("No events loaded.")
        else:
            figure = px.bar(by_type, x="events", y="event_type", orientation="h")
            figure.update_traces(marker_color="#5b8fc9")
            figure.update_layout(
                height=280,
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis_title=None,
                yaxis_title=None,
                yaxis={"categoryorder": "total ascending"},
            )
            st.plotly_chart(figure, width="stretch")

    left, right = st.columns(2)

    with left:
        st.subheader("Alerts by severity")
        by_severity = analytics.alerts_by_severity(alerts)
        if by_severity.empty:
            st.info("No alerts raised.")
        else:
            figure = px.bar(
                by_severity,
                x="severity",
                y="alerts",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
            )
            figure.update_layout(
                height=260,
                margin=dict(l=0, r=0, t=10, b=0),
                showlegend=False,
                xaxis_title=None,
                yaxis_title=None,
            )
            st.plotly_chart(figure, width="stretch")

    with right:
        st.subheader("Alerts by host")
        by_host = analytics.alerts_by_host(alerts)
        if by_host.empty:
            st.info("No alerts raised.")
        else:
            figure = px.bar(by_host, x="host", y="alerts")
            figure.update_traces(marker_color="#d9a441")
            figure.update_layout(
                height=260,
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis_title=None,
                yaxis_title=None,
            )
            st.plotly_chart(figure, width="stretch")


# --------------------------------------------------------------------------
# B. Detection
# --------------------------------------------------------------------------


def render_detection(tables: dict[str, pd.DataFrame]) -> None:
    alerts = tables["alerts"]
    events = tables["events"]

    st.subheader("Alerts")
    if alerts.empty:
        st.info("No alerts have been raised. Run the pipeline first.")
        return

    filter_columns = st.columns([1, 1, 2])
    severities = filter_columns[0].multiselect(
        "Severity",
        [s for s in schemas.SEVERITY_ORDER if s in set(alerts["severity"])],
        default=[],
    )
    rules = filter_columns[1].multiselect(
        "Rule", sorted(alerts["rule_id"].unique()), default=[]
    )
    hosts = filter_columns[2].multiselect(
        "Host", sorted(alerts["host"].unique()), default=[]
    )

    filtered = alerts
    if severities:
        filtered = filtered[filtered["severity"].isin(severities)]
    if rules:
        filtered = filtered[filtered["rule_id"].isin(rules)]
    if hosts:
        filtered = filtered[filtered["host"].isin(hosts)]

    st.dataframe(
        filtered[
            [
                "created_at",
                "rule_id",
                "rule_name",
                "severity",
                "host",
                "user",
                "status",
                "evidence_count",
                "technique_id",
                "reason",
            ]
        ],
        width="stretch",
        hide_index=True,
        height=min(80 + 35 * len(filtered), 400),
    )

    st.divider()
    st.subheader("Alert detail")
    if filtered.empty:
        st.info("No alerts match the current filters.")
        return

    choices = {
        f"{row.created_at:%Y-%m-%d %H:%M:%S} | {row.rule_id} | {row.host} | {row.severity}": row.alert_id
        for row in filtered.itertuples(index=False)
    }
    selected_label = st.selectbox("Select an alert", list(choices))
    alert_id = choices[selected_label]
    alert = filtered[filtered["alert_id"] == alert_id].iloc[0]
    rule = detections.RULES.get(alert["rule_id"])

    header = st.columns([3, 1])
    header[0].markdown(f"### {alert['rule_name']}")
    header[1].markdown(severity_badge(alert["severity"]), unsafe_allow_html=True)

    st.markdown(f"**Why this fired.** {alert['reason']}")

    if rule:
        detail = st.columns(2)
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

    st.markdown("**Evidence**")
    evidence_ids = investigate.split_ids(alert["evidence_event_ids"])
    evidence = events[events["event_id"].isin(evidence_ids)].sort_values("timestamp")
    show_events_table(evidence, height=min(80 + 35 * len(evidence), 320))
    show_raw_evidence(evidence)

    st.divider()
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


def render_investigation(tables: dict[str, pd.DataFrame]) -> None:
    incidents = tables["incidents"]
    if incidents.empty:
        st.info("No incidents have been correlated. Run the pipeline first.")
        return

    choices = {
        f"{row.start_time:%Y-%m-%d %H:%M} | {row.severity} | {row.title}": row.incident_id
        for row in incidents.sort_values("start_time", ascending=False).itertuples(
            index=False
        )
    }
    selected_label = st.selectbox("Incident", list(choices))
    incident_id = choices[selected_label]

    with guarded_connection() as conn:
        if conn is None:
            return
        context = investigate.summarize_incident(conn, incident_id)

    if not context:
        st.warning("That incident could not be loaded.")
        return

    incident = context["incident"]

    header = st.columns([4, 1])
    header[0].markdown(f"### {incident['title']}")
    header[1].markdown(severity_badge(incident["severity"]), unsafe_allow_html=True)

    facts = st.columns(5)
    facts[0].metric("Host", incident["host"])
    facts[1].metric("Account", incident["user"])
    facts[2].metric("Alerts", len(context["alerts"]))
    facts[3].metric("Evidence events", int(incident["evidence_count"]))
    facts[4].metric(
        "Duration",
        f"{int((incident['end_time'] - incident['start_time']).total_seconds() // 60)} min",
    )

    st.caption(
        f"Window: {incident['start_time']:%Y-%m-%d %H:%M:%S} to "
        f"{incident['end_time']:%Y-%m-%d %H:%M:%S} UTC | status: {incident['status']}"
    )

    st.markdown("**Summary**")
    st.write(incident["summary"])

    st.divider()
    st.markdown("**Timeline**")
    show_timeline(context["timeline"])

    st.divider()
    left, right = st.columns([2, 1])

    with left:
        st.markdown("**Related alerts**")
        st.dataframe(
            context["alerts"][
                ["created_at", "rule_id", "rule_name", "severity", "reason"]
            ],
            width="stretch",
            hide_index=True,
        )

    with right:
        st.markdown("**Indicators in this incident**")
        for label, values in context["indicators"].items():
            pretty = label.replace("_", " ").title()
            if values:
                st.markdown(f"*{pretty}*")
                for value in values:
                    st.code(value, language=None)
            else:
                st.markdown(f"*{pretty}*: none recorded")

    st.divider()
    st.markdown("**Evidence records**")
    show_events_table(context["evidence"], height=min(80 + 35 * len(context["evidence"]), 400))
    show_raw_evidence(context["evidence"])

    st.divider()
    st.markdown("**Widen the window**")
    st.caption(
        "Correlation attaches only events on the same host and account. Widen "
        "the window to see what else the host was doing around the incident."
    )
    minutes = st.slider("Minutes either side", 5, 180, 30, step=5)
    with guarded_connection() as conn:
        if conn is None:
            return
        surrounding = investigate.build_host_timeline(
            conn,
            incident["host"],
            incident["start_time"],
            minutes=minutes,
        )
    st.dataframe(
        surrounding[["timestamp", "host", "user", "event_type", "action", "details"]],
        width="stretch",
        hide_index=True,
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


def render_hunting() -> None:
    st.subheader("Threat hunting")
    st.caption(
        "Search across every field worth pivoting on, or narrow by specific "
        "attributes. Both are useful: free text for chasing an indicator you "
        "were handed, filters for describing a pattern you are looking for."
    )

    with guarded_connection() as conn:
        if conn is None:
            return
        options = investigate.entity_options(conn)

    term = st.text_input(
        "Search any indicator",
        placeholder="203.0.113.50, demo-suspicious.example, analyst_demo, WS-001, powershell.exe",
    )

    filters = st.columns(3)
    host = filters[0].selectbox("Host", ["(any)"] + options["hosts"])
    user = filters[1].selectbox("User", ["(any)"] + options["users"])
    event_type = filters[2].selectbox("Event type", ["(any)"] + options["event_types"])

    filters = st.columns(3)
    ip = filters[0].text_input("IP address (source or destination)")
    domain = filters[1].text_input("Domain contains")
    process = filters[2].text_input("Process contains")

    with guarded_connection() as conn:
        if conn is None:
            return
        if term.strip():
            limit = HUNT_TEXT_LIMIT
            results = investigate.hunt(conn, term.strip(), limit=limit)
            st.caption(f"Free-text search for '{term.strip()}'.")
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
    if truncated:
        st.markdown(f"**First {len(results)} matching event(s)**")
        st.caption(
            f"The result was capped at {limit} rows, so there may be more. "
            "Narrow the search to see the full set."
        )
    else:
        st.markdown(f"**{len(results)} matching event(s)**")
    show_events_table(results, height=420)

    if not results.empty:
        summary = st.columns(3)
        with summary[0]:
            st.markdown("**Hosts involved**")
            st.dataframe(
                analytics.top_values(results, "host"), width="stretch", hide_index=True
            )
        with summary[1]:
            st.markdown("**Accounts involved**")
            st.dataframe(
                analytics.top_values(results, "user"), width="stretch", hide_index=True
            )
        with summary[2]:
            st.markdown("**Event types**")
            st.dataframe(
                analytics.top_values(results, "event_type"),
                width="stretch",
                hide_index=True,
            )
        show_raw_evidence(results.head(25))


# --------------------------------------------------------------------------
# E. AI investigation
# --------------------------------------------------------------------------


def render_ai(tables: dict[str, pd.DataFrame]) -> None:
    incidents = tables["incidents"]
    st.subheader("AI investigation")

    available = ai_investigator.ollama_available()
    if available:
        models = ai_investigator.available_models()
        st.success(
            f"A local model service is reachable at {config.OLLAMA_URL}"
            + (f" (models: {', '.join(models)})" if models else "")
        )
    else:
        st.info(
            f"No local model service is reachable at {config.OLLAMA_URL}. "
            "This is a supported state - the AI layer is optional. SignalTrail "
            "will show a deterministic summary built from the same evidence."
        )

    st.caption(
        "The model is given only the evidence package for the selected "
        "incident and is instructed to separate observation from inference, "
        "to avoid inventing detail, and to recommend investigative steps "
        "rather than actions. It has no access to the database and cannot "
        "run anything."
    )

    if incidents.empty:
        st.info("No incidents to investigate. Run the pipeline first.")
        return

    choices = {
        f"{row.start_time:%Y-%m-%d %H:%M} | {row.severity} | {row.title}": row.incident_id
        for row in incidents.sort_values("start_time", ascending=False).itertuples(
            index=False
        )
    }
    selected_label = st.selectbox("Incident", list(choices), key="ai_incident")
    incident_id = choices[selected_label]

    controls = st.columns([1, 1, 3])
    use_ai = controls[0].toggle("Use local model", value=available, disabled=not available)
    run = controls[1].button("Generate notes", type="primary")

    if not run:
        st.caption("Select an incident and generate the investigation notes.")
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

    if result["mode"] == ai_investigator.MODE_AI:
        st.success(result["notice"])
    else:
        st.info(result["notice"])

    st.markdown(result["text"])

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


def render_anomalies(tables: dict[str, pd.DataFrame]) -> None:
    st.subheader("Behavioural anomalies")
    st.caption(
        "An Isolation Forest over per-host activity windows. This is a "
        "ranking aid for finding places to look when no rule fired. It does "
        "not raise alerts, does not create incidents, and unusual does not "
        "mean malicious."
    )

    if not anomaly_module.SKLEARN_AVAILABLE:
        st.info(
            "scikit-learn is not installed, so anomaly scoring is unavailable. "
            "Everything else in SignalTrail works without it."
        )
        return

    events = tables["events"]
    if events.empty:
        st.info("No events loaded.")
        return

    with st.spinner("Scoring behaviour windows..."):
        scored = anomaly_module.run_anomaly_detection(events)

    if scored.empty or scored["risk_signal"].isna().all():
        st.info("Not enough activity windows to score.")
        return

    top = scored.head(25).copy()
    top["note"] = top.apply(anomaly_module.describe_bucket, axis=1)
    st.dataframe(
        top[
            [
                "bucket",
                "host",
                "risk_signal",
                *anomaly_module.FEATURE_COLUMNS,
                "note",
            ]
        ],
        width="stretch",
        hide_index=True,
        height=420,
    )
    st.caption(
        "risk_signal rescales the model score to 0-100 within this dataset. "
        "It is a relative ranking, not a probability and not a confidence."
    )


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------


def main() -> None:
    st.title("SignalTrail")
    st.caption("Security telemetry and investigation platform - local, synthetic data")

    if not database_ready():
        st.error(
            f"No database found at {config.DB_PATH}.\n\n"
            "Run the pipeline first:\n\n```\npython run_pipeline.py\n```"
        )
        return

    try:
        tables = load_tables(str(config.DB_PATH))
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a notice
        # DuckDB holds a file lock, so the usual cause is run_pipeline.py
        # writing to the database while this page loads.
        st.warning(
            "Could not read the database. It is most likely locked by another "
            "process - check whether `run_pipeline.py` is still running, then "
            "reload this page.\n\n"
            f"`{exc}`"
        )
        return

    with st.sidebar:
        st.header("SignalTrail")
        st.caption(
            "Telemetry is ingested, normalized to a common event model, "
            "stored in DuckDB, matched against detection rules, and "
            "correlated into incidents."
        )
        st.divider()
        st.markdown("**Loaded**")
        st.write(f"{len(tables['events'])} events")
        st.write(f"{len(tables['alerts'])} alerts")
        st.write(f"{len(tables['incidents'])} incidents")
        if not tables["events"].empty:
            st.caption(
                f"{tables['events']['timestamp'].min():%Y-%m-%d} to "
                f"{tables['events']['timestamp'].max():%Y-%m-%d} (UTC)"
            )
        st.divider()
        if st.button("Reload from database"):
            load_tables.clear()
            st.rerun()
        st.caption(f"Database: `{config.DB_PATH.name}`")
        st.caption("All data in this project is synthetic.")

    overview, detection, investigation, hunting, ai, anomalies = st.tabs(
        [
            "Overview",
            "Detection",
            "Investigation",
            "Threat Hunting",
            "AI Investigation",
            "Anomalies",
        ]
    )

    with overview:
        render_overview(tables)
    with detection:
        render_detection(tables)
    with investigation:
        render_investigation(tables)
    with hunting:
        render_hunting()
    with ai:
        render_ai(tables)
    with anomalies:
        render_anomalies(tables)


main()
