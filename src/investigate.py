"""Investigation engine: the query layer analysts and the AI layer share.

Everything an analyst does after an alert fires is some form of pivot - from
an address to the hosts that talked to it, from an incident to the events
behind it, from a moment in time to what surrounded it. Those pivots are
implemented once here and reused by both the dashboard and the AI
investigator, so the two can never disagree about what the evidence says.

All functions take an open DuckDB connection and return DataFrames. Queries
are parameterised throughout; user-supplied search terms are never formatted
into SQL text.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import pandas as pd

from . import database
from . import schemas

logger = logging.getLogger(__name__)

#: Columns shown in a timeline, in the order an analyst reads them.
TIMELINE_COLUMNS = [
    "timestamp",
    "event_id",
    "host",
    "user",
    "source_type",
    "event_type",
    "action",
    "status",
    "details",
    "role",
]

_EVENT_SELECT = 'SELECT * FROM security_events'

#: Escape character used with every LIKE clause in this module.
_LIKE_ESCAPE = "\\"


def like_pattern(term: str) -> str:
    """Build a case-folded "contains" pattern that matches ``term`` literally.

    ``%`` and ``_`` are wildcards in SQL LIKE, so a term containing either
    would otherwise match more than the analyst asked for - and silently.
    That is not hypothetical here: account names like ``analyst_demo`` and
    ``svc_backup`` contain underscores, and an unescaped ``_`` matches any
    single character.

    Escaping is a correctness fix rather than a security one. Every term is
    already passed as a query parameter and never formatted into SQL.
    """
    escaped = (
        term.lower()
        .replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)  # the escape char itself first
        .replace("%", _LIKE_ESCAPE + "%")
        .replace("_", _LIKE_ESCAPE + "_")
    )
    return f"%{escaped}%"


def _like_clause(column: str) -> str:
    # DuckDB treats backslash literally inside a single-quoted string, so the
    # ESCAPE clause carries exactly one character.
    return f"lower({column}) LIKE ? ESCAPE '{_LIKE_ESCAPE}'"


# --------------------------------------------------------------------------
# Basic pivots
# --------------------------------------------------------------------------


def search_events(
    conn,
    host: str | None = None,
    user: str | None = None,
    ip: str | None = None,
    domain: str | None = None,
    process: str | None = None,
    event_type: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int | None = None,
) -> pd.DataFrame:
    """Filter events on any combination of the common investigation fields.

    An IP term matches either direction of a connection, because an analyst
    chasing an address rarely knows in advance which end it was.
    """
    clauses: list[str] = []
    params: list = []

    if host:
        clauses.append("host = ?")
        params.append(host)
    if user:
        clauses.append('"user" = ?')
        params.append(user)
    if ip:
        clauses.append("(src_ip = ? OR dst_ip = ?)")
        params.extend([ip, ip])
    if domain:
        clauses.append(_like_clause("domain"))
        params.append(like_pattern(domain))
    if process:
        clauses.append(_like_clause("process_name"))
        params.append(like_pattern(process))
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if start is not None:
        clauses.append("timestamp >= ?")
        params.append(start)
    if end is not None:
        clauses.append("timestamp <= ?")
        params.append(end)

    sql = _EVENT_SELECT
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY timestamp"
    if limit:
        sql += f" LIMIT {int(limit)}"

    return database.fetch_df(conn, sql, params)


def events_by_host(conn, host: str, limit: int | None = None) -> pd.DataFrame:
    return search_events(conn, host=host, limit=limit)


def events_by_user(conn, user: str, limit: int | None = None) -> pd.DataFrame:
    return search_events(conn, user=user, limit=limit)


def events_by_ip(conn, ip: str, limit: int | None = None) -> pd.DataFrame:
    return search_events(conn, ip=ip, limit=limit)


def events_by_domain(conn, domain: str, limit: int | None = None) -> pd.DataFrame:
    return search_events(conn, domain=domain, limit=limit)


def events_by_process(conn, process: str, limit: int | None = None) -> pd.DataFrame:
    return search_events(conn, process=process, limit=limit)


def events_in_window(
    conn,
    start: datetime,
    end: datetime,
    host: str | None = None,
    user: str | None = None,
) -> pd.DataFrame:
    """Everything recorded between two moments, optionally scoped."""
    return search_events(conn, host=host, user=user, start=start, end=end)


def events_by_ids(conn, event_ids: list[str]) -> pd.DataFrame:
    """Fetch specific events by identifier, in time order."""
    if not event_ids:
        return database.fetch_df(conn, _EVENT_SELECT + " WHERE 1 = 0")
    placeholders = ", ".join("?" for _ in event_ids)
    return database.fetch_df(
        conn,
        f"{_EVENT_SELECT} WHERE event_id IN ({placeholders}) ORDER BY timestamp",
        list(event_ids),
    )


# --------------------------------------------------------------------------
# Free-text hunting
# --------------------------------------------------------------------------

#: Fields a free-text hunt searches. Deliberately limited to the ones an
#: analyst actually pivots on, so results stay readable.
HUNT_FIELDS = (
    "host",
    '"user"',
    "src_ip",
    "dst_ip",
    "domain",
    "process_name",
    "command_line",
    "file_path",
    "event_type",
    "action",
)


def hunt(conn, term: str, limit: int = 500) -> pd.DataFrame:
    """Search one term across every field worth pivoting on.

    This is the "paste an indicator and see what comes back" entry point: an
    address, a domain, a username, a hostname or a process name all work
    without the analyst having to say which kind of thing it is.
    """
    term = (term or "").strip()
    if not term:
        return database.fetch_df(conn, _EVENT_SELECT + " WHERE 1 = 0")

    pattern = like_pattern(term)
    clause = " OR ".join(_like_clause(field) for field in HUNT_FIELDS)
    sql = f"{_EVENT_SELECT} WHERE {clause} ORDER BY timestamp LIMIT {int(limit)}"
    return database.fetch_df(conn, sql, [pattern] * len(HUNT_FIELDS))


# --------------------------------------------------------------------------
# Alerts and incidents
# --------------------------------------------------------------------------


def get_alert(conn, alert_id: str) -> dict | None:
    frame = database.fetch_df(
        conn, "SELECT * FROM alerts WHERE alert_id = ?", [alert_id]
    )
    return None if frame.empty else frame.iloc[0].to_dict()


def get_incident(conn, incident_id: str) -> dict | None:
    frame = database.fetch_df(
        conn, "SELECT * FROM incidents WHERE incident_id = ?", [incident_id]
    )
    return None if frame.empty else frame.iloc[0].to_dict()


def list_incidents(conn) -> pd.DataFrame:
    return database.fetch_df(
        conn, "SELECT * FROM incidents ORDER BY start_time DESC, incident_id"
    )


def list_alerts(conn) -> pd.DataFrame:
    return database.fetch_df(
        conn, "SELECT * FROM alerts ORDER BY created_at DESC, alert_id"
    )


#: Re-exported so callers of the investigation API have it to hand. The
#: implementation lives in schemas.py because correlation needs it too.
split_ids = schemas.split_ids


def get_alert_evidence(conn, alert_id: str) -> pd.DataFrame:
    """The events that caused one alert to fire."""
    alert = get_alert(conn, alert_id)
    if alert is None:
        return events_by_ids(conn, [])
    return events_by_ids(conn, split_ids(alert.get("evidence_event_ids")))


def get_incident_alerts(conn, incident_id: str) -> pd.DataFrame:
    """The alerts grouped into one incident."""
    incident = get_incident(conn, incident_id)
    if incident is None:
        return database.fetch_df(conn, "SELECT * FROM alerts WHERE 1 = 0")
    alert_ids = split_ids(incident.get("alert_ids"))
    if not alert_ids:
        return database.fetch_df(conn, "SELECT * FROM alerts WHERE 1 = 0")
    placeholders = ", ".join("?" for _ in alert_ids)
    return database.fetch_df(
        conn,
        f"SELECT * FROM alerts WHERE alert_id IN ({placeholders}) ORDER BY created_at",
        alert_ids,
    )


def get_incident_evidence(conn, incident_id: str) -> pd.DataFrame:
    """Every event attached to an incident, in time order."""
    incident = get_incident(conn, incident_id)
    if incident is None:
        return events_by_ids(conn, [])
    return events_by_ids(conn, split_ids(incident.get("evidence_event_ids")))


# --------------------------------------------------------------------------
# Timelines
# --------------------------------------------------------------------------


def describe_event(row) -> str:
    """One readable line of detail for an event, chosen by its type.

    The full original record is always available in ``raw_message``; this is
    the short form that makes a timeline scannable.
    """
    event_type = row.get("event_type")

    if event_type == schemas.EVENT_TYPE_AUTHENTICATION:
        outcome = "succeeded" if row.get("status") == schemas.STATUS_SUCCESS else "failed"
        source = row.get("src_ip") or "unknown source"
        return f"{row.get('action', 'login')} {outcome} from {source}"

    if event_type == schemas.EVENT_TYPE_PROCESS:
        command = row.get("command_line") or row.get("process_name") or ""
        return f"process started: {command}"

    if event_type == schemas.EVENT_TYPE_FILE:
        path = row.get("file_path") or "unrecorded path"
        actor = row.get("process_name") or "unknown process"
        return f"file created at {path} by {actor}"

    if event_type == schemas.EVENT_TYPE_DNS:
        return f"DNS query for {row.get('domain') or 'unknown domain'}"

    if event_type == schemas.EVENT_TYPE_NETWORK:
        port = row.get("dst_port")
        port_text = "" if port is None or pd.isna(port) else f":{int(port)}"
        verb = (
            "blocked connection to"
            if row.get("action") == "connection_blocked"
            else "connection to"
        )
        return f"{verb} {row.get('dst_ip') or 'unknown destination'}{port_text}"

    return row.get("action") or ""


def build_timeline(events: pd.DataFrame, evidence_ids: set[str] | None = None) -> pd.DataFrame:
    """Turn a set of events into an ordered, readable timeline.

    The ``role`` column separates events a rule actually fired on from the
    surrounding context pulled in by correlation, so the distinction between
    evidence and background survives into the UI.
    """
    if events.empty:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    timeline = events.sort_values("timestamp", kind="stable").copy()
    timeline["details"] = timeline.apply(describe_event, axis=1)

    if evidence_ids is None:
        timeline["role"] = "evidence"
    else:
        timeline["role"] = timeline["event_id"].map(
            lambda event_id: "evidence" if event_id in evidence_ids else "context"
        )

    return timeline[TIMELINE_COLUMNS].reset_index(drop=True)


def build_incident_timeline(conn, incident_id: str) -> pd.DataFrame:
    """The chronological reconstruction of one incident."""
    evidence = get_incident_evidence(conn, incident_id)
    if evidence.empty:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    alerts = get_incident_alerts(conn, incident_id)
    alert_evidence: set[str] = set()
    for value in alerts.get("evidence_event_ids", []):
        alert_evidence.update(split_ids(value))

    return build_timeline(evidence, evidence_ids=alert_evidence)


def build_host_timeline(
    conn, host: str, around: datetime, minutes: int = 30
) -> pd.DataFrame:
    """Everything a host did around a point in time."""
    window = timedelta(minutes=minutes)
    events = events_in_window(conn, around - window, around + window, host=host)
    return build_timeline(events)


# --------------------------------------------------------------------------
# Summaries
# --------------------------------------------------------------------------


def summarize_incident(conn, incident_id: str) -> dict:
    """Assemble everything known about one incident into a single structure.

    This is the shared investigation context: the dashboard renders it, and
    the AI investigator is given nothing beyond it.
    """
    incident = get_incident(conn, incident_id)
    if incident is None:
        return {}

    alerts = get_incident_alerts(conn, incident_id)
    evidence = get_incident_evidence(conn, incident_id)
    timeline = build_incident_timeline(conn, incident_id)

    indicators = {
        "source_ips": sorted({v for v in evidence.get("src_ip", []) if v}),
        "destination_ips": sorted({v for v in evidence.get("dst_ip", []) if v}),
        "domains": sorted({v for v in evidence.get("domain", []) if v}),
        "processes": sorted({v for v in evidence.get("process_name", []) if v}),
        "files": sorted({v for v in evidence.get("file_path", []) if v}),
    }

    return {
        "incident": incident,
        "alerts": alerts,
        "evidence": evidence,
        "timeline": timeline,
        "indicators": indicators,
        "rule_ids": split_ids(incident.get("rule_ids")),
    }


def render_timeline_text(timeline: pd.DataFrame) -> str:
    """Format a timeline as plain text, for terminals and AI prompts."""
    if timeline.empty:
        return "(no events)"
    lines = []
    for row in timeline.itertuples(index=False):
        marker = "*" if row.role == "evidence" else " "
        lines.append(
            f"{marker} {row.timestamp:%Y-%m-%d %H:%M:%S}  {row.host:<8} "
            f"{row.user:<13} {row.event_type:<15} {row.details}"
        )
    return "\n".join(lines)


def entity_options(conn) -> dict[str, list[str]]:
    """Distinct values for the dashboard's filter controls."""
    options: dict[str, list[str]] = {}
    for label, column in (
        ("hosts", "host"),
        ("users", '"user"'),
        ("event_types", "event_type"),
        ("processes", "process_name"),
    ):
        frame = database.fetch_df(
            conn,
            f"SELECT DISTINCT {column} AS value FROM security_events "
            f"WHERE {column} <> '' ORDER BY value",
        )
        options[label] = frame["value"].tolist()
    return options
