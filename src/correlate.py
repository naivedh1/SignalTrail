"""Incident correlation: from scattered alerts to one investigable story.

Individual alerts are a poor unit of work. Six failed logins, an encoded
PowerShell command, a DNS lookup and an outbound connection are four queue
items if you look at them one at a time, and one incident if you look at when
and where they happened.

Grouping here is intentionally conservative and explainable:

1. Alerts are partitioned by ``(host, user)``. Activity on different accounts
   or machines is kept apart unless an analyst links it by hand.
2. Within a partition, alerts are clustered by time. A gap longer than
   ``CORRELATION_GAP_MINUTES`` starts a new incident.
3. Each cluster is then enriched with *context events* - records from the same
   host and user around the alert window that share an indicator with the
   evidence, or that are authentication events. These are not alerts; they are
   the surrounding activity that makes the sequence readable.

Nothing here infers intent. The summary states the order things happened in
and leaves the conclusion to the analyst.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta

import pandas as pd

from . import config
from . import schemas
from .detections import RULES

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def make_incident_id(host: str, user: str, alert_ids: list[str]) -> str:
    """Deterministic incident identifier derived from its member alerts."""
    material = "|".join([host or "", user or "", *sorted(alert_ids)])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return "INC-" + digest[:16]


# --------------------------------------------------------------------------
# Clustering
# --------------------------------------------------------------------------


def cluster_alerts(
    alerts: pd.DataFrame, gap_minutes: int | None = None
) -> list[pd.DataFrame]:
    """Split alerts into time-adjacent clusters per (host, user)."""
    if alerts.empty:
        return []

    if gap_minutes is None:
        gap_minutes = config.CORRELATION_GAP_MINUTES
    gap = timedelta(minutes=gap_minutes)
    clusters: list[pd.DataFrame] = []

    ordered = alerts.sort_values(["host", "user", "created_at"], kind="stable")
    for _, group in ordered.groupby(["host", "user"], sort=True):
        rows = group.sort_values("created_at", kind="stable").reset_index(drop=True)
        current: list[int] = [0]
        for index in range(1, len(rows)):
            previous_time = rows.loc[index - 1, "created_at"]
            this_time = rows.loc[index, "created_at"]
            if this_time - previous_time <= gap:
                current.append(index)
            else:
                clusters.append(rows.loc[current].copy())
                current = [index]
        clusters.append(rows.loc[current].copy())

    return clusters


# --------------------------------------------------------------------------
# Context gathering
# --------------------------------------------------------------------------


def gather_context_events(
    events: pd.DataFrame,
    cluster: pd.DataFrame,
    evidence_ids: set[str],
    context_minutes: int | None = None,
) -> pd.DataFrame:
    """Find related events around a cluster that are not themselves evidence.

    "Related" means: same host and user, inside the padded time window, and
    either an authentication event (which explains how the session began) or
    an event sharing an address, domain or process with the alert evidence.
    """
    if events.empty:
        return events

    if context_minutes is None:
        context_minutes = config.INCIDENT_CONTEXT_MINUTES
    padding = timedelta(minutes=context_minutes)
    host = cluster["host"].iloc[0]
    user = cluster["user"].iloc[0]

    evidence = events[events["event_id"].isin(evidence_ids)]
    if evidence.empty:
        return events.iloc[0:0]

    window_start = evidence["timestamp"].min() - padding
    window_end = evidence["timestamp"].max() + padding

    nearby = events[
        (events["host"] == host)
        & (events["user"] == user)
        & (events["timestamp"] >= window_start)
        & (events["timestamp"] <= window_end)
        & (~events["event_id"].isin(evidence_ids))
    ]
    if nearby.empty:
        return nearby

    # Indicators observed in the evidence itself.
    indicators = {
        "src_ip": {v for v in evidence["src_ip"] if v},
        "dst_ip": {v for v in evidence["dst_ip"] if v},
        "domain": {v for v in evidence["domain"] if v},
        "process_name": {v for v in evidence["process_name"] if v},
    }

    related = nearby["event_type"] == schemas.EVENT_TYPE_AUTHENTICATION
    for column, values in indicators.items():
        if values:
            related = related | nearby[column].isin(values)

    return nearby[related]


# --------------------------------------------------------------------------
# Narrative
# --------------------------------------------------------------------------

#: Short, neutral phrases used when describing what a rule observed.
STAGE_PHRASES = {
    "RULE-001": "repeated failed logins",
    "RULE-002": "an encoded PowerShell command line",
    "RULE-003": "a lookup of a watchlisted domain",
    "RULE-004": "a connection to a watchlisted address",
    "RULE-005": "file creation shortly after a flagged process",
}


def build_title(host: str, user: str, rule_ids: list[str]) -> str:
    """A title that says where, who and roughly what - nothing more."""
    if len(rule_ids) >= 3:
        return f"Multi-stage suspicious activity on {host} ({user})"
    if len(rule_ids) == 1:
        rule = RULES.get(rule_ids[0])
        name = rule.name if rule else rule_ids[0]
        return f"{name} on {host} ({user})"
    return f"Related suspicious activity on {host} ({user})"


def build_summary(
    host: str,
    user: str,
    rule_ids: list[str],
    start: datetime,
    end: datetime,
    evidence_count: int,
    context_events: pd.DataFrame,
) -> str:
    """A deterministic, evidence-only description of the incident.

    This is also the fallback shown when the optional local AI layer is not
    available, so it has to stand on its own.
    """
    observed = [STAGE_PHRASES.get(rule_id, rule_id) for rule_id in rule_ids]
    if len(observed) == 1:
        observed_text = observed[0]
    else:
        observed_text = ", ".join(observed[:-1]) + " and " + observed[-1]

    duration = end - start
    minutes = max(int(duration.total_seconds() // 60), 0)
    span = f"{minutes} minute(s)" if minutes else "under a minute"

    lines = [
        f"Between {start:%Y-%m-%d %H:%M:%S} and {end:%H:%M:%S} UTC ({span}), "
        f"{len(rule_ids)} detection rule(s) fired for account '{user}' on {host}.",
        f"Observed: {observed_text}.",
        f"{evidence_count} event(s) are attached as evidence.",
    ]

    # A successful login inside the window is worth calling out explicitly,
    # because it changes what an analyst checks next.
    if not context_events.empty:
        successes = context_events[
            (context_events["event_type"] == schemas.EVENT_TYPE_AUTHENTICATION)
            & (context_events["status"] == schemas.STATUS_SUCCESS)
        ]
        if not successes.empty:
            first = successes.sort_values("timestamp").iloc[0]
            source = first["src_ip"] or "an unrecorded address"
            lines.append(
                f"A successful login for '{user}' from {source} was recorded at "
                f"{first['timestamp']:%H:%M:%S} within the same window."
            )

    lines.append(
        "This grouping reflects timing and shared host/account context. It "
        "shows what was observed, not a confirmed cause. Review the timeline "
        "and the underlying records before deciding on a response."
    )
    return " ".join(lines)


def incident_severity(cluster: pd.DataFrame, rule_ids: list[str]) -> str:
    """Severity of an incident: the worst alert, escalated only when earned.

    Escalation requires several distinct rules to have fired on the same host
    and account. One noisy rule cannot produce a CRITICAL on its own.
    """
    base = schemas.max_severity(cluster["severity"].tolist())
    if (
        len(set(rule_ids)) >= config.INCIDENT_ESCALATION_RULE_COUNT
        and schemas.SEVERITY_RANK[base] >= schemas.SEVERITY_RANK[schemas.SEVERITY_HIGH]
    ):
        return schemas.escalate(base)
    return base


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


def incidents_to_frame(incidents: list[dict]) -> pd.DataFrame:
    """Build a typed incidents DataFrame in the canonical column order."""
    frame = pd.DataFrame(incidents, columns=list(schemas.INCIDENT_COLUMNS))

    timestamp_columns = ("created_at", "start_time", "end_time")
    for column in schemas.INCIDENT_COLUMNS:
        if column in timestamp_columns or column == "evidence_count":
            continue
        frame[column] = frame[column].fillna(schemas.EMPTY_VALUE).astype("string")

    frame["evidence_count"] = pd.to_numeric(
        frame["evidence_count"], errors="coerce"
    ).astype("Int64")
    for column in timestamp_columns:
        frame[column] = schemas.to_naive_utc(frame[column])

    return frame.sort_values(["start_time", "incident_id"], kind="stable").reset_index(
        drop=True
    )


def correlate_alerts(
    alerts: pd.DataFrame,
    events: pd.DataFrame,
    gap_minutes: int | None = None,
    context_minutes: int | None = None,
) -> pd.DataFrame:
    """Group alerts into incidents and attach their evidence."""
    if alerts.empty:
        logger.warning("No alerts to correlate")
        return incidents_to_frame([])

    incidents: list[dict] = []

    for cluster in cluster_alerts(alerts, gap_minutes=gap_minutes):
        host = cluster["host"].iloc[0]
        user = cluster["user"].iloc[0]
        alert_ids = cluster["alert_id"].tolist()
        rule_ids = sorted(set(cluster["rule_id"].tolist()))

        evidence_ids: list[str] = []
        for value in cluster["evidence_event_ids"]:
            evidence_ids.extend(schemas.split_ids(value))
        evidence_ids = list(dict.fromkeys(evidence_ids))

        context = gather_context_events(
            events, cluster, set(evidence_ids), context_minutes=context_minutes
        )
        context_ids = context["event_id"].tolist() if not context.empty else []
        all_event_ids = list(dict.fromkeys(evidence_ids + context_ids))

        # The incident spans the alerts and every event attached to them.
        times = list(cluster["created_at"])
        attached = events[events["event_id"].isin(all_event_ids)]
        if not attached.empty:
            times.extend([attached["timestamp"].min(), attached["timestamp"].max()])
        start_time = min(times)
        end_time = max(times)

        severity = incident_severity(cluster, rule_ids)
        summary = build_summary(
            host, user, rule_ids, start_time, end_time, len(all_event_ids), context
        )

        incidents.append(
            {
                "incident_id": make_incident_id(host, user, alert_ids),
                "created_at": end_time,
                "host": host,
                "user": user,
                "severity": severity,
                "title": build_title(host, user, rule_ids),
                "status": schemas.STATUS_OPEN,
                "summary": summary,
                "start_time": start_time,
                "end_time": end_time,
                "evidence_count": len(all_event_ids),
                "alert_ids": ",".join(alert_ids),
                "rule_ids": ",".join(rule_ids),
                "evidence_event_ids": ",".join(all_event_ids),
            }
        )

    frame = incidents_to_frame(incidents)
    logger.info(
        "Correlation complete: %s alert(s) grouped into %s incident(s)",
        len(alerts),
        len(frame),
    )
    return frame
