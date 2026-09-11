"""Aggregations for the dashboard.

Chart data is computed here rather than inside the Streamlit layer, which
keeps the UI code about presentation and makes the aggregations testable
without starting a web server. Every function returns a tidy DataFrame with
predictable column names, so a chart can be swapped without touching the
query behind it.
"""

from __future__ import annotations

import pandas as pd

from . import schemas


def overview_metrics(
    events: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame
) -> dict[str, int]:
    """Headline counters for the overview panel."""
    high_ranks = {schemas.SEVERITY_HIGH, schemas.SEVERITY_CRITICAL}
    return {
        "total_events": len(events),
        "hosts": int(events["host"].nunique()) if not events.empty else 0,
        "users": int(events["user"].nunique()) if not events.empty else 0,
        "alerts": len(alerts),
        "high_severity_alerts": (
            int(alerts["severity"].isin(high_ranks).sum()) if not alerts.empty else 0
        ),
        "incidents": len(incidents),
    }


def events_over_time(events: pd.DataFrame, freq: str = "h") -> pd.DataFrame:
    """Event volume per time bucket, for the activity chart."""
    if events.empty:
        return pd.DataFrame(columns=["bucket", "events"])
    counts = (
        events.set_index("timestamp")
        .resample(freq)
        .size()
        .rename("events")
        .reset_index()
        .rename(columns={"timestamp": "bucket"})
    )
    return counts


def events_by_type(events: pd.DataFrame) -> pd.DataFrame:
    """Counts per normalized event type."""
    if events.empty:
        return pd.DataFrame(columns=["event_type", "events"])
    return (
        events.groupby("event_type").size().rename("events").reset_index()
        .sort_values("events", ascending=False)
    )


def alerts_by_severity(alerts: pd.DataFrame) -> pd.DataFrame:
    """Alert counts per severity, ordered low to high rather than by size."""
    if alerts.empty:
        return pd.DataFrame(columns=["severity", "alerts"])
    counts = alerts.groupby("severity").size().rename("alerts").reset_index()
    counts["rank"] = counts["severity"].map(schemas.SEVERITY_RANK).fillna(0)
    return counts.sort_values("rank").drop(columns="rank").reset_index(drop=True)


def alerts_by_host(alerts: pd.DataFrame) -> pd.DataFrame:
    """Alert counts per host, busiest first."""
    if alerts.empty:
        return pd.DataFrame(columns=["host", "alerts"])
    return (
        alerts.groupby("host").size().rename("alerts").reset_index()
        .sort_values("alerts", ascending=False)
    )


def alerts_by_rule(alerts: pd.DataFrame) -> pd.DataFrame:
    """Alert counts per rule, which is the first thing to check when tuning."""
    if alerts.empty:
        return pd.DataFrame(columns=["rule_id", "rule_name", "alerts"])
    return (
        alerts.groupby(["rule_id", "rule_name"]).size().rename("alerts").reset_index()
        .sort_values("alerts", ascending=False)
    )


def top_values(events: pd.DataFrame, column: str, limit: int = 10) -> pd.DataFrame:
    """The most frequent non-empty values in a column."""
    if events.empty or column not in events.columns:
        return pd.DataFrame(columns=[column, "count"])
    series = events[column]
    series = series[series.notna() & (series != schemas.EMPTY_VALUE)]
    if series.empty:
        return pd.DataFrame(columns=[column, "count"])
    return (
        series.value_counts().head(limit).rename("count").reset_index()
        .rename(columns={"index": column})
    )


def severity_counts(frame: pd.DataFrame) -> dict[str, int]:
    """Severity histogram as a plain dict, covering every level."""
    counts = {level: 0 for level in schemas.SEVERITY_ORDER}
    if frame.empty or "severity" not in frame.columns:
        return counts
    for severity, count in frame["severity"].value_counts().items():
        if severity in counts:
            counts[severity] = int(count)
    return counts
