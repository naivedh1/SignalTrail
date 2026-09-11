"""Optional behavioural anomaly detection.

This module answers a different question from ``detections.py``. A rule asks
"did this specific thing happen?" and can be read, argued with and tuned. An
anomaly model asks "is this unlike the rest of the data?" and cannot explain
itself in the same way.

That difference decides how the output is used. Anomaly scores here are a
*ranking aid*: they suggest where an analyst might look when no rule has
fired. They never create alerts, never create incidents, and never appear as
a verdict. A high score means unusual, and unusual is not the same as
malicious - on a small dataset like this one, a quiet host or a backup window
will score just as highly as anything worth investigating.

scikit-learn is an optional dependency. If it is missing the rest of
SignalTrail works unchanged; this module simply reports that it is
unavailable.
"""

from __future__ import annotations

import logging

import pandas as pd

from . import config
from . import schemas

logger = logging.getLogger(__name__)

try:  # pragma: no cover - exercised by whether the package is installed
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    IsolationForest = None
    SKLEARN_AVAILABLE = False


#: The behavioural features scored by the model. Each is a count over one
#: time bucket for one host, which keeps them interpretable.
FEATURE_COLUMNS = [
    "failed_logins",
    "dns_requests",
    "outbound_connections",
    "unique_destinations",
    "process_count",
    "rare_process_indicator",
]


def build_features(
    events: pd.DataFrame, bucket_minutes: int | None = None
) -> pd.DataFrame:
    """Summarize activity into per-host, per-time-bucket behaviour features.

    The bucket length is a trade-off: short buckets catch fast bursts but make
    every quiet window look alike, long buckets smooth bursts away. Five
    minutes matches the brute-force rule's timescale.
    """
    if events.empty:
        return pd.DataFrame(columns=["host", "bucket", *FEATURE_COLUMNS])

    minutes = config.ANOMALY_BUCKET_MINUTES if bucket_minutes is None else bucket_minutes
    frame = events.copy()
    frame["bucket"] = frame["timestamp"].dt.floor(f"{minutes}min")

    # A process is "rare" if it appears in the bottom decile of the overall
    # process frequency distribution. Computed across the whole dataset, so it
    # describes the environment rather than the individual bucket.
    processes = frame.loc[frame["process_name"] != schemas.EMPTY_VALUE, "process_name"]
    if processes.empty:
        rare_processes: set[str] = set()
    else:
        frequencies = processes.value_counts()
        cutoff = frequencies.quantile(0.10)
        rare_processes = set(frequencies[frequencies <= cutoff].index)

    frame["is_failed_login"] = (
        (frame["event_type"] == schemas.EVENT_TYPE_AUTHENTICATION)
        & (frame["status"] == schemas.STATUS_FAILURE)
    ).astype(int)
    frame["is_dns"] = (frame["event_type"] == schemas.EVENT_TYPE_DNS).astype(int)
    frame["is_network"] = (frame["event_type"] == schemas.EVENT_TYPE_NETWORK).astype(int)
    frame["is_process"] = (frame["event_type"] == schemas.EVENT_TYPE_PROCESS).astype(int)
    frame["is_rare_process"] = frame["process_name"].isin(rare_processes).astype(int)
    frame["destination"] = frame["dst_ip"].where(
        frame["dst_ip"] != schemas.EMPTY_VALUE, None
    )

    grouped = frame.groupby(["host", "bucket"], sort=True)
    features = pd.DataFrame(
        {
            "failed_logins": grouped["is_failed_login"].sum(),
            "dns_requests": grouped["is_dns"].sum(),
            "outbound_connections": grouped["is_network"].sum(),
            "unique_destinations": grouped["destination"].nunique(),
            "process_count": grouped["is_process"].sum(),
            "rare_process_indicator": grouped["is_rare_process"].sum(),
        }
    ).reset_index()

    return features


def score_anomalies(
    features: pd.DataFrame,
    contamination: float | None = None,
    random_state: int | None = None,
) -> pd.DataFrame:
    """Score behaviour buckets with an Isolation Forest.

    Returns the features with two extra columns:

    ``anomaly_score``
        The raw model score. Lower means more isolated, i.e. more unusual.
    ``risk_signal``
        The same information rescaled to 0-100 for display. This is a relative
        ranking within this dataset, not a probability and not a confidence.
    """
    if features.empty:
        return features.assign(anomaly_score=[], risk_signal=[], is_outlier=[])

    if not SKLEARN_AVAILABLE:
        logger.warning("scikit-learn is not installed; skipping anomaly scoring")
        return features.assign(
            anomaly_score=float("nan"), risk_signal=float("nan"), is_outlier=False
        )

    # The model needs more samples than it has features to say anything useful.
    if len(features) <= len(FEATURE_COLUMNS):
        logger.warning(
            "Only %s behaviour buckets; too few for anomaly scoring", len(features)
        )
        return features.assign(
            anomaly_score=float("nan"), risk_signal=float("nan"), is_outlier=False
        )

    model = IsolationForest(
        contamination=(
            config.ANOMALY_CONTAMINATION if contamination is None else contamination
        ),
        random_state=(
            config.ANOMALY_RANDOM_STATE if random_state is None else random_state
        ),
        n_estimators=200,
    )
    matrix = features[FEATURE_COLUMNS].to_numpy(dtype=float)
    predictions = model.fit_predict(matrix)
    scores = model.score_samples(matrix)

    scored = features.copy()
    scored["anomaly_score"] = scores
    scored["is_outlier"] = predictions == -1

    # Rescale so the most isolated bucket in this run reads as 100.
    low, high = float(scores.min()), float(scores.max())
    if high == low:
        scored["risk_signal"] = 0.0
    else:
        scored["risk_signal"] = ((high - scores) / (high - low) * 100).round(1)

    return scored.sort_values("risk_signal", ascending=False).reset_index(drop=True)


def run_anomaly_detection(
    events: pd.DataFrame, bucket_minutes: int | None = None
) -> pd.DataFrame:
    """Build behaviour features and score them in one step."""
    features = build_features(events, bucket_minutes=bucket_minutes)
    logger.info("Built %s behaviour buckets for anomaly scoring", len(features))
    return score_anomalies(features)


def describe_bucket(row) -> str:
    """A plain-language note about why a bucket stood out.

    The model does not produce reasons, so this reports the feature values
    that are unusually high instead - which is a hint for an analyst, not an
    explanation of the model's decision.
    """
    notes = []
    if row.get("failed_logins", 0) >= 3:
        notes.append(f"{int(row['failed_logins'])} failed logins")
    if row.get("outbound_connections", 0) >= 5:
        notes.append(f"{int(row['outbound_connections'])} outbound connections")
    if row.get("unique_destinations", 0) >= 5:
        notes.append(f"{int(row['unique_destinations'])} distinct destinations")
    if row.get("dns_requests", 0) >= 5:
        notes.append(f"{int(row['dns_requests'])} DNS queries")
    if row.get("rare_process_indicator", 0) >= 1:
        notes.append("an uncommon process")
    if not notes:
        return "Activity mix differs from this dataset's usual pattern."
    return "Higher than usual: " + ", ".join(notes) + "."
