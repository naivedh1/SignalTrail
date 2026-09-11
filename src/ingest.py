"""Ingestion: raw JSON files in, validated normalized events out.

The ingest stage is where a pipeline earns trust. It is not enough to load
what parses and quietly drop the rest, so every record is accounted for:
accepted, rejected with a reason, or discarded as a duplicate. The counters
collected here are printed by ``run_pipeline.py`` and surfaced in the
dashboard.
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from . import config
from . import normalize
from . import schemas

logger = logging.getLogger(__name__)


@dataclass
class IngestionMetrics:
    """Counters describing one ingestion run."""

    raw_records: int = 0
    valid_records: int = 0
    invalid_records: int = 0
    duplicate_event_ids: int = 0
    normalized_records: int = 0
    missing_field_records: int = 0
    duration_seconds: float = 0.0
    per_source: dict[str, int] = field(default_factory=dict)
    rejections: list[str] = field(default_factory=list)
    missing_fields: Counter = field(default_factory=Counter)

    def record_rejection(self, source_type: str, index: int, reason: str) -> None:
        self.invalid_records += 1
        # Keep a bounded sample; the count is what matters at scale.
        if len(self.rejections) < 20:
            self.rejections.append(f"{source_type}[{index}]: {reason}")

    def render(self) -> str:
        """Human-readable ingestion summary."""
        lines = [
            "SignalTrail ingestion",
            "",
            f"Raw records:      {self.raw_records}",
            f"Valid records:    {self.valid_records}",
            f"Invalid records:  {self.invalid_records}",
            f"Duplicates:       {self.duplicate_event_ids}",
            f"Normalized:       {self.normalized_records}",
            f"Duration:         {self.duration_seconds:.2f} seconds",
        ]
        if self.per_source:
            lines.append("")
            lines.append("Per source:")
            for source_type in sorted(self.per_source):
                lines.append(f"  {source_type:<16} {self.per_source[source_type]}")
        if self.missing_fields:
            lines.append("")
            lines.append("Events missing important fields:")
            for name, count in sorted(self.missing_fields.items()):
                lines.append(f"  {name:<16} {count}")
        if self.rejections:
            lines.append("")
            lines.append("Rejected records:")
            for reason in self.rejections:
                lines.append(f"  {reason}")
        return "\n".join(lines)


def load_raw_file(path: Path) -> list:
    """Read one raw JSON file, tolerating an unreadable or missing file."""
    if not path.exists():
        logger.warning("Raw source file not found: %s", path)
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.error("Raw source file is not valid JSON: %s", path)
        return []
    if not isinstance(payload, list):
        logger.error("Raw source file does not contain a list: %s", path)
        return []
    return payload


def ingest_records(
    records: list, source_type: str, metrics: IngestionMetrics, seen: set[str]
) -> list[dict]:
    """Validate and normalize one source's records, updating the metrics."""
    accepted: list[dict] = []

    for index, record in enumerate(records):
        metrics.raw_records += 1

        problems = schemas.validate_raw_record(record, source_type)
        if problems:
            metrics.record_rejection(source_type, index, "; ".join(problems))
            continue

        try:
            event = normalize.normalize_record(record, source_type)
        except normalize.NormalizationError as exc:
            metrics.record_rejection(source_type, index, str(exc))
            continue

        metrics.valid_records += 1

        if event["event_id"] in seen:
            metrics.duplicate_event_ids += 1
            continue
        seen.add(event["event_id"])

        missing = normalize.missing_important_fields(event)
        if missing:
            metrics.missing_field_records += 1
            metrics.missing_fields.update(missing)

        accepted.append(event)

    metrics.per_source[source_type] = len(accepted)
    return accepted


def events_to_frame(events: list[dict]) -> pd.DataFrame:
    """Build a typed DataFrame in the canonical column order.

    Explicit dtypes matter: an empty result still has to load into DuckDB
    without the column types shifting, so they are set even when there are no
    rows to infer from.
    """
    frame = pd.DataFrame(events, columns=list(schemas.NORMALIZED_COLUMNS))

    for column in schemas.NORMALIZED_TEXT_COLUMNS:
        frame[column] = frame[column].fillna(schemas.EMPTY_VALUE).astype("string")

    frame["dst_port"] = pd.to_numeric(frame["dst_port"], errors="coerce").astype("Int64")

    # Store timestamps as naive UTC. Every layer above treats them as UTC,
    # which avoids mixed-offset comparisons inside DuckDB and pandas.
    frame["timestamp"] = schemas.to_naive_utc(frame["timestamp"])

    return frame.sort_values("timestamp", kind="stable").reset_index(drop=True)


def run_ingestion(sources: dict[str, Path] | None = None) -> tuple[pd.DataFrame, IngestionMetrics]:
    """Ingest every configured raw source into one normalized DataFrame."""
    sources = config.RAW_SOURCES if sources is None else sources
    metrics = IngestionMetrics()
    started = time.perf_counter()

    seen: set[str] = set()
    all_events: list[dict] = []

    for source_type, path in sources.items():
        records = load_raw_file(Path(path))
        logger.info("Read %s raw records from %s", len(records), Path(path).name)
        all_events.extend(ingest_records(records, source_type, metrics, seen))

    frame = events_to_frame(all_events)
    metrics.normalized_records = len(frame)
    metrics.duration_seconds = time.perf_counter() - started

    logger.info(
        "Ingestion complete: %s normalized, %s invalid, %s duplicate",
        metrics.normalized_records,
        metrics.invalid_records,
        metrics.duplicate_event_ids,
    )
    return frame, metrics
