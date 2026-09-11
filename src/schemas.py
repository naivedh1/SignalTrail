"""Schema definitions for SignalTrail.

Three things live here:

1. The *raw* schema of each telemetry source. Every source has a slightly
   different shape, which is exactly the problem the normalizer solves.
2. The *common event model* every source is mapped onto.
3. Small metadata vocabularies: severities, event types and the conservative
   MITRE ATT&CK mapping used to label detections.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pandas as pd

# --------------------------------------------------------------------------
# Severity vocabulary
# --------------------------------------------------------------------------

SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER = [
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
]
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}


def max_severity(severities) -> str:
    """Return the highest severity in an iterable, or INFO when empty."""
    ranked = [s for s in severities if s in SEVERITY_RANK]
    if not ranked:
        return SEVERITY_INFO
    return max(ranked, key=lambda s: SEVERITY_RANK[s])


def escalate(severity: str, steps: int = 1) -> str:
    """Move a severity up the scale, stopping at CRITICAL."""
    rank = SEVERITY_RANK.get(severity, 0)
    return SEVERITY_ORDER[min(rank + steps, len(SEVERITY_ORDER) - 1)]


# --------------------------------------------------------------------------
# Standardized event vocabulary
# --------------------------------------------------------------------------

EVENT_TYPE_AUTHENTICATION = "authentication"
EVENT_TYPE_PROCESS = "process"
EVENT_TYPE_FILE = "file"
EVENT_TYPE_DNS = "dns"
EVENT_TYPE_NETWORK = "network"

EVENT_TYPES = [
    EVENT_TYPE_AUTHENTICATION,
    EVENT_TYPE_PROCESS,
    EVENT_TYPE_FILE,
    EVENT_TYPE_DNS,
    EVENT_TYPE_NETWORK,
]

STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_UNKNOWN = "unknown"

# --------------------------------------------------------------------------
# Raw source schemas
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RawSourceSchema:
    """Validation contract for one raw telemetry source."""

    source_type: str
    required: tuple[str, ...]
    #: Fields a source may carry but whose absence is not an error. Recorded
    #: so the shape of each source is documented in one place; validation does
    #: not act on them, so nothing here should name a field the source never
    #: actually produces.
    optional: tuple[str, ...] = ()
    #: Field holding the event time, and the parser strategy for its format.
    timestamp_field: str = "timestamp"
    timestamp_format: str = "iso"  # one of: iso, naive, epoch
    integer_fields: tuple[str, ...] = ()


RAW_SCHEMAS: dict[str, RawSourceSchema] = {
    # Authentication logs use ISO-8601 with an explicit UTC Z suffix and name
    # the account field "username".
    "authentication": RawSourceSchema(
        source_type="authentication",
        required=("timestamp", "username", "source_ip", "action", "status", "host"),
        optional=("auth_method",),
        timestamp_format="iso",
    ),
    # Endpoint logs use a space-separated timestamp with no zone marker and
    # name the account field "user".
    "endpoint": RawSourceSchema(
        source_type="endpoint",
        required=("timestamp", "host", "user", "process", "action"),
        optional=("command_line", "file_path"),
        timestamp_format="naive",
    ),
    # DNS logs use a Unix epoch timestamp and call the domain "query".
    "dns": RawSourceSchema(
        source_type="dns",
        required=("timestamp", "host", "user", "query", "action"),
        optional=("response_code",),
        timestamp_format="epoch",
    ),
    # Network logs use an ISO-8601 timestamp with a numeric UTC offset.
    "network": RawSourceSchema(
        source_type="network",
        required=(
            "timestamp",
            "host",
            "user",
            "destination_ip",
            "destination_port",
            "action",
        ),
        optional=("protocol", "bytes_out"),
        timestamp_format="iso",
        integer_fields=("destination_port", "bytes_out"),
    ),
}


def _is_blank(value: Any) -> bool:
    """Whether a required field carries nothing usable.

    A whitespace-only value has to count as empty here. Normalization strips
    it to the empty marker anyway, so accepting it would let a record through
    validation and then produce an event with no host or no account - which is
    the same unusable record, minus the rejection that explains it.
    """
    return value is None or (isinstance(value, str) and not value.strip())


def validate_raw_record(record: Any, source_type: str) -> list[str]:
    """Return a list of validation problems for one raw record.

    An empty list means the record is structurally usable. Validation is
    deliberately shallow: it checks the things that would break normalization,
    not the plausibility of the values.
    """
    schema = RAW_SCHEMAS.get(source_type)
    if schema is None:
        return ["unknown source type: " + str(source_type)]

    if not isinstance(record, dict):
        return ["record is " + type(record).__name__ + ", expected object"]

    problems: list[str] = []
    for name in schema.required:
        if name not in record:
            problems.append("missing required field: " + name)
        elif _is_blank(record[name]):
            problems.append("empty required field: " + name)

    for name in schema.integer_fields:
        value = record.get(name)
        if value is None or value == "":
            continue
        try:
            int(value)
        except (TypeError, ValueError):
            problems.append("field is not an integer: " + name)

    return problems


# --------------------------------------------------------------------------
# Common (normalized) event model
# --------------------------------------------------------------------------

#: Column order of the normalized event model, shared by pandas and DuckDB.
NORMALIZED_COLUMNS: tuple[str, ...] = (
    "event_id",
    "timestamp",
    "host",
    "user",
    "source_type",
    "event_type",
    "action",
    "src_ip",
    "dst_ip",
    "dst_port",
    "domain",
    "process_name",
    "command_line",
    "file_path",
    "status",
    "severity",
    "raw_message",
)

#: Fields stored as text. Everything else is the timestamp or an integer.
NORMALIZED_TEXT_COLUMNS: tuple[str, ...] = tuple(
    c for c in NORMALIZED_COLUMNS if c not in ("timestamp", "dst_port")
)

#: Fields whose absence does not invalidate an event but is worth counting,
#: because investigations get much harder without them.
IMPORTANT_FIELDS: tuple[str, ...] = ("timestamp", "host", "user", "event_type")

#: Placeholder written into text fields that do not apply to a source.
EMPTY_VALUE = ""


def to_naive_utc(values) -> pd.Series:
    """Coerce a column of moments to the project's one timestamp convention.

    Every timestamp in the store is naive UTC, decided once at normalization
    so that nothing downstream has to compare mixed offsets. Events, alerts
    and incidents all go through here, because three near-identical copies of
    this is how the convention drifts.

    ``utc=True`` is the part that matters. Without it, a column holding two
    different offsets cannot become one datetime dtype, and ``coerce`` turns
    the odd one out into ``NaT`` - the finding survives with its time silently
    erased, which is worse than an error. Naive input is read as UTC, which is
    the stated assumption rather than the local machine's.
    """
    converted = pd.to_datetime(values, utc=True, errors="coerce")
    return converted.dt.tz_localize(None)


def split_ids(value) -> list[str]:
    """Split a stored comma-separated identifier list into its parts.

    Evidence references are stored as one comma-separated string per alert or
    incident, so this runs on the path between a finding and the records
    behind it. It has to tolerate every way a database round-trip can express
    "no value": ``None``, ``float('nan')``, and pandas' ``NA`` - which raises
    on ``bool()`` rather than being falsy, and stringifies to ``"<NA>"``
    rather than to nothing.

    Getting that wrong is quiet rather than loud: a bogus identifier simply
    matches no event, and the evidence disappears without an error.
    """
    if value is None:
        return []

    # NA scalars are not equal to themselves. pandas' NA raises TypeError on
    # the comparison's truth test instead of returning False, so both the
    # True branch and the exception mean "this is a null".
    try:
        if value != value:
            return []
    except (TypeError, ValueError):
        return []

    return [part for part in str(value).split(",") if part]

# --------------------------------------------------------------------------
# MITRE ATT&CK mapping
# --------------------------------------------------------------------------
# Intentionally tiny. Only techniques that the corresponding rule can
# genuinely suggest are listed, and the labels are treated as hypotheses for
# an analyst to confirm, never as proof.


@dataclass(frozen=True)
class Technique:
    technique_id: str
    technique_name: str
    tactic: str


MITRE_TECHNIQUES: dict[str, Technique] = {
    "T1110": Technique("T1110", "Brute Force", "Credential Access"),
    "T1059.001": Technique(
        "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"
    ),
    "T1071.001": Technique(
        "T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"
    ),
    "T1071.004": Technique(
        "T1071.004", "Application Layer Protocol: DNS", "Command and Control"
    ),
    "T1105": Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
}


# --------------------------------------------------------------------------
# Detection rule metadata
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionRule:
    """Everything a reviewer needs to judge a detection without reading code."""

    rule_id: str
    name: str
    description: str
    severity: str
    inputs: tuple[str, ...]
    logic: str
    technique_id: str | None = None
    false_positives: tuple[str, ...] = field(default_factory=tuple)

    @property
    def technique(self) -> Technique | None:
        if self.technique_id is None:
            return None
        return MITRE_TECHNIQUES.get(self.technique_id)

    @property
    def technique_name(self) -> str:
        technique = self.technique
        return technique.technique_name if technique else EMPTY_VALUE

    @property
    def tactic(self) -> str:
        technique = self.technique
        return technique.tactic if technique else EMPTY_VALUE


# --------------------------------------------------------------------------
# Alert and incident models
# --------------------------------------------------------------------------

ALERT_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "created_at",
    "rule_id",
    "rule_name",
    "host",
    "user",
    "event_id",
    "evidence_event_ids",
    "evidence_count",
    "severity",
    "reason",
    "status",
    "technique_id",
    "technique_name",
)

INCIDENT_COLUMNS: tuple[str, ...] = (
    "incident_id",
    "created_at",
    "host",
    "user",
    "severity",
    "title",
    "status",
    "summary",
    "start_time",
    "end_time",
    "evidence_count",
    "alert_ids",
    "rule_ids",
    "evidence_event_ids",
)

STATUS_OPEN = "open"
