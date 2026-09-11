"""Detection engine.

The rules here are deterministic: given the same events they always produce
the same alerts, with the same identifiers. That is a deliberate choice. A
detection an analyst cannot reproduce is a detection they cannot trust, and it
also makes the rules straightforward to unit-test.

Two conventions run through the whole module:

**Every alert carries its evidence.** ``evidence_event_ids`` lists the exact
events that caused the rule to fire, so an analyst can always get from a
finding back to the records behind it.

**Alerts describe observations, not conclusions.** A rule can say that six
failed logins were followed by a success; it cannot say an account was
compromised. The wording of every ``reason`` string reflects that, and the
MITRE labels are hypotheses to check rather than verdicts.
"""

from __future__ import annotations

import hashlib
import logging
import shlex
from datetime import datetime, timedelta

import pandas as pd

from . import config
from . import schemas
from .schemas import DetectionRule

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Rule catalogue
# --------------------------------------------------------------------------

RULES: dict[str, DetectionRule] = {
    "RULE-001": DetectionRule(
        rule_id="RULE-001",
        name="Repeated authentication failures",
        description=(
            "A burst of failed logins for the same account, on the same host, "
            "from the same source address. Consistent with password guessing, "
            "but also with a stale saved credential."
        ),
        severity=schemas.SEVERITY_MEDIUM,
        inputs=("authentication",),
        logic=(
            f"{config.AUTH_FAILURE_THRESHOLD} or more failed logins grouped by "
            f"(user, host, src_ip) within a sliding "
            f"{config.AUTH_FAILURE_WINDOW_MINUTES} minute window"
        ),
        technique_id="T1110",
        false_positives=(
            "A service account or scheduled job still using a rotated password",
            "A user whose saved credential expired on a phone or mail client",
            "A misconfigured application retrying automatically",
        ),
    ),
    "RULE-002": DetectionRule(
        rule_id="RULE-002",
        name="Encoded PowerShell command",
        description=(
            "PowerShell started with an encoded command line. Encoding is a "
            "supported feature, and it is also a common way to keep a command "
            "out of plain-text logs."
        ),
        severity=schemas.SEVERITY_HIGH,
        inputs=("endpoint",),
        logic=(
            "process_name is exactly one of the configured PowerShell binaries "
            "and a command-line token is an encoded-command switch (any prefix "
            "of -EncodedCommand, down to -e)"
        ),
        technique_id="T1059.001",
        false_positives=(
            "Management and deployment tooling that legitimately encodes commands",
            "Installers and vendor agents that wrap their own scripts",
        ),
    ),
    "RULE-003": DetectionRule(
        rule_id="RULE-003",
        name="Suspicious DNS query",
        description=(
            "A host resolved a domain on the local watchlist. Resolution alone "
            "does not prove a connection was made or that anything was sent."
        ),
        severity=schemas.SEVERITY_MEDIUM,
        inputs=("dns",),
        logic="domain matches an entry in the configured suspicious-domain watchlist",
        technique_id="T1071.004",
        false_positives=(
            "A stale watchlist entry after a domain changes ownership",
            "Security tooling or a researcher resolving the domain on purpose",
            "A cached or prefetched lookup the user never initiated",
        ),
    ),
    "RULE-004": DetectionRule(
        rule_id="RULE-004",
        name="Connection to suspicious destination",
        description=(
            "An outbound connection to an address on the local watchlist. The "
            "volume of data transferred, if known, is worth checking next."
        ),
        severity=schemas.SEVERITY_MEDIUM,
        inputs=("network",),
        logic="dst_ip matches an entry in the configured suspicious-destination watchlist",
        technique_id="T1071.001",
        false_positives=(
            "A shared hosting address where most traffic is unrelated",
            "A blocked connection attempt that never completed",
            "An address recycled since the watchlist was written",
        ),
    ),
    "RULE-005": DetectionRule(
        rule_id="RULE-005",
        name="File activity after suspicious process execution",
        description=(
            "A file was created on the same host and account shortly after a "
            "process that RULE-002 flagged. The sequence is what is "
            "interesting here; neither event alone would be."
        ),
        severity=schemas.SEVERITY_MEDIUM,
        inputs=("endpoint",),
        logic=(
            "a file_create event on the same (host, user) within "
            f"{config.POST_EXECUTION_WINDOW_MINUTES} minutes after a process "
            "flagged by RULE-002"
        ),
        technique_id="T1105",
        false_positives=(
            "A legitimate script writing its own output or log files",
            "Software installation running under the same account",
        ),
    ),
}


# --------------------------------------------------------------------------
# Alert construction
# --------------------------------------------------------------------------


def make_alert_id(rule_id: str, host: str, user: str, evidence_ids: list[str]) -> str:
    """Deterministic alert identifier.

    Built from the rule and the exact evidence, so re-running detection over
    unchanged data regenerates the same alert rather than a new one.
    """
    material = "|".join([rule_id, host or "", user or "", *sorted(evidence_ids)])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return "ALR-" + digest[:16]


def build_alert(
    rule: DetectionRule,
    host: str,
    user: str,
    anchor_event_id: str,
    evidence_ids: list[str],
    created_at: datetime,
    reason: str,
    severity: str | None = None,
) -> dict:
    """Assemble one alert record in the shape the alerts table expects."""
    evidence = list(dict.fromkeys(evidence_ids))  # de-duplicate, keep order
    return {
        "alert_id": make_alert_id(rule.rule_id, host, user, evidence),
        "created_at": created_at,
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "host": host,
        "user": user,
        "event_id": anchor_event_id,
        "evidence_event_ids": ",".join(evidence),
        "evidence_count": len(evidence),
        "severity": severity or rule.severity,
        "reason": reason,
        "status": schemas.STATUS_OPEN,
        "technique_id": rule.technique_id or schemas.EMPTY_VALUE,
        "technique_name": rule.technique_name,
    }


# --------------------------------------------------------------------------
# RULE-001: repeated authentication failures
# --------------------------------------------------------------------------


def detect_auth_bruteforce(
    events: pd.DataFrame,
    threshold: int | None = None,
    window_minutes: int | None = None,
) -> list[dict]:
    """Find bursts of failed logins sharing an account, host and source IP."""
    rule = RULES["RULE-001"]
    # Explicit None checks, not "or": a caller passing 0 means 0.
    if threshold is None:
        threshold = config.AUTH_FAILURE_THRESHOLD
    if window_minutes is None:
        window_minutes = config.AUTH_FAILURE_WINDOW_MINUTES
    window = timedelta(minutes=window_minutes)

    failures = events[
        (events["event_type"] == schemas.EVENT_TYPE_AUTHENTICATION)
        & (events["status"] == schemas.STATUS_FAILURE)
    ].sort_values("timestamp")

    alerts: list[dict] = []
    for (user, host, src_ip), group in failures.groupby(
        ["user", "host", "src_ip"], sort=True
    ):
        rows = group.reset_index(drop=True)
        times = list(rows["timestamp"])
        ids = list(rows["event_id"])

        # Sliding window: walk the failures once, keeping the left edge inside
        # the window. Bursts are reported whole rather than once per event.
        start = 0
        claimed = 0  # index of the first failure not yet part of an alert
        for end in range(len(times)):
            # Never reach back past failures already reported. Without this a
            # sustained stream - a scheduled job retrying a stale password all
            # morning - produces one alert per event, each re-reporting the
            # same failures under a different identifier.
            start = max(start, claimed)
            if start > end:
                continue
            while times[end] - times[start] > window:
                start += 1
            if end - start + 1 < threshold:
                continue

            # Extend the burst as far as the window allows.
            burst_end = end
            while (
                burst_end + 1 < len(times)
                and times[burst_end + 1] - times[start] <= window
            ):
                burst_end += 1

            evidence = ids[start : burst_end + 1]
            count = len(evidence)
            reason = (
                f"{count} failed logins for '{user}' on {host} from {src_ip} "
                f"within {window_minutes} "
                "minutes. Possible password guessing; confirm whether the "
                "source and account are expected before treating it as an attack."
            )
            alerts.append(
                build_alert(
                    rule=rule,
                    host=host,
                    user=user,
                    anchor_event_id=ids[burst_end],
                    evidence_ids=evidence,
                    created_at=times[burst_end],
                    reason=reason,
                )
            )
            claimed = burst_end + 1

    return alerts


# --------------------------------------------------------------------------
# RULE-002: encoded PowerShell
# --------------------------------------------------------------------------


def _is_powershell(process_name: str) -> bool:
    """Whether a process name is one of the configured PowerShell binaries.

    Compared on the file name alone, so a path does not change the answer. It
    is an equality test rather than a substring test: "notpowershell.exe"
    contains "powershell.exe" but is a different program.
    """
    name = (process_name or "").strip().lower().replace("\\", "/").rsplit("/", 1)[-1]
    return name in config.POWERSHELL_PROCESS_NAMES


def _is_switch(token: str, names: tuple[str, ...]) -> bool:
    """Whether one command-line token is any of the named PowerShell switches.

    PowerShell resolves an abbreviated switch to its full name, so "-e",
    "-enc" and "-EncodedCommand" all mean the same thing, and a value may be
    attached with a colon. Matching whole tokens rather than substrings is
    what stops "-e" inside an unrelated argument from firing the rule.
    """
    if len(token) < 2 or token[0] not in "-/":
        return False
    name = token[1:].split(":", 1)[0].lower()
    return bool(name) and any(switch.startswith(name) for switch in names)


def _is_encoded_switch(token: str) -> bool:
    """Whether one command-line token selects PowerShell's encoded command."""
    return _is_switch(token, config.ENCODED_COMMAND_SWITCHES)


def _tokenize(command_line: str) -> list[str]:
    """Split a command line into tokens, respecting quoted arguments.

    Splitting on whitespace alone is not enough: in
    ``-Command "Write-Host 'a -e b'"`` the ``-e`` is part of a quoted string,
    not a switch, and treating it as one fires RULE-002 on an ordinary
    command. ``posix=False`` keeps the quote characters attached to the token,
    which is what lets the switch test reject it.

    An unbalanced quote makes shlex raise. That is a malformed command line
    rather than a reason to skip the event, so it falls back to whitespace
    splitting - the rule stays slightly over-eager on broken input instead of
    going blind to it.
    """
    if not command_line:
        return []
    try:
        return shlex.split(command_line, posix=False)
    except ValueError:
        return command_line.split()


def _is_encoded_powershell(process_name: str, command_line: str) -> bool:
    if not _is_powershell(process_name):
        return False
    for token in _tokenize(command_line):
        if _is_encoded_switch(token):
            return True
        if _is_switch(token, config.POWERSHELL_TERMINATING_SWITCHES):
            # -File and -Command hand everything after them to the script or
            # the command text, so a later "-e" is an argument to that script
            # rather than a switch PowerShell itself would act on.
            return False
    return False


def detect_encoded_powershell(events: pd.DataFrame) -> list[dict]:
    """Flag PowerShell processes started with an encoded command line."""
    rule = RULES["RULE-002"]
    processes = events[events["event_type"] == schemas.EVENT_TYPE_PROCESS]

    alerts: list[dict] = []
    for row in processes.itertuples(index=False):
        if not _is_encoded_powershell(row.process_name, row.command_line):
            continue
        reason = (
            f"{row.process_name} started on {row.host} as '{row.user}' with an "
            "encoded command line. The command was not recorded in readable "
            "form; decode and review it before drawing conclusions."
        )
        alerts.append(
            build_alert(
                rule=rule,
                host=row.host,
                user=row.user,
                anchor_event_id=row.event_id,
                evidence_ids=[row.event_id],
                created_at=row.timestamp,
                reason=reason,
            )
        )
    return alerts


# --------------------------------------------------------------------------
# RULE-003: suspicious DNS
# --------------------------------------------------------------------------


def detect_suspicious_dns(
    events: pd.DataFrame, watchlist: set[str] | None = None
) -> list[dict]:
    """Flag lookups of domains on the watchlist."""
    rule = RULES["RULE-003"]
    if watchlist is None:
        watchlist = config.SUSPICIOUS_DOMAINS
    watchlist = {d.lower() for d in watchlist}

    queries = events[
        (events["event_type"] == schemas.EVENT_TYPE_DNS)
        & (events["domain"].str.lower().isin(watchlist))
    ]

    alerts: list[dict] = []
    for row in queries.itertuples(index=False):
        reason = (
            f"{row.host} resolved '{row.domain}', which is on the suspicious-domain "
            "watchlist. A lookup does not by itself show that a connection "
            "followed; check network telemetry for the same host and time."
        )
        alerts.append(
            build_alert(
                rule=rule,
                host=row.host,
                user=row.user,
                anchor_event_id=row.event_id,
                evidence_ids=[row.event_id],
                created_at=row.timestamp,
                reason=reason,
            )
        )
    return alerts


# --------------------------------------------------------------------------
# RULE-004: suspicious destination
# --------------------------------------------------------------------------


def detect_suspicious_destination(
    events: pd.DataFrame, watchlist: set[str] | None = None
) -> list[dict]:
    """Flag connections to addresses on the watchlist."""
    rule = RULES["RULE-004"]
    if watchlist is None:
        watchlist = config.SUSPICIOUS_DESTINATIONS
    watchlist = set(watchlist)

    connections = events[
        (events["event_type"] == schemas.EVENT_TYPE_NETWORK)
        & (events["dst_ip"].isin(watchlist))
    ]

    alerts: list[dict] = []
    for row in connections.itertuples(index=False):
        port = "" if pd.isna(row.dst_port) else f":{int(row.dst_port)}"
        outcome = (
            "blocked" if row.action == "connection_blocked" else "allowed"
        )
        reason = (
            f"{row.host} made an {outcome} outbound connection to "
            f"{row.dst_ip}{port}, which is on the suspicious-destination "
            "watchlist. Review what transferred before assessing impact."
        )
        alerts.append(
            build_alert(
                rule=rule,
                host=row.host,
                user=row.user,
                anchor_event_id=row.event_id,
                evidence_ids=[row.event_id],
                created_at=row.timestamp,
                reason=reason,
            )
        )
    return alerts


# --------------------------------------------------------------------------
# RULE-005: file activity after suspicious execution
# --------------------------------------------------------------------------


def detect_post_execution_file_activity(
    events: pd.DataFrame,
    process_alerts: list[dict],
    window_minutes: int | None = None,
) -> list[dict]:
    """Link a flagged process to file creation that follows it closely.

    This rule builds on RULE-002 rather than re-deriving what counts as a
    suspicious process, which keeps the definition in one place.
    """
    rule = RULES["RULE-005"]
    if window_minutes is None:
        window_minutes = config.POST_EXECUTION_WINDOW_MINUTES
    window = timedelta(minutes=window_minutes)

    file_events = events[events["event_type"] == schemas.EVENT_TYPE_FILE]
    if file_events.empty or not process_alerts:
        return []

    alerts: list[dict] = []
    for process_alert in process_alerts:
        anchor_time = process_alert["created_at"]
        host = process_alert["host"]
        user = process_alert["user"]

        following = file_events[
            (file_events["host"] == host)
            & (file_events["user"] == user)
            & (file_events["timestamp"] >= anchor_time)
            & (file_events["timestamp"] <= anchor_time + window)
        ].sort_values("timestamp")

        if following.empty:
            continue

        evidence = [process_alert["event_id"], *following["event_id"].tolist()]
        paths = [p for p in following["file_path"].tolist() if p]
        path_text = f" ({', '.join(paths[:3])})" if paths else ""
        last_row = following.iloc[-1]
        minutes = int(window.total_seconds() // 60)
        reason = (
            f"{len(following)} file(s) created on {host} as '{user}' within "
            f"{minutes} minutes of a process flagged by "
            f"{RULES['RULE-002'].rule_id}{path_text}. The ordering is "
            "suggestive; confirm the process actually wrote the file before "
            "treating it as a payload."
        )
        alerts.append(
            build_alert(
                rule=rule,
                host=host,
                user=user,
                anchor_event_id=last_row["event_id"],
                evidence_ids=evidence,
                created_at=last_row["timestamp"],
                reason=reason,
            )
        )
    return alerts


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


def alerts_to_frame(alerts: list[dict]) -> pd.DataFrame:
    """Build a typed alerts DataFrame in the canonical column order."""
    frame = pd.DataFrame(alerts, columns=list(schemas.ALERT_COLUMNS))

    for column in schemas.ALERT_COLUMNS:
        if column in ("created_at", "evidence_count"):
            continue
        frame[column] = frame[column].fillna(schemas.EMPTY_VALUE).astype("string")

    frame["evidence_count"] = pd.to_numeric(
        frame["evidence_count"], errors="coerce"
    ).astype("Int64")
    frame["created_at"] = schemas.to_naive_utc(frame["created_at"])

    return frame.sort_values(["created_at", "alert_id"], kind="stable").reset_index(
        drop=True
    )


def run_detections(events: pd.DataFrame) -> pd.DataFrame:
    """Run every rule and return the alerts as a DataFrame."""
    if events.empty:
        logger.warning("No events to run detections against")
        return alerts_to_frame([])

    alerts: list[dict] = []

    auth_alerts = detect_auth_bruteforce(events)
    powershell_alerts = detect_encoded_powershell(events)
    dns_alerts = detect_suspicious_dns(events)
    destination_alerts = detect_suspicious_destination(events)
    # RULE-005 consumes RULE-002's output, so it runs last.
    file_alerts = detect_post_execution_file_activity(events, powershell_alerts)

    for name, produced in (
        ("RULE-001", auth_alerts),
        ("RULE-002", powershell_alerts),
        ("RULE-003", dns_alerts),
        ("RULE-004", destination_alerts),
        ("RULE-005", file_alerts),
    ):
        logger.info("%s produced %s alert(s)", name, len(produced))
        alerts.extend(produced)

    frame = alerts_to_frame(alerts)
    logger.info("Detection complete: %s alert(s) total", len(frame))
    return frame


def rule_catalogue() -> pd.DataFrame:
    """The rule metadata as a table, for documentation and the dashboard."""
    rows = []
    for rule in RULES.values():
        rows.append(
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "inputs": ", ".join(rule.inputs),
                "logic": rule.logic,
                "technique_id": rule.technique_id or schemas.EMPTY_VALUE,
                "technique_name": rule.technique_name,
                "tactic": rule.tactic,
                "description": rule.description,
                "false_positives": " | ".join(rule.false_positives),
            }
        )
    return pd.DataFrame(rows)
