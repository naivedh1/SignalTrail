"""Optional local AI investigation layer.

The AI here is a writing assistant for an investigation, not a decision maker.
It is given a fixed evidence package built by ``investigate.summarize_incident``
and asked to organise it. It has no tools, no database access and no ability
to act; the only thing it can do is return text.

Three constraints shape the design:

**Local only.** Generation goes to an Ollama instance on the machine. No
telemetry leaves the host, which is the point of a local-first tool.

**Optional.** Ollama is not a dependency. If it is not running, this module
returns a deterministic summary built from the same evidence package. The
fallback is written to be genuinely useful on its own, not a stub.

**Grounded.** The prompt supplies the evidence and instructs the model to use
nothing else, to separate what was observed from what it infers, and to state
what is missing. Models still get things wrong, so the dashboard shows the
generated text next to the timeline it came from rather than in place of it.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

import pandas as pd

from . import config
from . import investigate
from .detections import RULES

logger = logging.getLogger(__name__)

MODE_AI = "ai"
MODE_DETERMINISTIC = "deterministic"


# --------------------------------------------------------------------------
# Availability
# --------------------------------------------------------------------------


def ollama_available(url: str | None = None, timeout: float | None = None) -> bool:
    """Check whether a local Ollama instance is reachable.

    Deliberately quick and quiet: an unavailable AI layer is a normal state
    for this project, not an error worth a stack trace.
    """
    endpoint = (url or config.OLLAMA_URL).rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(
            endpoint, timeout=timeout or config.OLLAMA_PROBE_TIMEOUT_SECONDS
        ) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def available_models(url: str | None = None) -> list[str]:
    """List models the local Ollama instance has pulled."""
    endpoint = (url or config.OLLAMA_URL).rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(
            endpoint, timeout=config.OLLAMA_PROBE_TIMEOUT_SECONDS
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return []
    return [model.get("name", "") for model in payload.get("models", [])]


# --------------------------------------------------------------------------
# Evidence package
# --------------------------------------------------------------------------


def build_evidence_package(conn, incident_id: str) -> dict:
    """Collect everything the AI layer is allowed to see for one incident."""
    context = investigate.summarize_incident(conn, incident_id)
    if not context:
        return {}

    incident = context["incident"]
    alerts = context["alerts"]

    return {
        "incident_id": incident.get("incident_id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "host": incident.get("host"),
        "user": incident.get("user"),
        "start_time": incident.get("start_time"),
        "end_time": incident.get("end_time"),
        "evidence_count": int(incident.get("evidence_count") or 0),
        "deterministic_summary": incident.get("summary"),
        "rule_ids": context["rule_ids"],
        "alerts": alerts,
        "timeline": context["timeline"],
        "indicators": context["indicators"],
    }


def render_evidence_text(package: dict) -> str:
    """Format the evidence package as the plain text given to the model."""
    lines = [
        "INCIDENT METADATA",
        f"  id:          {package['incident_id']}",
        f"  title:       {package['title']}",
        f"  severity:    {package['severity']}",
        f"  host:        {package['host']}",
        f"  account:     {package['user']}",
        f"  window:      {package['start_time']} to {package['end_time']} UTC",
        f"  evidence:    {package['evidence_count']} event(s)",
        "",
        "TRIGGERED DETECTION RULES",
    ]

    alerts = package["alerts"]
    if isinstance(alerts, pd.DataFrame) and not alerts.empty:
        for row in alerts.itertuples(index=False):
            rule = RULES.get(row.rule_id)
            technique = (
                f" [{row.technique_id} {row.technique_name}]" if row.technique_id else ""
            )
            lines.append(f"  {row.rule_id} ({row.severity}){technique}: {row.rule_name}")
            lines.append(f"    observation: {row.reason}")
            if rule and rule.false_positives:
                lines.append(
                    "    known benign causes: " + "; ".join(rule.false_positives)
                )
    else:
        lines.append("  (none)")

    lines.extend(["", "OBSERVED INDICATORS"])
    for label, values in package["indicators"].items():
        lines.append(f"  {label}: {', '.join(values) if values else '(none)'}")

    lines.extend(
        [
            "",
            "TIMELINE (events marked * caused a rule to fire; others are context)",
            investigate.render_timeline_text(package["timeline"]),
        ]
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Prompting
# --------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are assisting a security analyst who is investigating one incident in a \
local security analytics tool. You are a summarisation and reasoning aid. You \
do not take action and you do not have access to any system.

Rules you must follow:

1. Use ONLY the evidence supplied in the message. It is the complete record \
available for this incident.
2. Never invent events, timestamps, hostnames, accounts, addresses, domains, \
file paths or process names. If something is not in the evidence, it is not \
known.
3. Clearly separate what was OBSERVED (present in the evidence) from what you \
INFER. Label inferences as inferences.
4. State uncertainty plainly. A detection rule firing is not proof of an \
attack, and several of these rules have common benign causes.
5. Do not output commands, scripts, payloads, or any instructions for \
carrying out an attack. Recommend investigative steps only - what to check \
and where to look.
6. Do not recommend automated or destructive response actions. A human \
decides those.

Answer using exactly these six headings:

1. Incident summary
2. Observed evidence
3. Likely sequence
4. Risk assessment
5. Recommended investigation steps
6. Evidence gaps
"""


def build_investigation_prompt(package: dict) -> str:
    """The user-side prompt: the evidence, then the task."""
    return (
        "Investigate the following security incident.\n\n"
        "=== EVIDENCE PACKAGE ===\n"
        f"{render_evidence_text(package)}\n"
        "=== END OF EVIDENCE PACKAGE ===\n\n"
        "Write the investigation notes using the six required headings. Base "
        "every statement on the evidence above. Where the evidence does not "
        "settle a question, say so instead of filling the gap."
    )


def query_ollama(
    prompt: str,
    system: str = SYSTEM_PROMPT,
    model: str | None = None,
    url: str | None = None,
    timeout: float | None = None,
) -> str:
    """Send one prompt to the local Ollama instance and return the response."""
    endpoint = (url or config.OLLAMA_URL).rstrip("/") + "/api/generate"
    body = json.dumps(
        {
            "model": model or config.OLLAMA_MODEL,
            "prompt": prompt,
            "system": system,
            "stream": False,
            # Low temperature: this is a summarisation task over fixed
            # evidence, where invention is the main failure mode.
            "options": {"temperature": 0.2},
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        endpoint, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(
        request, timeout=timeout or config.OLLAMA_TIMEOUT_SECONDS
    ) as response:
        payload = json.loads(response.read().decode("utf-8"))
    # A well-behaved Ollama returns a string here. Coercing rather than
    # assuming means a malformed reply becomes an empty answer - which the
    # caller already handles - instead of an AttributeError.
    return str(payload.get("response") or "").strip()


# --------------------------------------------------------------------------
# Deterministic fallback
# --------------------------------------------------------------------------


def deterministic_investigation(package: dict) -> str:
    """Build the same six sections from the evidence, without a model.

    This is what SignalTrail shows when no local model is available. It is
    derived entirely from stored evidence, so it is always reproducible - and
    unlike the model, it cannot assert anything the data does not contain.
    """
    alerts = package["alerts"]
    indicators = package["indicators"]
    timeline = package["timeline"]

    sections: list[str] = []

    # 1 -------------------------------------------------------------------
    sections.append(
        "## 1. Incident summary\n\n"
        f"{package['deterministic_summary']}\n\n"
        f"Severity recorded as {package['severity']}, derived from the highest "
        "alert severity and the number of distinct rules that fired."
    )

    # 2 -------------------------------------------------------------------
    observed = ["## 2. Observed evidence\n"]
    if isinstance(alerts, pd.DataFrame) and not alerts.empty:
        for row in alerts.itertuples(index=False):
            technique = (
                f" (suggests {row.technique_id} {row.technique_name}, unconfirmed)"
                if row.technique_id
                else ""
            )
            observed.append(f"- **{row.rule_id} - {row.rule_name}**{technique}")
            observed.append(f"  {row.reason}")
    else:
        observed.append("- No alerts are attached to this incident.")

    observed.append("")
    observed.append("Indicators present in the evidence:")
    for label, values in indicators.items():
        pretty = label.replace("_", " ")
        observed.append(f"- {pretty}: {', '.join(values) if values else 'none recorded'}")
    sections.append("\n".join(observed))

    # 3 -------------------------------------------------------------------
    sequence = ["## 3. Likely sequence\n"]
    if isinstance(timeline, pd.DataFrame) and not timeline.empty:
        sequence.append("Events in recorded order (E = rule evidence, C = context):\n")
        sequence.append("```")
        for row in timeline.itertuples(index=False):
            marker = "E" if row.role == "evidence" else "C"
            sequence.append(
                f"{marker}  {row.timestamp:%H:%M:%S}  {row.event_type:<15} {row.details}"
            )
        sequence.append("```")
        sequence.append(
            "\nThis is the order the records were written in. Ordering shows "
            "what followed what; it does not by itself establish that one "
            "event caused another."
        )
    else:
        sequence.append("No events are attached to this incident.")
    sections.append("\n".join(sequence))

    # 4 -------------------------------------------------------------------
    rule_count = len(set(package["rule_ids"]))
    risk = ["## 4. Risk assessment\n"]
    risk.append(
        f"{rule_count} distinct rule(s) fired on {package['host']} for account "
        f"'{package['user']}' inside a "
        f"{_window_minutes(package)} minute window."
    )
    if rule_count >= 3:
        risk.append(
            "Several independent detections covering different telemetry "
            "sources agree on the same host and account, which is harder to "
            "explain as coincidence than any one of them alone. Treat this as "
            "worth prompt review."
        )
    else:
        risk.append(
            "A single rule fired. Confirm whether the activity is expected "
            "before escalating; the benign causes listed for this rule are "
            "common."
        )
    risk.append("")
    risk.append("Benign explanations that have not been ruled out:")
    seen_causes: set[str] = set()
    for rule_id in package["rule_ids"]:
        rule = RULES.get(rule_id)
        if not rule:
            continue
        for cause in rule.false_positives:
            if cause not in seen_causes:
                seen_causes.add(cause)
                risk.append(f"- {cause} ({rule_id})")
    if not seen_causes:
        risk.append("- None recorded for the rules involved.")
    sections.append("\n".join(risk))

    # 5 -------------------------------------------------------------------
    steps = ["## 5. Recommended investigation steps\n"]
    steps.append(
        f"1. Confirm with the owner of '{package['user']}' whether the activity "
        f"on {package['host']} during this window was theirs."
    )
    step_number = 2
    if indicators["source_ips"]:
        steps.append(
            f"{step_number}. Check whether {', '.join(indicators['source_ips'])} "
            "is an expected source of logins for this account, and search for "
            "the same address against other accounts."
        )
        step_number += 1
    if indicators["processes"]:
        steps.append(
            f"{step_number}. Retrieve the full command line for "
            f"{', '.join(indicators['processes'])} from the endpoint record and "
            "decode it if it was encoded."
        )
        step_number += 1
    if indicators["domains"] or indicators["destination_ips"]:
        targets = ", ".join(indicators["domains"] + indicators["destination_ips"])
        steps.append(
            f"{step_number}. Review connection volume and duration for {targets}, "
            "and check whether any other host contacted the same destination."
        )
        step_number += 1
    if indicators["files"]:
        steps.append(
            f"{step_number}. Locate {', '.join(indicators['files'])} on the host "
            "and establish what wrote it and whether it still exists."
        )
        step_number += 1
    steps.append(
        f"{step_number}. Use the Threat Hunting view to pivot on each indicator "
        "above and look for the same pattern on other hosts and accounts."
    )
    sections.append("\n".join(steps))

    # 6 -------------------------------------------------------------------
    gaps = ["## 6. Evidence gaps\n"]
    gaps.append("This incident was assembled from the telemetry available, which is limited:")
    if not indicators["files"]:
        gaps.append("- No file activity is recorded, so nothing is known about what was written.")
    if not indicators["destination_ips"]:
        gaps.append("- No outbound connection is recorded, so no data transfer can be assessed.")
    gaps.extend(
        [
            "- Command lines are recorded as logged. An encoded command is not "
            "decoded anywhere in this dataset, so its contents are unknown.",
            "- There is no process-parent, registry, or authentication-token "
            "telemetry, so neither the origin of a process nor the reuse of a "
            "session can be established here.",
            "- Nothing in this dataset confirms whether any connection "
            "succeeded in transferring data.",
            "- Correlation grouped these alerts by host, account and timing. "
            "Activity on other hosts, or under other accounts, would not be "
            "attached to this incident automatically.",
        ]
    )
    sections.append("\n".join(gaps))

    return "\n\n".join(sections)


def _window_minutes(package: dict) -> int:
    """Incident duration in whole minutes, tolerant of missing timestamps."""
    start, end = package.get("start_time"), package.get("end_time")
    if start is None or end is None:
        return 0
    try:
        return max(int((end - start).total_seconds() // 60), 0)
    except (TypeError, AttributeError):
        return 0


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def investigate_incident(
    conn, incident_id: str, use_ai: bool = True, model: str | None = None
) -> dict:
    """Produce investigation notes for one incident.

    Returns a dict with ``mode`` ("ai" or "deterministic"), the ``text`` of
    the notes, a ``notice`` explaining which path was taken, and the evidence
    ``package`` the notes were built from - so the UI can always show the
    reader what the text was based on.
    """
    package = build_evidence_package(conn, incident_id)
    if not package:
        return {
            "mode": MODE_DETERMINISTIC,
            "text": f"No incident found with id {incident_id}.",
            "notice": "Unknown incident.",
            "package": {},
        }

    fallback = deterministic_investigation(package)

    if not use_ai:
        return {
            "mode": MODE_DETERMINISTIC,
            "text": fallback,
            "notice": "Local AI was not requested. Showing the evidence-based summary.",
            "package": package,
        }

    if not ollama_available():
        logger.info("Ollama not reachable at %s; using deterministic summary", config.OLLAMA_URL)
        return {
            "mode": MODE_DETERMINISTIC,
            "text": fallback,
            "notice": (
                f"No local model service reachable at {config.OLLAMA_URL}. "
                "Showing the deterministic evidence summary instead. This is a "
                "supported state: the AI layer is optional."
            ),
            "package": package,
        }

    try:
        generated = query_ollama(build_investigation_prompt(package), model=model)
    except Exception as exc:  # noqa: BLE001 - any failure falls back cleanly
        logger.warning("Local model request failed: %s", exc)
        return {
            "mode": MODE_DETERMINISTIC,
            "text": fallback,
            "notice": (
                f"The local model request failed ({exc}). Showing the "
                "deterministic evidence summary instead."
            ),
            "package": package,
        }

    # Blank or whitespace-only output is a failed generation, not an answer.
    generated = str(generated or "").strip()
    if not generated:
        return {
            "mode": MODE_DETERMINISTIC,
            "text": fallback,
            "notice": "The local model returned no text. Showing the deterministic summary.",
            "package": package,
        }

    return {
        "mode": MODE_AI,
        "text": generated,
        "notice": (
            f"Generated locally by {model or config.OLLAMA_MODEL} from the evidence "
            "package below. Model output can be wrong - check it against the timeline."
        ),
        "package": package,
    }
