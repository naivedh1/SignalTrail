"""Synthetic security telemetry generator.

Everything SignalTrail analyses is generated here. The data is entirely
fabricated and safe: addresses come from the RFC 5737 documentation ranges,
the "suspicious" domain uses the reserved .example TLD, and the one encoded
PowerShell command line carries a literal placeholder instead of a payload.

The generator is seeded and anchored to a fixed start date, so running it
twice produces identical files. That reproducibility is what lets the tests
assert on exact record counts.

Three kinds of records are produced:

* Background noise - the large majority. Logins, routine processes, ordinary
  DNS lookups and internal network connections.
* A small burst of failed logins for a service account, which trips the
  brute-force rule and exists to show that a firing rule is not the same
  thing as a confirmed attack.
* One multi-stage storyline on WS-001 that the detection, correlation and
  timeline layers are meant to reconstruct end to end.

Two deliberately malformed records are appended so the ingestion metrics have
something real to report.
"""

from __future__ import annotations

import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Value pools for background noise
# --------------------------------------------------------------------------

BENIGN_PROCESSES = [
    ("chrome.exe", "chrome.exe --profile-directory=Default"),
    ("outlook.exe", "outlook.exe /recycle"),
    ("code.exe", "code.exe --reuse-window"),
    ("explorer.exe", "explorer.exe"),
    ("teams.exe", "teams.exe --process-start-args"),
    ("python.exe", "python.exe scripts/report.py"),
    ("svchost.exe", "svchost.exe -k netsvcs"),
    ("backup_agent.exe", "backup_agent.exe --job nightly"),
    ("powershell.exe", "powershell.exe -File C:\\ops\\inventory.ps1"),
]

BENIGN_DOMAINS = [
    "updates.example.com",
    "mail.example.com",
    "docs.example.net",
    "packages.example.org",
    "telemetry.example.com",
    "ntp.example.net",
    "intranet.example.com",
]

BENIGN_PORTS = [80, 443, 445, 3389, 53, 8080]

BENIGN_FILE_PATHS = [
    "C:\\Users\\{user}\\Documents\\report.docx",
    "C:\\Users\\{user}\\Downloads\\dataset.csv",
    "C:\\ProgramData\\agent\\cache.tmp",
    "C:\\Users\\{user}\\Desktop\\notes.txt",
]

# --------------------------------------------------------------------------
# The demo incident storyline
# --------------------------------------------------------------------------

# A visible placeholder, not a real encoded payload. The detection rule only
# needs the -EncodedCommand switch to be present.
DEMO_ENCODED_COMMAND = (
    "powershell.exe -NoProfile -WindowStyle Hidden "
    "-EncodedCommand <DEMO_ONLY_PLACEHOLDER_NOT_A_REAL_PAYLOAD>"
)

DEMO_DROPPED_FILE = "C:\\Users\\analyst_demo\\AppData\\Local\\Temp\\demo_payload.bin"

#: Day offset (from config.DATA_START) on which the storyline happens.
STORYLINE_DAY = 3
STORYLINE_HOUR = 10


# --------------------------------------------------------------------------
# Timestamp formatting - each source writes its own format on purpose
# --------------------------------------------------------------------------


def _fmt_auth(moment: datetime) -> str:
    """ISO-8601 with a trailing Z, e.g. 2026-09-10T10:01:12Z."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_endpoint(moment: datetime) -> str:
    """Space separated, no zone marker, e.g. 2026-09-10 10:04:00."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_dns(moment: datetime) -> int:
    """Unix epoch seconds."""
    return int(moment.astimezone(timezone.utc).timestamp())


def _fmt_network(moment: datetime) -> str:
    """ISO-8601 with a numeric offset, e.g. 2026-09-10T10:06:00+00:00."""
    return moment.astimezone(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Record builders
# --------------------------------------------------------------------------


def _auth_record(moment, user, host, source_ip, action, status, method="password"):
    return {
        "timestamp": _fmt_auth(moment),
        "username": user,
        "source_ip": source_ip,
        "action": action,
        "status": status,
        "host": host,
        "auth_method": method,
    }


def _endpoint_record(moment, host, user, process, action, command_line="", file_path=None):
    record = {
        "timestamp": _fmt_endpoint(moment),
        "host": host,
        "user": user,
        "process": process,
        "command_line": command_line,
        "action": action,
    }
    if file_path is not None:
        record["file_path"] = file_path
    return record


def _dns_record(moment, host, user, query, response_code="NOERROR"):
    return {
        "timestamp": _fmt_dns(moment),
        "host": host,
        "user": user,
        "query": query,
        "action": "query",
        "response_code": response_code,
    }


def _network_record(moment, host, user, dst_ip, dst_port, action="allow", bytes_out=0):
    return {
        "timestamp": _fmt_network(moment),
        "host": host,
        "user": user,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "action": action,
        "protocol": "tcp",
        "bytes_out": bytes_out,
    }


# --------------------------------------------------------------------------
# Background noise
# --------------------------------------------------------------------------


def _internal_ip(rng: random.Random) -> str:
    return f"{config.INTERNAL_SUBNET}.{rng.randint(10, 200)}"


def _external_ip(rng: random.Random) -> str:
    return f"{rng.choice(config.EXTERNAL_RANGES)}.{rng.randint(1, 254)}"


def _business_hours_moment(rng: random.Random, day: int) -> datetime:
    """Pick a timestamp inside a working day, so activity looks human."""
    base = config.DATA_START + timedelta(days=day)
    return base + timedelta(
        hours=rng.randint(8, 18),
        minutes=rng.randint(0, 59),
        seconds=rng.randint(0, 59),
    )


def _generate_background(rng: random.Random) -> dict[str, list[dict]]:
    """Produce the routine activity that makes up most of the dataset."""
    auth: list[dict] = []
    endpoint: list[dict] = []
    dns: list[dict] = []
    network: list[dict] = []

    for day in range(config.DATA_DAYS):
        for user in config.USERS:
            host = config.HOSTS[config.USERS.index(user) % len(config.HOSTS)]

            # A morning login and an evening logout per user per day.
            login_at = config.DATA_START + timedelta(
                days=day, hours=8, minutes=rng.randint(0, 50)
            )
            auth.append(
                _auth_record(
                    login_at, user, host, _internal_ip(rng), "login", "success"
                )
            )
            auth.append(
                _auth_record(
                    login_at + timedelta(hours=rng.randint(7, 9)),
                    user,
                    host,
                    _internal_ip(rng),
                    "logout",
                    "success",
                )
            )

            # Extra sessions during the day: workstation unlocks, remote
            # access to a server, and so on.
            for _ in range(rng.randint(2, 5)):
                auth.append(
                    _auth_record(
                        _business_hours_moment(rng, day),
                        user,
                        rng.choice(config.HOSTS),
                        _internal_ip(rng),
                        "login",
                        "success",
                        method=rng.choice(["password", "mfa", "sso"]),
                    )
                )

            # One or two mistyped passwords. Kept well under the detection
            # threshold and spread out in time so they stay benign.
            for _ in range(rng.randint(0, 2)):
                auth.append(
                    _auth_record(
                        _business_hours_moment(rng, day),
                        user,
                        host,
                        _internal_ip(rng),
                        "login",
                        "failure",
                    )
                )

            # Routine process activity.
            for _ in range(rng.randint(8, 14)):
                process, command_line = rng.choice(BENIGN_PROCESSES)
                endpoint.append(
                    _endpoint_record(
                        _business_hours_moment(rng, day),
                        host,
                        user,
                        process,
                        "process_start",
                        command_line,
                    )
                )

            # Ordinary file writes.
            for _ in range(rng.randint(1, 3)):
                endpoint.append(
                    _endpoint_record(
                        _business_hours_moment(rng, day),
                        host,
                        user,
                        "explorer.exe",
                        "file_create",
                        "",
                        rng.choice(BENIGN_FILE_PATHS).format(user=user),
                    )
                )

            # Name resolution for everyday services.
            for _ in range(rng.randint(8, 14)):
                dns.append(
                    _dns_record(
                        _business_hours_moment(rng, day),
                        host,
                        user,
                        rng.choice(BENIGN_DOMAINS),
                    )
                )

            # Outbound and internal connections.
            for _ in range(rng.randint(6, 12)):
                network.append(
                    _network_record(
                        _business_hours_moment(rng, day),
                        host,
                        user,
                        _external_ip(rng) if rng.random() < 0.4 else _internal_ip(rng),
                        rng.choice(BENIGN_PORTS),
                        "allow",
                        rng.randint(200, 60000),
                    )
                )

    return {
        "authentication": auth,
        "endpoint": endpoint,
        "dns": dns,
        "network": network,
    }


# --------------------------------------------------------------------------
# Secondary cluster: a service account that trips the brute-force rule
# --------------------------------------------------------------------------


def _generate_service_account_lockout(buckets: dict[str, list[dict]]) -> None:
    """Six failed logins from a scheduled job using a stale password.

    This fires RULE-001 without being an attack. It exists so the dashboard
    shows what an alert that needs triage - rather than response - looks like.
    """
    start = config.DATA_START + timedelta(days=1, hours=2, minutes=15)
    source_ip = f"{config.INTERNAL_SUBNET}.240"
    for index in range(6):
        buckets["authentication"].append(
            _auth_record(
                start + timedelta(seconds=45 * index),
                "svc_backup",
                "SRV-002",
                source_ip,
                "login",
                "failure",
                method="service_token",
            )
        )


# --------------------------------------------------------------------------
# The multi-stage storyline
# --------------------------------------------------------------------------


def _generate_storyline(buckets: dict[str, list[dict]]) -> None:
    """Seven linked events that a working investigation should recover.

    failed logins -> successful login -> encoded PowerShell -> suspicious DNS
    -> outbound connection -> file creation
    """
    host = config.DEMO_INCIDENT_HOST
    user = config.DEMO_INCIDENT_USER
    src_ip = config.DEMO_ATTACK_SOURCE_IP
    dst_ip = sorted(config.SUSPICIOUS_DESTINATIONS)[0]
    domain = sorted(config.SUSPICIOUS_DOMAINS)[0]

    base = config.DATA_START + timedelta(days=STORYLINE_DAY, hours=STORYLINE_HOUR)

    # Stage 1: repeated authentication failures from one external address.
    failure_offsets = [72, 82, 91, 104, 118, 129]
    for offset in failure_offsets:
        buckets["authentication"].append(
            _auth_record(
                base + timedelta(seconds=offset),
                user,
                host,
                src_ip,
                "login",
                "failure",
            )
        )

    # Stage 2: the attempt that succeeds.
    buckets["authentication"].append(
        _auth_record(
            base + timedelta(seconds=151), user, host, src_ip, "login", "success"
        )
    )

    # Stage 3 and 4: PowerShell started with an encoded command.
    buckets["endpoint"].append(
        _endpoint_record(
            base + timedelta(seconds=240),
            host,
            user,
            "powershell.exe",
            "process_start",
            DEMO_ENCODED_COMMAND,
        )
    )

    # Stage 5: name resolution for the demo suspicious domain.
    buckets["dns"].append(
        _dns_record(base + timedelta(seconds=300), host, user, domain)
    )

    # Stage 6: outbound connection to the demo destination.
    buckets["network"].append(
        _network_record(
            base + timedelta(seconds=360), host, user, dst_ip, 443, "allow", 184320
        )
    )

    # Stage 7: a file written by the same process shortly afterwards.
    buckets["endpoint"].append(
        _endpoint_record(
            base + timedelta(seconds=420),
            host,
            user,
            "powershell.exe",
            "file_create",
            DEMO_ENCODED_COMMAND,
            DEMO_DROPPED_FILE,
        )
    )


# --------------------------------------------------------------------------
# Deliberately broken records
# --------------------------------------------------------------------------


def _generate_malformed(buckets: dict[str, list[dict]]) -> None:
    """Append two unusable records so validation has something to reject.

    Real log pipelines always carry some broken input. Generating it on
    purpose keeps the ingestion metrics honest instead of always reporting a
    perfect run.
    """
    # Missing the required host field.
    buckets["authentication"].append(
        {
            "timestamp": _fmt_auth(config.DATA_START + timedelta(days=2, hours=11)),
            "username": "m.chen",
            "source_ip": "10.10.0.77",
            "action": "login",
            "status": "success",
        }
    )
    # Timestamp that cannot be parsed as epoch seconds.
    buckets["dns"].append(
        {
            "timestamp": "not-a-timestamp",
            "host": "WS-003",
            "user": "k.osei",
            "query": "docs.example.net",
            "action": "query",
            "response_code": "NOERROR",
        }
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def build_dataset(include_malformed: bool = True) -> dict[str, list[dict]]:
    """Build every raw source in memory, sorted by time within each source."""
    rng = random.Random(config.GENERATOR_SEED)

    buckets = _generate_background(rng)
    _generate_service_account_lockout(buckets)
    _generate_storyline(buckets)
    if include_malformed:
        _generate_malformed(buckets)

    # Sort by the raw timestamp where that is safely possible. The malformed
    # records are left at the end rather than crashing the sort.
    for source_type, records in buckets.items():
        sortable = [r for r in records if _sort_key(r, source_type) is not None]
        unsortable = [r for r in records if _sort_key(r, source_type) is None]
        sortable.sort(key=lambda r: _sort_key(r, source_type))
        buckets[source_type] = sortable + unsortable

    return buckets


def _sort_key(record: dict, source_type: str):
    """Best-effort sort key; returns None for records that cannot be ordered."""
    value = record.get("timestamp")
    if source_type == "dns":
        return value if isinstance(value, (int, float)) else None
    return value if isinstance(value, str) else None


def write_dataset(buckets: dict[str, list[dict]], raw_dir: Path | None = None) -> dict[str, int]:
    """Write each source to its JSON file and return the per-source counts."""
    config.ensure_directories()
    counts: dict[str, int] = {}
    for source_type, records in buckets.items():
        path = (raw_dir / f"{source_type}.json") if raw_dir else config.RAW_SOURCES[source_type]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(records, indent=2), encoding="utf-8")
        counts[source_type] = len(records)
        logger.info("Wrote %s records to %s", len(records), path.name)
    return counts


def generate(force: bool = False) -> dict[str, int]:
    """Generate the raw dataset unless it already exists on disk."""
    existing = all(path.exists() for path in config.RAW_SOURCES.values())
    if existing and not force:
        counts = {}
        for source_type, path in config.RAW_SOURCES.items():
            counts[source_type] = len(json.loads(path.read_text(encoding="utf-8")))
        logger.info("Raw telemetry already present (%s records)", sum(counts.values()))
        return counts

    return write_dataset(build_dataset())


if __name__ == "__main__":  # pragma: no cover - manual entry point
    config.configure_logging()
    totals = generate(force=True)
    print("Generated:", totals, "total:", sum(totals.values()))
