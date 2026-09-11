"""Central configuration for SignalTrail.

Every path used by the project is derived from the repository root at import
time, so the project can be cloned to any directory on any operating system
without editing code.  Detection thresholds live here too, which keeps tuning
decisions in one reviewable place instead of scattered through the rules.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

# config.py lives in <root>/src/, so the root is two levels up.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

# The DuckDB file may be relocated for tests via an environment variable.
DB_PATH = Path(os.environ.get("SIGNALTRAIL_DB", PROCESSED_DIR / "signaltrail.duckdb"))

# Raw telemetry file for each source type.
RAW_SOURCES: dict[str, Path] = {
    "authentication": RAW_DIR / "authentication.json",
    "endpoint": RAW_DIR / "endpoint.json",
    "dns": RAW_DIR / "dns.json",
    "network": RAW_DIR / "network.json",
}


def ensure_directories() -> None:
    """Create the data directories the pipeline writes into."""
    for directory in (RAW_DIR, PROCESSED_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# Synthetic data generation
# --------------------------------------------------------------------------

# A fixed anchor and seed make every generated dataset byte-for-byte
# reproducible, which is what lets the tests assert on exact counts.
GENERATOR_SEED = 20260911
DATA_START = datetime(2026, 9, 7, 0, 0, 0, tzinfo=timezone.utc)
DATA_DAYS = 5

HOSTS = ["WS-001", "WS-002", "WS-003", "WS-004", "SRV-001", "SRV-002"]
USERS = ["analyst_demo", "j.rivera", "m.chen", "k.osei", "svc_backup", "admin_demo"]

# Documentation-only address space (RFC 5737) plus RFC 1918 internal ranges.
INTERNAL_SUBNET = "10.10.0"
EXTERNAL_RANGES = ["192.0.2", "198.51.100", "203.0.113"]

# --------------------------------------------------------------------------
# Demo indicators used by the synthetic incident storyline
# --------------------------------------------------------------------------

DEMO_INCIDENT_HOST = "WS-001"
DEMO_INCIDENT_USER = "analyst_demo"
DEMO_ATTACK_SOURCE_IP = "198.51.100.23"

# Watchlists the detection rules match against.  In a real deployment these
# would come from a threat-intelligence feed; here they are static demo values.
SUSPICIOUS_DOMAINS = {"demo-suspicious.example"}
SUSPICIOUS_DESTINATIONS = {"203.0.113.50"}

# Switches that indicate a PowerShell encoded-command invocation. PowerShell
# accepts any unambiguous prefix of a switch name, so "-e", "-enc" and
# "-EncodedCommand" all select the same one; the detection matches prefixes as
# whole command-line tokens rather than as substrings, because "-e " appearing
# anywhere in a line is not the same thing as the switch being used.
ENCODED_COMMAND_SWITCHES = ("encodedcommand",)

# Switches after which PowerShell stops reading its own parameters: everything
# that follows belongs to the script or to the command text.
POWERSHELL_TERMINATING_SWITCHES = ("file", "command")

# Process names the PowerShell rule applies to, compared against the file name
# exactly. A renamed copy of powershell.exe would therefore not match - see
# RULE-002's documented limitations.
POWERSHELL_PROCESS_NAMES = ("powershell.exe", "pwsh.exe")

# --------------------------------------------------------------------------
# Detection thresholds (all tunable)
# --------------------------------------------------------------------------

# RULE-001: repeated authentication failures.
AUTH_FAILURE_THRESHOLD = 5
AUTH_FAILURE_WINDOW_MINUTES = 10

# RULE-005: file activity shortly after suspicious process execution.
POST_EXECUTION_WINDOW_MINUTES = 10

# Correlation: alerts on the same host/user closer together than this are
# treated as belonging to the same incident.
CORRELATION_GAP_MINUTES = 30
# Context events pulled in around an incident's alert evidence.
INCIDENT_CONTEXT_MINUTES = 15
# Number of distinct rules that must fire before an incident is escalated.
INCIDENT_ESCALATION_RULE_COUNT = 4

# --------------------------------------------------------------------------
# Anomaly detection (optional)
# --------------------------------------------------------------------------

ANOMALY_BUCKET_MINUTES = 5
ANOMALY_CONTAMINATION = 0.05
ANOMALY_RANDOM_STATE = 42

# --------------------------------------------------------------------------
# Local AI investigator (optional)
# --------------------------------------------------------------------------

OLLAMA_URL = os.environ.get("SIGNALTRAIL_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("SIGNALTRAIL_OLLAMA_MODEL", "llama3.1")
OLLAMA_TIMEOUT_SECONDS = float(os.environ.get("SIGNALTRAIL_OLLAMA_TIMEOUT", "120"))
OLLAMA_PROBE_TIMEOUT_SECONDS = 2.0

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-22s | %(message)s"
LOG_DATE_FORMAT = "%H:%M:%S"


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logging once, for command-line entry points."""
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
