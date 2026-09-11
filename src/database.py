"""DuckDB storage layer.

DuckDB was chosen because it is an analytical engine that runs in-process
against a single file: no server, no credentials, no network exposure. For a
local-first security tool that matters twice over, because the data being
analysed is exactly the kind that should not leave the machine.

Every SQL statement in the project lives either here or in ``investigate.py``.
Keeping writes in one module is what makes the "run the pipeline twice"
guarantee checkable: loads replace table contents inside a transaction, and
because every identifier is derived from content, a second run writes the same
rows rather than a second copy of them.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path

import duckdb
import pandas as pd

from . import config
from . import schemas

logger = logging.getLogger(__name__)

EVENTS_TABLE = "security_events"
ALERTS_TABLE = "alerts"
INCIDENTS_TABLE = "incidents"

# Table definitions. Column order matches the dataclass-style column tuples in
# schemas.py so the two cannot silently drift apart.
SCHEMA_SQL = {
    EVENTS_TABLE: """
        CREATE TABLE IF NOT EXISTS security_events (
            event_id      VARCHAR PRIMARY KEY,
            timestamp     TIMESTAMP,
            host          VARCHAR,
            "user"        VARCHAR,
            source_type   VARCHAR,
            event_type    VARCHAR,
            action        VARCHAR,
            src_ip        VARCHAR,
            dst_ip        VARCHAR,
            dst_port      BIGINT,
            domain        VARCHAR,
            process_name  VARCHAR,
            command_line  VARCHAR,
            file_path     VARCHAR,
            status        VARCHAR,
            severity      VARCHAR,
            raw_message   VARCHAR
        )
    """,
    ALERTS_TABLE: """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id            VARCHAR PRIMARY KEY,
            created_at          TIMESTAMP,
            rule_id             VARCHAR,
            rule_name           VARCHAR,
            host                VARCHAR,
            "user"              VARCHAR,
            event_id            VARCHAR,
            evidence_event_ids  VARCHAR,
            evidence_count      BIGINT,
            severity            VARCHAR,
            reason              VARCHAR,
            status              VARCHAR,
            technique_id        VARCHAR,
            technique_name      VARCHAR
        )
    """,
    INCIDENTS_TABLE: """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id         VARCHAR PRIMARY KEY,
            created_at          TIMESTAMP,
            host                VARCHAR,
            "user"              VARCHAR,
            severity            VARCHAR,
            title               VARCHAR,
            status              VARCHAR,
            summary             VARCHAR,
            start_time          TIMESTAMP,
            end_time            TIMESTAMP,
            evidence_count      BIGINT,
            alert_ids           VARCHAR,
            rule_ids            VARCHAR,
            evidence_event_ids  VARCHAR
        )
    """,
}

TABLE_COLUMNS = {
    EVENTS_TABLE: schemas.NORMALIZED_COLUMNS,
    ALERTS_TABLE: schemas.ALERT_COLUMNS,
    INCIDENTS_TABLE: schemas.INCIDENT_COLUMNS,
}

#: Columns named "user" collide with the SQL keyword and need quoting.
_RESERVED = {"user"}


def _quote(column: str) -> str:
    return f'"{column}"' if column in _RESERVED else column


def connect(db_path: Path | str | None = None, read_only: bool = False):
    """Open a DuckDB connection, creating the parent directory if needed."""
    path = Path(db_path) if db_path is not None else config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return duckdb.connect(str(path), read_only=read_only)


@contextmanager
def connection(db_path: Path | str | None = None, read_only: bool = False):
    """Context-managed connection, so files are never left open on error."""
    conn = connect(db_path, read_only=read_only)
    try:
        yield conn
    finally:
        conn.close()


def initialize(conn) -> None:
    """Create any missing tables. Safe to call on every run."""
    for statement in SCHEMA_SQL.values():
        conn.execute(statement)
    logger.debug("Database schema ready")


def replace_table(conn, table: str, frame: pd.DataFrame) -> int:
    """Replace a table's contents with the rows of ``frame``.

    Replacement rather than append is deliberate. The pipeline recomputes
    alerts and incidents from scratch on every run, so appending would produce
    duplicate findings with each execution.
    """
    if table not in TABLE_COLUMNS:
        raise ValueError(f"unknown table: {table}")

    columns = TABLE_COLUMNS[table]
    payload = frame.reindex(columns=list(columns))
    column_sql = ", ".join(_quote(c) for c in columns)

    conn.execute("BEGIN TRANSACTION")
    try:
        conn.execute(f"DELETE FROM {table}")
        if not payload.empty:
            conn.register("_incoming", payload)
            conn.execute(
                f"INSERT INTO {table} ({column_sql}) SELECT {column_sql} FROM _incoming"
            )
            conn.unregister("_incoming")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    logger.info("Loaded %s rows into %s", len(payload), table)
    return len(payload)


def load_events(conn, frame: pd.DataFrame) -> int:
    return replace_table(conn, EVENTS_TABLE, frame)


def load_alerts(conn, frame: pd.DataFrame) -> int:
    return replace_table(conn, ALERTS_TABLE, frame)


def load_incidents(conn, frame: pd.DataFrame) -> int:
    return replace_table(conn, INCIDENTS_TABLE, frame)


def fetch_df(conn, sql: str, params: list | None = None) -> pd.DataFrame:
    """Run a query and return the result as a DataFrame."""
    return conn.execute(sql, params or []).fetch_df()


def read_table(conn, table: str) -> pd.DataFrame:
    """Read a whole table, ordered so results are stable between runs."""
    order = {
        EVENTS_TABLE: "timestamp, event_id",
        ALERTS_TABLE: "created_at, alert_id",
        INCIDENTS_TABLE: "start_time, incident_id",
    }[table]
    return fetch_df(conn, f"SELECT * FROM {table} ORDER BY {order}")


def table_counts(conn) -> dict[str, int]:
    """Row count per table, used by the pipeline summary and the dashboard."""
    counts = {}
    for table in TABLE_COLUMNS:
        counts[table] = int(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
    return counts
