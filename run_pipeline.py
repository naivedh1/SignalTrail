"""SignalTrail pipeline entry point.

Runs the whole chain in order:

    generate/verify telemetry -> validate -> normalize -> load DuckDB
      -> detect -> correlate -> summarize

The pipeline is safe to run repeatedly. Event, alert and incident identifiers
are derived from content, and each load replaces a table's contents rather
than appending to it, so a second run over unchanged input produces exactly
the same database rather than a second copy of every finding.

Usage:

    python run_pipeline.py                 # run the pipeline
    python run_pipeline.py --regenerate    # rebuild the synthetic telemetry first
    python run_pipeline.py --anomaly       # also score behavioural anomalies
    python run_pipeline.py --quiet         # warnings and errors only
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from src import analytics
from src import config
from src import correlate
from src import database
from src import detections
from src import generate_data
from src import ingest

logger = logging.getLogger("signaltrail.pipeline")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_pipeline.py",
        description="Run the SignalTrail ingestion, detection and correlation pipeline.",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="rebuild the synthetic telemetry before running, overwriting data/raw",
    )
    parser.add_argument(
        "--anomaly",
        action="store_true",
        help="also run the optional behavioural anomaly scoring",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="path to the DuckDB file (defaults to data/processed/signaltrail.duckdb)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="log warnings and errors only"
    )
    return parser.parse_args(argv)


def _rule(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config.configure_logging(logging.WARNING if args.quiet else logging.INFO)
    config.ensure_directories()

    started = time.perf_counter()

    # 1. Telemetry ---------------------------------------------------------
    logger.info("Step 1/6: verifying synthetic telemetry")
    raw_counts = generate_data.generate(force=args.regenerate)

    # 2 and 3. Validation and normalization --------------------------------
    logger.info("Step 2/6: validating and normalizing raw records")
    events, metrics = ingest.run_ingestion()

    if events.empty:
        logger.error("No events survived ingestion; stopping.")
        return 1

    # 4. Storage -----------------------------------------------------------
    logger.info("Step 3/6: loading the local security data store")
    db_path = args.db or config.DB_PATH

    with database.connection(db_path) as conn:
        database.initialize(conn)
        database.load_events(conn, events)

        # 5. Detection -----------------------------------------------------
        logger.info("Step 4/6: running detection rules")
        alerts = detections.run_detections(events)
        database.load_alerts(conn, alerts)

        # 6. Correlation ---------------------------------------------------
        logger.info("Step 5/6: correlating alerts into incidents")
        incidents = correlate.correlate_alerts(alerts, events)
        database.load_incidents(conn, incidents)

        counts = database.table_counts(conn)

    # Optional anomaly pass -------------------------------------------------
    anomalies = None
    if args.anomaly:
        logger.info("Running optional anomaly scoring")
        from src import anomaly as anomaly_module

        anomalies = anomaly_module.run_anomaly_detection(events)

    # 7. Summary -----------------------------------------------------------
    logger.info("Step 6/6: writing summary")
    elapsed = time.perf_counter() - started

    print(_rule("SignalTrail pipeline"))
    print(f"Database: {db_path}")
    print(f"Raw telemetry files: {sum(raw_counts.values())} records across "
          f"{len(raw_counts)} sources")

    print(_rule("Ingestion"))
    print(metrics.render())

    print(_rule("Storage"))
    for table, count in counts.items():
        print(f"{table:<18} {count}")

    print(_rule("Detection"))
    if alerts.empty:
        print("No alerts raised.")
    else:
        by_rule = analytics.alerts_by_rule(alerts)
        for row in by_rule.itertuples(index=False):
            print(f"{row.rule_id}  {row.rule_name:<48} {row.alerts}")
        print()
        for severity, count in analytics.severity_counts(alerts).items():
            if count:
                print(f"{severity:<10} {count}")

    print(_rule("Incidents"))
    if incidents.empty:
        print("No incidents correlated.")
    else:
        for row in incidents.itertuples(index=False):
            print(f"{row.incident_id}  [{row.severity}]  {row.title}")
            print(
                f"    {row.start_time} to {row.end_time} UTC | "
                f"{row.evidence_count} event(s) | rules: {row.rule_ids}"
            )

    if anomalies is not None and not anomalies.empty:
        print(_rule("Behavioural anomalies (supporting signal only)"))
        print("These do not create alerts and are not evidence of an attack.")
        top = anomalies.head(5)
        for row in top.itertuples(index=False):
            print(
                f"  {row.bucket}  {row.host:<8} risk_signal={row.risk_signal:>5}  "
                f"failed_logins={int(row.failed_logins)} "
                f"dns={int(row.dns_requests)} net={int(row.outbound_connections)}"
            )

    print(_rule("Result"))
    print(f"Pipeline completed in {elapsed:.2f} seconds.")
    print("Next: python -m streamlit run src/dashboard.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
