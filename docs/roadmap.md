# Roadmap

## V1 - working local security analytics (current)

The complete path from raw telemetry to an investigable incident, running
locally on synthetic data.

- [x] Four telemetry sources with deliberately different raw schemas
- [x] Validation that counts and explains every rejected record
- [x] Normalization onto one common event model, original record preserved
- [x] DuckDB store with three tables, safe to re-run
- [x] Five deterministic detection rules, each carrying its evidence
- [x] Detection metadata including known benign causes and MITRE mapping
- [x] Correlation into incidents, with context events attached
- [x] Chronological incident timelines separating evidence from context
- [x] Threat hunting by indicator and by field
- [x] Streamlit dashboard: overview, detection, investigation, hunting, AI, anomalies
- [x] Optional Isolation Forest as a supporting signal
- [x] Optional local AI investigator with a deterministic fallback
- [x] 164 tests covering ingestion, normalization, detection and correlation

### Known limits of V1

- Batch processing over the whole dataset, not streaming.
- Everything is held in memory during a run.
- Correlation is scoped to one host and one account.
- Watchlists are static configuration, not a feed.
- Synthetic data only. The rules have never seen a real environment's noise.

## V2 - better detection

The rules cover single-account credential attacks and a few known-bad
indicators. The obvious gaps are patterns that need a different shape of
query.

**Detection**

- Password spraying: one password against many accounts. RULE-001 groups by
  account, so this is invisible to it today.
- Beaconing: regular low-volume connections to one destination. Interval
  analysis rather than a watchlist - it would catch destinations no list knows
  about yet.
- Impossible travel: one account authenticating from incompatible locations.
  Needs geolocation enrichment.
- Process lineage: add a parent-process field to the endpoint source and the
  common event model. "PowerShell launched by a browser" is a much stronger
  signal than "PowerShell ran".
- Rare-process baselining per host, rather than the dataset-wide frequency cut
  the anomaly module uses now.

**Rule engine**

- Move rule definitions into declarative YAML so a rule can be added without
  writing Python.
- Per-rule allowlists - by account, host or parent process. This is the single
  most useful tuning mechanism missing today, and the reason RULE-001 and
  RULE-002 would be noisy in a real environment.
- Rule-level enable/disable and severity override in configuration.

**Machine learning**

- Per-host baselines instead of one global model, so a quiet server is not
  compared against a busy workstation.
- Time-of-day and day-of-week features. Activity at 03:00 differs from the
  same activity at 14:00, and the current features cannot express that.
- Feature attribution, so a high score comes with which features drove it
  rather than a note about what is generally unusual.
- Honest evaluation: labelled synthetic data, and precision/recall figures for
  the model against the rules. Today's claim that anomaly scoring is a
  "supporting signal" is a design decision, not a measured one.

**Storage**

- Push detection predicates into SQL so rules run against data larger than
  memory.
- Incremental ingestion with a watermark, so a run only processes new records.

## V3 - local AI investigation and richer workflows

**AI layer**

- Retrieval over historical incidents, so the model can be asked whether
  anything similar has been seen before.
- Structured output (JSON) rather than prose, so generated assessments can be
  stored, compared and evaluated.
- A regression suite for the prompt: fixed evidence packages with known
  correct answers, checked for invented indicators. Grounding is currently
  enforced by prompt instructions and by showing the evidence next to the
  output - neither is a guarantee.
- Let an analyst ask follow-up questions against the incident's evidence,
  still with no ability to act.

**Workflow**

- Incident status beyond `open`: triaged, confirmed, closed as benign, with a
  reason. Closing as benign is the most valuable signal a tool can capture,
  and there is nowhere to record it today.
- Analyst notes attached to incidents and alerts.
- Alert suppression with an expiry, so tuning is reversible.
- Case export - timeline, evidence and notes as a single document.

**Investigation**

- Cross-host correlation for lateral movement, which means relaxing the
  `(host, user)` partition without merging everything into one incident.
- An entity view: everything known about one host, account or address in one
  place.
- A saved-hunt library, so a useful query is written once.

**Ingestion**

- A real log format. Windows Security event log or Sysmon would exercise the
  normalizer against a schema nobody designed for convenience.
- A file-watching ingest mode for near-real-time processing.

## Explicitly out of scope

Some things are missing on purpose, not by omission.

- **Automated response.** No isolating hosts, disabling accounts or killing
  processes. The AI layer especially has no ability to act - it returns text.
- **Cloud or multi-tenant deployment.** Local-first is the point. Security
  telemetry not leaving the machine is a feature.
- **Live capture.** SignalTrail analyses telemetry; it does not collect it.
- **Offensive tooling.** No payload generation, no exploitation, no evasion
  testing. The project is defensive analytics.
