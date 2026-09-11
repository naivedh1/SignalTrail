# Architecture

## The shape of the problem

Security telemetry arrives from systems that were never designed to agree with
each other. An authentication log calls the account `username`; an endpoint
agent calls it `user`. One source writes ISO-8601, another writes Unix epoch
seconds, a third writes a local timestamp with no zone at all. None of them
know about the others.

An analyst investigating an incident has to reconcile all of that in their
head, under time pressure, while also doing the actual investigation. Most of
what SignalTrail does is move that reconciliation work earlier - out of the
investigation and into a pipeline that runs before anyone is looking.

## The pipeline

```
   authentication.json   endpoint.json   dns.json   network.json
            |                  |            |            |
            +------------------+------------+------------+
                               |
                        ingest.py  ........  validate every record,
                               |             count what is rejected
                        normalize.py  .....  one common event model,
                               |             original record preserved
                        database.py  ......  DuckDB: security_events
                               |
                        detections.py  ....  five deterministic rules
                               |             -> alerts (with evidence)
                        correlate.py  .....  group by host/user/time
                               |             -> incidents
                               |
         +---------------------+---------------------+
         |                     |                     |
   investigate.py        analytics.py          anomaly.py
   (queries, timelines)  (chart data)          (optional, supporting)
         |                     |
         +----------+----------+
                    |
              dashboard.py  ......  Streamlit, six tabs
                    |
            ai_investigator.py  ..  optional local model,
                                    deterministic fallback
```

Each stage has one job and hands a well-defined structure to the next. A stage
can be replaced without touching its neighbours: swapping DuckDB for another
store means rewriting `database.py` and nothing else.

## Why each component exists

### `config.py` - one place for every decision

Paths are derived from the repository root with `pathlib`, so the project runs
from any directory on any OS with no edits. Detection thresholds live here
too. When someone asks "why does this fire after five failures and not ten?",
the answer should be one file, not a search through the rules.

### `schemas.py` - the contracts

Three contracts, deliberately together:

- **Raw source schemas.** What each source must provide to be usable.
- **The common event model.** The 17 columns everything is mapped onto.
- **Vocabularies.** Severity levels, event types, and the MITRE mapping.

Keeping the column order in one tuple that both pandas and DuckDB read from
means the two cannot silently drift apart.

### `ingest.py` - accounting for every record

Validation is shallow on purpose: it checks what would break normalization,
not whether values are plausible. A record that fails is counted and sampled
with a reason, never silently dropped. The metrics (`raw`, `valid`, `invalid`,
`duplicate`, `normalized`, duration) are printed by the pipeline because a
number that nobody looks at is a number nobody notices going wrong.

### `normalize.py` - the common event model

Four things happen per record:

1. **Field mapping.** `username`/`user` -> `user`, `query` -> `domain`, and so on.
2. **Timestamp conversion.** Four input formats, one UTC output. Sources
   without zone information are read as UTC, which is a stated assumption
   rather than an accident of the local machine's settings.
3. **Standardization.** Empty, missing, `null`, `-` and `N/A` all collapse to
   one empty marker, so a query never has to test six ways of saying nothing.
   Event types and actions come from a fixed vocabulary.
4. **Identity.** `event_id` is `sha256(source_type + canonical_json(record))`,
   truncated. Two consequences follow: identical records deduplicate for free,
   and re-running the pipeline produces the same identifiers.

The complete original record is kept in `raw_message`. Every normalized field
can be checked against its source, which matters because normalization is
lossy by design and evidence should not be.

### `database.py` - the local store

DuckDB runs in-process against a single file. No server, no credentials, no
port. For a tool that analyses security telemetry, data that never leaves the
machine is a feature, not a limitation.

All writes live here. Loads replace a table's contents inside a transaction
rather than appending, which is what makes repeated pipeline runs safe:
combined with content-derived identifiers, a second run over unchanged input
writes the same rows instead of a second copy of every finding.

The three tables mirror the three stages of the workflow: `security_events`
(what happened), `alerts` (what was flagged), `incidents` (what to
investigate).

### `detections.py` - deterministic rules first

Rules come before machine learning here, deliberately. A rule can be read,
argued with, tuned, and unit-tested. It produces the same answer every time,
and it can say *why* it fired in a sentence a person can check.

Two conventions hold across every rule:

- Every alert carries `evidence_event_ids` - the exact records behind it.
- Every alert describes an observation, not a conclusion. Rule metadata
  includes known benign causes, stored with the rule so it is reviewable
  without reading code.

### `correlate.py` - alerts into incidents

Individual alerts are a poor unit of work. Six failed logins, an encoded
command, a lookup and a connection are four queue items when viewed
separately and one incident when viewed together.

Grouping is conservative and explainable: partition by `(host, user)`, cluster
by time gap, then attach context events - records nearby that share an
indicator with the evidence or that are authentications. Context is what makes
a timeline readable; the successful login in the demo incident is context, not
evidence, and the distinction survives all the way into the UI.

### `investigate.py` - the shared query layer

Every pivot an analyst makes is implemented once here. The dashboard and the
AI investigator both call it, so they cannot disagree about what the evidence
says. Every query is parameterised; search terms are never formatted into SQL.

### `anomaly.py` - a supporting signal, clearly labelled

An Isolation Forest over per-host activity windows. It answers a different
question from a rule - "is this unlike the rest of the data?" rather than "did
this specific thing happen?" - and it cannot explain itself the way a rule
can.

So it is wired in as a ranking aid, not a detector. It raises no alerts and
creates no incidents. On this dataset it ranks the incident's 10:00 window in
roughly the top 2% of about 1,050 windows, which is genuinely useful, while
the single highest-scoring window is an unremarkable one that happens to be
quiet. That is the honest behaviour of the technique, and the module says so.

### `ai_investigator.py` - optional, local, grounded

The model is a writing assistant for an investigation, not a decision maker.
It receives a fixed evidence package and returns text. It has no tools, no
database access, and no ability to act.

If Ollama is not running, a deterministic summary is built from the same
evidence package. That fallback is written to be genuinely useful on its own -
it is the primary path for anyone who never installs a model.

### `dashboard.py` - the analyst's view

Six tabs, ordered by the questions an analyst actually asks: what happened
(Overview), why was it flagged (Detection), what is the story (Investigation),
what else is out there (Threat Hunting), help me write it up (AI), and where
should I look when nothing fired (Anomalies).

## Design decisions worth defending

**Content-derived identifiers rather than sequence numbers.** The alternative
is a pipeline that either duplicates findings on every run or needs
reconciliation logic to avoid it. Hashing content makes idempotency a property
of the data rather than a procedure to get right.

**Timestamps stored as naive UTC.** Everything converts to UTC at
normalization and drops the marker. Mixed-offset comparisons inside pandas and
DuckDB are a recurring source of subtle bugs; "everything is UTC, stated
once" avoids the whole category.

**`raw_message` on every event.** It costs storage. It buys the ability to
answer "is that really what the log said?" without leaving the tool, and it is
what makes the normalized model safe to change later.

**One extra column beyond the specified event model.** `file_path` is stored
as its own column rather than being packed into `command_line`. Overloading a
field to mean two things is exactly the kind of shortcut that makes a schema
untrustworthy a year later.

**Correlation groups by host *and* account.** A looser rule would merge
unrelated activity and produce one enormous unusable incident. Being too
conservative produces several small incidents an analyst can link by hand,
which is the better failure.

**Severity escalation has to be earned.** An incident's severity is its worst
alert. It escalates one step to CRITICAL only when four or more distinct rules
fire on the same host and account - independent detections agreeing is harder
to dismiss than one noisy rule repeating itself. No single rule can produce a
CRITICAL alone.

## Limits of this design

- Detection runs in batch over the whole dataset, not on a stream. Rewriting
  the rules for incremental evaluation would be a substantial change.
- Everything is in memory during a run. The dataset is small; a real one would
  need the rules pushed into SQL.
- Correlation uses timing and shared identity only. It has no notion of
  process lineage, so it cannot link activity across accounts or machines.
- The watchlists are static configuration, not a threat-intelligence feed.
