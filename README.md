# SignalTrail

**Security telemetry and investigation platform — local-first, synthetic data.**

SignalTrail collects heterogeneous security telemetry, normalizes it into a
common event model, stores it locally in DuckDB, detects suspicious activity
with deterministic rules, correlates related findings into incidents,
reconstructs investigation timelines, supports threat hunting, and includes an
optional local AI investigation layer.

It runs entirely on one machine. No cloud services, no paid APIs, no external
database, no external LLM API.

```
telemetry -> ingest -> validate -> normalize -> DuckDB -> detect -> alerts
          -> correlate -> incidents -> timeline -> hunt -> dashboard
                                                        -> optional local AI
```

---

## The problem

Security telemetry arrives from systems that were never designed to agree with
each other. An authentication log calls the account `username`; an endpoint
agent calls it `user`. One source writes ISO-8601, another Unix epoch seconds,
a third a local timestamp with no zone at all.

An analyst has to reconcile all of that in their head, under time pressure,
while also doing the investigation. Then they face a second problem: alerts
arrive one at a time. Six failed logins, an encoded command, a DNS lookup and
an outbound connection are four separate queue items — and one incident.

SignalTrail moves both problems earlier. Reconciliation happens in the
pipeline, before anyone is looking. Grouping happens in correlation, so what
reaches an analyst is a story rather than a list.

---

## Architecture

```
   authentication.json   endpoint.json   dns.json   network.json
            |                  |            |            |
            +------------------+------------+------------+
                               |
                        ingest.py  ........  validate, count rejections
                               |
                        normalize.py  .....  common event model,
                               |             original record preserved
                        database.py  ......  DuckDB (local file)
                               |
                        detections.py  ....  5 deterministic rules -> alerts
                               |
                        correlate.py  .....  host + user + time -> incidents
                               |
         +---------------------+---------------------+
         |                     |                     |
   investigate.py        analytics.py          anomaly.py
   (queries, timelines)  (chart data)          (optional signal)
         |                     |
         +----------+----------+
                    |
              dashboard.py  ......  Streamlit page composition
                    |             ui.py  ....  palette, stylesheet, charts
            ai_investigator.py  ..  optional local model + fallback
```

Full detail in [docs/architecture.md](docs/architecture.md).

---

## Features

- **Four telemetry sources** with deliberately different raw schemas
- **Validation** that counts and explains every rejected record
- **Normalization** onto one 17-field common event model
- **DuckDB** local analytical store, safe to re-run
- **Five detection rules**, each carrying the exact evidence behind it
- **Detection metadata** — logic, inputs, MITRE technique, benign causes
- **Incident correlation** grouping related findings by host, account and time
- **Chronological timelines** that separate rule evidence from context
- **Threat hunting** by free-text indicator or by field
- **Streamlit dashboard** with six analyst-oriented tabs
- **Optional anomaly detection** (Isolation Forest), clearly labelled as a supporting signal
- **Optional local AI investigator** with a deterministic fallback
- **164 tests**, no external services required

---

## Telemetry sources

Four sources, four different shapes. Normalizing that disagreement is the
point of the ingest stage.

| Source | Timestamp format | Account field | Notable fields |
| --- | --- | --- | --- |
| `authentication` | `2026-09-10T10:01:12Z` | `username` | `source_ip`, `status` |
| `endpoint` | `2026-09-10 10:04:00` | `user` | `process`, `command_line`, `file_path` |
| `dns` | `1789034700` (epoch) | `user` | `query`, `response_code` |
| `network` | `2026-09-10T10:06:00+00:00` | `user` | `destination_ip`, `destination_port` |

All data is synthetic. Addresses come from the RFC 5737 documentation ranges,
domains from the reserved `.example` TLD, and the "encoded" PowerShell command
is a literal placeholder — there is no payload anywhere in this project. See
[data/README.md](data/README.md).

---

## Common event schema

| Field | Notes |
| --- | --- |
| `event_id` | `sha256(source_type + canonical record)`, truncated |
| `timestamp` | UTC, naive — all sources converge here |
| `host`, `user` | mapped from each source's own naming |
| `source_type` | which raw source it came from |
| `event_type` | `authentication`, `process`, `file`, `dns`, `network` |
| `action` | standardized verb (`login`, `process_start`, `dns_query`, ...) |
| `src_ip`, `dst_ip`, `dst_port` | network identity |
| `domain`, `process_name`, `command_line`, `file_path` | activity detail |
| `status` | `success`, `failure`, `unknown` |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `raw_message` | the untouched original record |

Two properties matter more than the field list:

**Traceability.** `raw_message` holds the complete original record, so any
normalized field can be checked against its source. Normalization is lossy by
design; evidence should not be.

**Stable identity.** `event_id` is derived from content, so identical records
deduplicate for free and re-running the pipeline produces the same
identifiers — which is what makes it safe to run repeatedly.

---

## Detection engine

| Rule | Severity | Detects | Technique |
| --- | --- | --- | --- |
| RULE-001 | MEDIUM | 5+ failed logins per (user, host, source IP) in 10 min | T1110 |
| RULE-002 | HIGH | PowerShell started with an encoded command line | T1059.001 |
| RULE-003 | MEDIUM | Lookup of a watchlisted domain | T1071.004 |
| RULE-004 | MEDIUM | Connection to a watchlisted destination | T1071.001 |
| RULE-005 | MEDIUM | File created shortly after a RULE-002 process | T1105 |

Thresholds and windows are configurable in `src/config.py`.

Two conventions hold throughout:

**Every alert carries its evidence.** `evidence_event_ids` lists the exact
records that caused the rule to fire. There is no finding here that cannot be
traced back.

**Alerts are observations, not conclusions.** A rule can report that six failed
logins were followed by a success. It cannot report that an account was
compromised. So the wording is *possible brute-force behaviour*, *potential
encoded PowerShell activity*, *investigation recommended* — never "malware
detected", and never a fabricated confidence percentage.

Each rule stores its own metadata, including known benign causes, in a
`DetectionRule` dataclass — reviewable without reading code, and rendered
directly in the dashboard. Full detail in
[docs/detection-rules.md](docs/detection-rules.md).

---

## Incident correlation

Alerts are partitioned by `(host, user)`, clustered by time gap, then enriched
with **context events**: nearby records that share an indicator with the
evidence, or that are authentications.

That last part is what makes a timeline readable. No rule fires on a
successful login — a successful login is not suspicious. But in the demo
incident it is the single most important event, because it is where failed
attempts stop and activity starts. Correlation attaches it and the timeline
marks it as context rather than evidence, so the distinction is never lost.

**Severity has to be earned.** An incident's severity is its worst alert. It
escalates one step to CRITICAL only when four or more distinct rules fire on
the same host and account — independent detections agreeing is harder to
dismiss than one noisy rule repeating itself. No single rule can produce a
CRITICAL on its own.

---

## Investigation

`src/investigate.py` implements every pivot once, and both the dashboard and
the AI layer call it — so they cannot disagree about what the evidence says.

- search by host, user, IP, domain, process, event type or time window
- retrieve the evidence behind any alert or incident
- build an incident timeline, or a host timeline around any moment
- summarize an incident into a single evidence structure

Every query is parameterised. Search terms are never formatted into SQL.

The demo incident reconstructs like this:

```
E  10:01:12  authentication  login failed from 198.51.100.23
E  10:01:22  authentication  login failed from 198.51.100.23
E  10:01:31  authentication  login failed from 198.51.100.23
E  10:01:44  authentication  login failed from 198.51.100.23
E  10:01:58  authentication  login failed from 198.51.100.23
E  10:02:09  authentication  login failed from 198.51.100.23
C  10:02:31  authentication  login succeeded from 198.51.100.23
E  10:04:00  process         powershell.exe ... -EncodedCommand <DEMO_ONLY...>
E  10:05:00  dns             DNS query for demo-suspicious.example
E  10:06:00  network         connection to 203.0.113.50:443
E  10:07:00  file            file created at ...\Temp\demo_payload.bin
```

`E` = a rule fired on it. `C` = context added by correlation.

Walkthrough in
[docs/investigation-workflow.md](docs/investigation-workflow.md).

---

## Threat hunting

Paste an indicator — an address, domain, account, hostname or process — and
see everything that mentions it, without having to say what kind of thing it
is. Field filters are the other entry point, for describing a pattern rather
than chasing a value.

| Search | Returns |
| --- | --- |
| `203.0.113.50` | every event involving that address, either direction |
| `powershell.exe` | related process and file events |
| `analyst_demo` | all activity for that account |

---

## MITRE ATT&CK mapping

A deliberately small mapping — five techniques, only where a rule can
genuinely suggest one. Each entry stores `technique_id`, `technique_name` and
`tactic`.

The labels are hypotheses. A technique ID means "this is the kind of thing
this could be", not "this is what happened", and the UI says so next to every
label. Implementing the full framework would add breadth without adding
confidence.

---

## Anomaly detection

An optional Isolation Forest over per-host, five-minute activity windows,
using six interpretable features: failed logins, DNS requests, outbound
connections, unique destinations, process count, and a rare-process indicator.

It answers a different question from a rule — "is this unlike the rest of the
data?" rather than "did this specific thing happen?" — and it cannot explain
itself the way a rule can. So it is wired in as a **ranking aid, not a
detector**: it raises no alerts and creates no incidents.

Honest result on this dataset: the incident's 10:00 window ranks in roughly
the top 2% of ~1,050 windows and is flagged as an outlier, which is genuinely
useful. The single highest-scoring window is an unremarkable quiet one. That
is the real behaviour of the technique, and the module documents it rather
than overselling it.

scikit-learn is optional. Everything else works without it.

---

## Local AI investigation

An optional layer that turns an incident's evidence into written
investigation notes under six headings: summary, observed evidence, likely
sequence, risk assessment, recommended investigation steps, evidence gaps.

Three constraints shape it:

**Local only.** Generation goes to an Ollama instance at `localhost:11434`, so
nothing leaves the machine. This is the one component that opens a socket at
all; pointing `SIGNALTRAIL_OLLAMA_URL` at a remote host would send the
evidence package there, which is why it defaults to loopback.

**Optional.** Ollama is not a dependency. Without it, the same six sections
are built deterministically from the same evidence — and that fallback is
written to be genuinely useful on its own, because it is the default path for
anyone who never installs a model.

**Grounded.** The model receives a fixed evidence package and nothing else. It
has no tools, no database access, and no ability to act. The prompt instructs
it to use only the supplied evidence, to label inference as inference, never
to invent events or indicators, to state uncertainty, and to recommend
investigative steps rather than actions. The dashboard shows the evidence
package next to the generated text, so anything unsupported is visible.

To enable it: install [Ollama](https://ollama.com), `ollama pull llama3.1`,
and SignalTrail will detect it. Override with `SIGNALTRAIL_OLLAMA_MODEL` and
`SIGNALTRAIL_OLLAMA_URL`.

---

## Dashboard

Six sections, reached from a persistent left rail and ordered by the questions
an analyst actually asks.

| Section | Answers |
| --- | --- |
| **Overview** | What happened? Six headline counters, event volume over time, the severity split, the latest detections, top hosts and indicators, and a snapshot of every correlated incident. |
| **Detection** | Why was it flagged? Filterable alerts, rule logic, possible technique, benign causes to rule out, and the evidence. |
| **Investigation** | What is the story? Incident header, observed attack sequence, a marked timeline, related alerts, indicators, evidence records, and a widenable window. |
| **Threat Hunting** | What else is out there? Free-text indicator search and field filters, with the result cap always stated. |
| **AI Investigation** | Help me write it up. Local model if available, deterministic summary otherwise, rendered section by section. |
| **Anomalies** | Where should I look when nothing fired? Ranked behaviour windows, presented as a ranking rather than a verdict. |

One section renders per run, which is what keeps the page quick with a
thousand events loaded.

Evidence is never more than one click away — every alert and incident
expands to the underlying records, including the original raw message.
Severity is never carried by colour alone: every badge, axis label and table
cell keeps the word.

Appearance lives in `src/ui.py` — one palette, one stylesheet, one chart
theme — and the same palette is mirrored into `.streamlit/config.toml`,
so Streamlit's own widgets sit on the colours the custom panels use. A test
asserts the two definitions stay in step.

---

## Project structure

```
SignalTrail/
├── .streamlit/
│   └── config.toml             dashboard on loopback, no usage reporting
├── data/
│   ├── raw/                    generated telemetry (4 JSON sources)
│   ├── processed/              DuckDB database
│   └── README.md               dataset documentation and safety notes
├── src/
│   ├── config.py               paths, thresholds, watchlists
│   ├── schemas.py              raw schemas, event model, severity, MITRE
│   ├── generate_data.py        synthetic telemetry generator
│   ├── ingest.py               validation and ingestion metrics
│   ├── normalize.py            common event model mapping
│   ├── database.py             DuckDB schema and loading
│   ├── detections.py           five detection rules + metadata
│   ├── correlate.py            alerts -> incidents
│   ├── investigate.py          query layer (dashboard + AI share it)
│   ├── analytics.py            chart aggregations
│   ├── anomaly.py              optional Isolation Forest
│   ├── ai_investigator.py      optional local AI + deterministic fallback
│   ├── dashboard.py            Streamlit UI (page composition)
│   └── ui.py                   the console's visual system
├── tests/                      219 pytest tests
├── docs/
│   ├── architecture.md
│   ├── detection-rules.md
│   ├── investigation-workflow.md
│   └── roadmap.md
├── run_pipeline.py             pipeline entry point
├── requirements.txt
└── pytest.ini
```

---

## Setup

Requires Python 3.11 or newer. Developed and verified on **Python 3.14.5,
Windows 10, PowerShell**.

### Windows (PowerShell)

```powershell
git clone <repository-url>
cd SignalTrail

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

If activation is blocked by execution policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Running the pipeline

```powershell
python run_pipeline.py
```

Generates the telemetry if it is missing, validates it, normalizes it, loads
DuckDB, runs detections, correlates incidents and prints a summary.

```powershell
python run_pipeline.py --regenerate   # rebuild the synthetic telemetry first
python run_pipeline.py --anomaly      # also run behavioural anomaly scoring
python run_pipeline.py --quiet        # warnings and errors only
python run_pipeline.py --db other.duckdb
```

Expected output:

```
Ingestion
---------
SignalTrail ingestion

Raw records:      1227
Valid records:    1225
Invalid records:  2
Duplicates:       0
Normalized:       1225
Duration:         0.08 seconds

Storage
-------
security_events    1225
alerts             6
incidents          2

Detection
---------
RULE-001  Repeated authentication failures                 2
RULE-002  Encoded PowerShell command                       1
RULE-003  Suspicious DNS query                             1
RULE-004  Connection to suspicious destination             1
RULE-005  File activity after suspicious process execution 1

Incidents
---------
INC-96b7f6e63219ad60  [MEDIUM]  Repeated authentication failures on SRV-002 (svc_backup)
INC-0531f4455002b7eb  [CRITICAL]  Multi-stage suspicious activity on WS-001 (analyst_demo)
```

The two invalid records are planted on purpose — see
[data/README.md](data/README.md).

**The pipeline is safe to run repeatedly.** Identifiers are derived from
content and loads replace table contents rather than appending, so a second
run over unchanged input produces an identical database.

## Running the tests

```powershell
python -m pytest
```

164 tests. No external services, no network access, no generated dataset
required — fixtures are small and hand-written.

## Running the dashboard

```powershell
python -m streamlit run src/dashboard.py
```

Then open <http://localhost:8501>. Run the pipeline first, or the dashboard
will say so.

`.streamlit/config.toml` keeps the server on loopback and turns Streamlit's
usage reporting off. Delete or edit it if you want the page reachable from
elsewhere — there is no authentication in front of it.

---

## Design decisions

**Rules before machine learning.** A rule can be read, argued with, tuned and
unit-tested, and it can say why it fired in a sentence a person can check. The
anomaly model is a supporting signal, wired in so it cannot create alerts.

**Content-derived identifiers.** The alternative is a pipeline that either
duplicates findings on every run or needs reconciliation logic to avoid it.
Hashing content makes idempotency a property of the data.

**`raw_message` on every event.** It costs storage. It buys the ability to
answer "is that really what the log said?" without leaving the tool.

**Timestamps stored as naive UTC.** Everything converts at normalization.
Mixed-offset comparisons in pandas and DuckDB are a recurring source of subtle
bugs; "everything is UTC, stated once" avoids the category.

**DuckDB over SQLite or Postgres.** Analytical queries over columnar data,
in-process, one file, no server and no credentials. For a tool analysing
security telemetry, data that never leaves the machine is the point.

**Correlation groups by host *and* account.** Looser would merge unrelated
activity into one unusable incident. Too conservative produces several small
incidents an analyst can link by hand — the better failure.

**No fabricated confidence.** Severity labels have defined meaning. There are
no percentages, because an invented number is worse than no number: people act
on it.

**Two planted scenarios, not one.** The multi-stage incident *and* a service
account tripping the brute-force rule with a stale password. A dataset where
every alert is a true positive teaches the wrong instinct about triage.

---

## Limitations

- **Synthetic data only.** The rules have never met a real environment's
  noise. RULE-001 and RULE-002 in particular would need allowlists before
  being usable anywhere real.
- **Batch, not streaming.** Detection runs over the whole dataset each time.
- **In memory.** Fine at this scale; a real dataset would need the rules
  pushed into SQL.
- **Correlation is single-host, single-account.** No lateral movement, no
  process lineage, no cross-account linking.
- **Static watchlists.** Configuration, not a threat-intelligence feed.
- **No evaluation numbers.** There is no labelled ground truth here, so no
  precision or recall is claimed for either the rules or the model.
- **The AI layer's grounding is enforced by prompt instructions and by showing
  the evidence beside the output.** Neither is a guarantee. Model output can be
  wrong, and the UI says so.
- **No authentication or multi-user support.** Single-analyst local tool.

---

## Roadmap

- **V1 (current)** — working local security analytics, end to end
- **V2** — password spraying, beaconing, process lineage, declarative rules,
  per-rule allowlists, per-host ML baselines, measured evaluation
- **V3** — richer local AI investigation, incident status and analyst notes,
  cross-host correlation, case export, real log formats

Detail in [docs/roadmap.md](docs/roadmap.md).

---

## Safety

Everything in this project is synthetic and defensive.

- Addresses come only from RFC 5737 documentation ranges and RFC 1918 space.
- Domains use the reserved `.example` TLD and never resolve.
- The "encoded" PowerShell command is the literal text
  `<DEMO_ONLY_PLACEHOLDER_NOT_A_REAL_PAYLOAD>`. There is no encoded payload
  anywhere in this repository.
- Nothing is executed, downloaded or written outside `data/`.
- `.streamlit/config.toml` binds the dashboard to `localhost` and turns off
  Streamlit's usage reporting. Out of the box Streamlit serves on every
  interface with no authentication in front of it, which is the wrong default
  for a page showing security telemetry. The only socket SignalTrail itself
  opens is the optional call to a local Ollama.
- There are no credentials, keys or secrets in the repository, and no
  machine-specific paths — every path is derived from the repository root.

SignalTrail is an analysis tool. It contains no offensive capability, no
automated response, and no ability for any component — the AI layer included —
to act on a system.

---

## License

Released under the [MIT License](LICENSE).
