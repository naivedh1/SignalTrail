# Investigation workflow

How a raw log line becomes something an analyst can act on, traced through the
demo incident end to end.

```
event -> alert -> evidence -> correlation -> incident -> timeline -> analyst
```

Each arrow adds context without discarding what came before. At every stage
you can get back to the original record.

## 1. Event

A raw record arrives and is validated, then mapped onto the common event
model:

```json
{
  "timestamp": "2026-09-10T10:01:12Z",
  "username": "analyst_demo",
  "source_ip": "198.51.100.23",
  "action": "login",
  "status": "failure",
  "host": "WS-001"
}
```

becomes

```
event_id     EVT-1a2b3c4d5e6f7890
timestamp    2026-09-10 10:01:12   (UTC)
host         WS-001
user         analyst_demo          <- from "username"
event_type   authentication
action       login
status       failure
src_ip       198.51.100.23         <- from "source_ip"
severity     LOW
raw_message  {"action":"login","host":"WS-001",...}
```

Two things to notice. The `event_id` is a hash of the original record, so the
same input always produces the same identifier. And `raw_message` holds the
untouched original, so nothing above it has to be taken on trust.

At this point nothing has been judged. A single failed login is an ordinary
thing that happens dozens of times a day.

## 2. Alert

Rules run over the normalized events. Six failures for one account, on one
host, from one address, inside ten minutes crosses RULE-001's threshold:

```
alert_id            ALR-e0409725298cb5f4
rule_id             RULE-001
severity            MEDIUM
host                WS-001
user                analyst_demo
evidence_event_ids  EVT-...,EVT-...,EVT-...,EVT-...,EVT-...,EVT-...
evidence_count      6
technique_id        T1110
reason              6 failed logins for 'analyst_demo' on WS-001 from
                    198.51.100.23 within 10 minutes. Possible password
                    guessing; confirm whether the source and account are
                    expected before treating it as an attack.
```

The wording is the point. "Possible password guessing" and "confirm ... before
treating it as an attack" describe what was seen and what remains unknown. An
alert that overstates its case trains people to ignore alerts.

Four more rules fire on the same host over the next five minutes: encoded
PowerShell (HIGH), a watchlisted domain, a watchlisted destination, and file
creation after the flagged process.

## 3. Evidence

Every alert names the events behind it. `investigate.get_alert_evidence()`
resolves them:

```python
evidence = investigate.get_alert_evidence(conn, "ALR-e0409725298cb5f4")
```

returns the six failed-login events in time order - and each of those still
carries its `raw_message`. The chain from finding back to source is never
broken.

## 4. Correlation

Five alerts on one host in six minutes is five queue items. It should be one.

`correlate.py` partitions alerts by `(host, user)`, clusters them by time gap,
and then attaches **context events**: records nearby that share an indicator
with the evidence, or that are authentication events.

That second part is what makes the story readable. No rule fires on the
successful login at 10:02:31 - a successful login is not suspicious. But it is
the single most important event in the sequence, because it is where failed
attempts stop and activity starts. Correlation pulls it in, and the timeline
marks it as context rather than evidence so the distinction is never lost.

## 5. Incident

```
incident_id     INC-0531f4455002b7eb
severity        CRITICAL
title           Multi-stage suspicious activity on WS-001 (analyst_demo)
host            WS-001
user            analyst_demo
start_time      2026-09-10 10:01:12
end_time        2026-09-10 10:07:00
evidence_count  11
rule_ids        RULE-001,RULE-002,RULE-003,RULE-004,RULE-005
```

Severity is CRITICAL here because five distinct rules, reading four different
telemetry sources, agree on the same host and account inside six minutes. That
is the only path to CRITICAL in this system - no single rule can produce one,
however noisy it is.

The summary is generated deterministically from the evidence:

> Between 2026-09-10 10:01:12 and 10:07:00 UTC (5 minutes), 5 detection rules
> fired for account 'analyst_demo' on WS-001. Observed: repeated failed logins,
> an encoded PowerShell command line, a lookup of a watchlisted domain, a
> connection to a watchlisted address and file creation shortly after a flagged
> process. 11 events are attached as evidence. A successful login for
> 'analyst_demo' from 198.51.100.23 was recorded at 10:02:31 within the same
> window. This grouping reflects timing and shared host/account context. It
> shows what was observed, not a confirmed cause.

## 6. Timeline

```
E  10:01:12  authentication  login failed from 198.51.100.23
E  10:01:22  authentication  login failed from 198.51.100.23
E  10:01:31  authentication  login failed from 198.51.100.23
E  10:01:44  authentication  login failed from 198.51.100.23
E  10:01:58  authentication  login failed from 198.51.100.23
E  10:02:09  authentication  login failed from 198.51.100.23
C  10:02:31  authentication  login succeeded from 198.51.100.23
E  10:04:00  process         process started: powershell.exe -NoProfile
                             -WindowStyle Hidden -EncodedCommand <DEMO_ONLY...>
E  10:05:00  dns             DNS query for demo-suspicious.example
E  10:06:00  network         connection to 203.0.113.50:443
E  10:07:00  file            file created at C:\Users\analyst_demo\AppData\
                             Local\Temp\demo_payload.bin by powershell.exe
```

`E` marks events a rule fired on; `C` marks context added by correlation.

Read top to bottom, the sequence is legible without any interpretation layer:
repeated attempts, then one that works, then execution, then name resolution,
then a connection, then a file. Every row keeps its `event_id`, host, account,
source and original record.

What the timeline does **not** say is that any of this caused any of the rest.
Ordering shows what followed what. Establishing causation needs process
lineage and file-provenance data that this telemetry does not contain, and the
tool says so rather than implying otherwise.

## 7. Analyst

From the incident view, the pivots available are:

| Question | How |
| --- | --- |
| Is this address known elsewhere? | Hunt `198.51.100.23` - does it appear against other accounts? |
| Did other hosts contact that destination? | Hunt `203.0.113.50` |
| Did the domain resolve anywhere else? | Hunt `demo-suspicious.example` |
| What else did this account do? | Hunt `analyst_demo` |
| What else ran on this host? | Widen the window in the Investigation tab |
| What did the command actually do? | Read `raw_message`, decode the command line |

Free-text hunting is one entry point: paste an indicator and see everything
that mentions it, without having to say what kind of indicator it is. Field
filters are the other, for describing a pattern rather than chasing a value.

## 8. Writing it up

The AI Investigation tab produces notes under six headings: summary, observed
evidence, likely sequence, risk assessment, recommended investigation steps,
and evidence gaps.

If a local Ollama instance is running, the text is generated from the evidence
package - and only the evidence package. The prompt instructs the model to use
nothing else, to label inference as inference, to avoid inventing detail, and
to recommend investigative steps rather than actions.

If Ollama is not running, the same six sections are built deterministically
from the same evidence. That path is the default for anyone who never installs
a model, so it is written to stand on its own rather than as a stub.

Either way the evidence package is shown alongside the notes. Anything in the
text that is not in the package was not supported by evidence, and the reader
can check that directly.

## Triage is not the same as response

The demo incident looks like an attack because it was built to. Real
investigations end in "expected activity" far more often than not - which is
why the second planted scenario matters.

`svc_backup` on `SRV-002` produces six failed logins from a scheduled job with
a stale password. RULE-001 fires correctly. The incident is MEDIUM and reads
almost identically to the first stage of the demo incident. Nothing about it
is an attack.

A tool that only ever demonstrates true positives teaches the wrong instinct.
Both incidents are in the dataset so that the workflow has to distinguish
between them, which is what triage actually is.
