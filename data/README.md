# Data

Everything in this directory is generated. Nothing here comes from a real
network, a real user, or a real piece of malware.

```
data/
├── raw/          generated telemetry, one JSON file per source
├── processed/    the DuckDB database the pipeline writes
└── README.md
```

Both subdirectories are excluded from version control. To recreate them:

```powershell
python run_pipeline.py --regenerate
```

The generator is seeded (`config.GENERATOR_SEED`) and anchored to a fixed
start date (`config.DATA_START`), so that command produces byte-identical
files on any machine.

## Safety of the dataset

| Concern | How it is handled |
| --- | --- |
| Addresses | Only RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 1918 internal space (`10.10.0.0/24`). |
| Domains | Only `.example` and `.example.com/net/org`, reserved by RFC 2606 and never resolvable. |
| The "encoded" PowerShell command | The literal text `<DEMO_ONLY_PLACEHOLDER_NOT_A_REAL_PAYLOAD>`. There is no encoded payload anywhere in this project. |
| The "dropped" file | A path string. No file is created, and nothing is executed. |
| Users and hosts | Invented names (`analyst_demo`, `WS-001`). |

## Raw sources

The four sources deliberately disagree about field names and timestamp
formats, because normalizing that disagreement is the point of the ingest
stage.

### `authentication.json`

ISO-8601 with a `Z` suffix. Calls the account `username`.

```json
{
  "timestamp": "2026-09-10T10:01:12Z",
  "username": "analyst_demo",
  "source_ip": "198.51.100.23",
  "action": "login",
  "status": "failure",
  "host": "WS-001",
  "auth_method": "password"
}
```

### `endpoint.json`

Space-separated timestamp with no zone marker. Calls the account `user` and
the binary `process`. Carries `file_path` only on file events.

```json
{
  "timestamp": "2026-09-10 10:04:00",
  "host": "WS-001",
  "user": "analyst_demo",
  "process": "powershell.exe",
  "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <DEMO_ONLY_PLACEHOLDER_NOT_A_REAL_PAYLOAD>",
  "action": "process_start"
}
```

### `dns.json`

Unix epoch seconds. Calls the domain `query`.

```json
{
  "timestamp": 1789034700,
  "host": "WS-001",
  "user": "analyst_demo",
  "query": "demo-suspicious.example",
  "action": "query",
  "response_code": "NOERROR"
}
```

### `network.json`

ISO-8601 with a numeric offset. Calls the destination `destination_ip` /
`destination_port`.

```json
{
  "timestamp": "2026-09-10T10:06:00+00:00",
  "host": "WS-001",
  "user": "analyst_demo",
  "destination_ip": "203.0.113.50",
  "destination_port": 443,
  "action": "allow",
  "protocol": "tcp",
  "bytes_out": 184320
}
```

## What the dataset contains

Roughly 1,230 records across five days and six hosts. The large majority is
routine activity: logins and logouts, everyday processes, ordinary name
resolution, internal and external connections, and a handful of mistyped
passwords that stay well under the detection threshold.

Three things are planted on purpose.

### 1. The demo incident (WS-001, `analyst_demo`, 2026-09-10 10:01-10:07 UTC)

Seven linked events that the pipeline should recover as a single incident:

| Time (UTC) | Source | What happened |
| --- | --- | --- |
| 10:01:12 - 10:02:09 | authentication | six failed logins from `198.51.100.23` |
| 10:02:31 | authentication | a successful login from the same address |
| 10:04:00 | endpoint | `powershell.exe` started with an encoded command line |
| 10:05:00 | dns | lookup of `demo-suspicious.example` |
| 10:06:00 | network | outbound connection to `203.0.113.50:443` |
| 10:07:00 | endpoint | file created under the user's temp directory |

All five detection rules fire on this sequence, and correlation groups them
into one incident. The successful login at 10:02:31 is not itself an alert -
correlation pulls it in as context, which is why it appears in the timeline
without an evidence marker.

### 2. A service-account lockout (SRV-002, `svc_backup`, 2026-09-08 02:15 UTC)

Six failed logins from a scheduled job using a stale password. This trips
RULE-001 and becomes its own MEDIUM incident.

It is planted deliberately. A rule firing is not the same thing as an attack,
and a dataset where every alert is a true positive teaches the wrong lesson
about triage.

### 3. Two malformed records

One authentication record missing its `host` field, and one DNS record whose
timestamp cannot be parsed. Both are rejected at validation and reported in
the ingestion metrics:

```
Raw records:      1227
Valid records:    1225
Invalid records:  2
Duplicates:       0
Normalized:       1225
```

Real log pipelines always carry some broken input. Generating it means the
metrics report a realistic run rather than a perfect one.
