# Detection rules

Five deterministic rules, defined in `src/detections.py`. Each rule's metadata
- description, logic, inputs, severity, possible technique, and known benign
causes - is stored with the rule itself in a `DetectionRule` dataclass, so it
can be reviewed without reading the implementation and rendered directly in
the dashboard.

## Conventions

**Alerts are observations.** A rule can report that six failed logins were
followed by a success. It cannot report that an account was compromised - that
is a conclusion, and it needs evidence a log line does not contain. Every
`reason` string is written accordingly.

**Every alert carries its evidence.** `evidence_event_ids` lists the exact
records that caused the rule to fire. There is no finding in this system that
cannot be traced back to the events behind it.

**MITRE labels are hypotheses.** A technique ID says "this is the kind of
thing this could be", not "this is what happened". The UI states this next to
every label.

**Alert identifiers are derived from content.** `sha256(rule + host + user +
sorted evidence)`. Re-running detection over unchanged data regenerates the
same alert instead of a new one.

## Severity scale

| Level | Meaning |
| --- | --- |
| `INFO` | Recorded for context. Event-level default. |
| `LOW` | Slightly notable on its own - a failed login, for instance. |
| `MEDIUM` | Worth an analyst's time. Most rules sit here. |
| `HIGH` | Specific and uncommon enough to prioritise. |
| `CRITICAL` | Reserved for incidents where several independent rules agree. No single rule assigns it. |

There are no confidence percentages anywhere in this project. A number like
"87% malicious" would be invented, and an invented number is worse than no
number because people act on it.

---

## RULE-001 - Repeated authentication failures

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **Inputs** | `authentication` |
| **Technique** | T1110 Brute Force (Credential Access) |

### Logic

Failed logins are grouped by `(user, host, src_ip)`. A sliding window walks
each group in time order; when five or more failures fall inside a ten-minute
window, the burst is reported as one alert. The window is extended as far as
it reaches, and the events in it are marked as claimed, so a burst of twenty
failures produces one alert with twenty pieces of evidence rather than sixteen
overlapping alerts.

Both the threshold and the window are configurable
(`config.AUTH_FAILURE_THRESHOLD`, `config.AUTH_FAILURE_WINDOW_MINUTES`).

### Why it is grouped this way

Grouping by source address as well as account is what separates "one system
retrying with a stale credential" from "many sources trying one account". The
second pattern would not be caught by this rule as written - it is a known gap
rather than an oversight, and it is on the roadmap as password spraying.

### Benign causes

- A service account or scheduled job still using a rotated password.
- A user whose saved credential expired on a phone or mail client.
- A misconfigured application retrying automatically.

The synthetic dataset contains exactly this situation on purpose: `svc_backup`
on `SRV-002` produces six failures from a scheduled job and becomes its own
MEDIUM incident. It is a correct rule firing on non-malicious activity, which
is the normal case in real environments.

### Tuning

Raising the threshold cuts noise and misses slow attempts. Lowering it does
the reverse. The useful move is usually neither: it is excluding known service
accounts by name, which the current implementation does not support.

---

## RULE-002 - Encoded PowerShell command

| | |
| --- | --- |
| **Severity** | HIGH |
| **Inputs** | `endpoint` |
| **Technique** | T1059.001 Command and Scripting Interpreter: PowerShell (Execution) |

### Logic

A process event where the binary is PowerShell and one command-line token
selects the encoded-command switch. Both halves are stricter than a substring
search, because a substring search is wrong in ways that matter:

**The binary is matched on its file name, by equality.** A path does not change
the answer, so `C:\Windows\System32\powershell.exe` matches. But
`notpowershell.exe` *contains* `powershell.exe` and is a different program, so
equality is the right test.

**The switch is matched as a whole token, allowing abbreviation.** PowerShell
resolves any unambiguous prefix of a parameter name, so `-EncodedCommand`,
`-enc` and `-e` all select the same switch, and a value may be attached with a
colon (`-EncodedCommand:abc`). Matching tokens rather than substrings is what
stops `-e` appearing inside an unrelated argument from firing the rule.

**Tokenizing respects quotes.** In
`-Command "Write-Host 'a -e b'"` the `-e` is inside a quoted string. Splitting
on whitespace alone would treat it as a switch and fire on an ordinary
command. An unbalanced quote falls back to whitespace splitting: malformed
input should leave the rule slightly over-eager, not blind.

**`-File` and `-Command` end the switch list.** PowerShell passes everything
after them to the script or the command text, so a `-e` that appears later is
an argument to *that*, not a switch PowerShell itself acts on. Scanning stops
there.

Matching is case-insensitive throughout.

### Why HIGH

Because it is specific. The rule does not fire on PowerShell - it fires on
PowerShell whose command was deliberately made unreadable in the log. That is
a much smaller set of events, and the relevant fact is precisely that the
evidence a reviewer would want is missing.

The alert says so explicitly: the command was not recorded in readable form,
so decode it before drawing conclusions.

### Benign causes

- Management and deployment tooling that legitimately encodes commands.
- Installers and vendor agents that wrap their own scripts.

Both are common. In an environment with such tooling this rule needs an
allowlist by parent process or by signing certificate before it is usable.

### What it does not do

It does not decode the command. Decoding is left to the analyst, and nothing
in this project executes anything from telemetry.

It also does not catch a renamed binary. A copy of `powershell.exe` saved as
`svchost.exe` runs the same interpreter and would not match, because the rule
tests the recorded process name. Catching that needs file hashes or the
original-filename field from the binary's version information, neither of
which this telemetry carries.

---

## RULE-003 - Suspicious DNS query

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **Inputs** | `dns` |
| **Technique** | T1071.004 Application Layer Protocol: DNS (Command and Control) |

### Logic

The queried domain matches an entry in `config.SUSPICIOUS_DOMAINS`, compared
case-insensitively and in full. In a real deployment this list would come from
a threat-intelligence feed; here it is static configuration, and the watchlist
is injectable so the rule can be tested without touching global state.

### Limits

A DNS lookup shows that a name was resolved. It does not show that a
connection followed, that anything was sent, or that the user initiated it.
The alert text says this and points the analyst at network telemetry for the
same host and window - which, in the demo incident, is exactly what RULE-004
found.

The match is on the whole name, so `sub.demo-suspicious.example` does **not**
fire when `demo-suspicious.example` is watchlisted. That is the conservative
choice - suffix matching would make `notdemo-suspicious.example` and
`demo-suspicious.example.attacker.test` match too - but it is a real blind
spot, and a feed that lists a domain without its subdomains will miss them
here. Matching parent domains properly needs the public-suffix list, so that a
rule for `example.co.uk` does not become a rule for `co.uk`.

### Benign causes

- A stale watchlist entry after a domain changes ownership.
- Security tooling or a researcher resolving the domain on purpose.
- A cached or prefetched lookup the user never initiated.

---

## RULE-004 - Connection to suspicious destination

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **Inputs** | `network` |
| **Technique** | T1071.001 Application Layer Protocol: Web Protocols (Command and Control) |

### Logic

`dst_ip` matches an entry in `config.SUSPICIOUS_DESTINATIONS`. The alert
reports whether the connection was allowed or blocked, because the two call
for very different responses.

### Limits

An address-based watchlist is a blunt instrument. Shared hosting means one
address can serve thousands of unrelated sites, and addresses get recycled.
The rule reports the connection and prompts the analyst to check what actually
transferred rather than asserting impact.

### Benign causes

- A shared hosting address where most traffic is unrelated.
- A blocked connection attempt that never completed.
- An address recycled since the watchlist was written.

---

## RULE-005 - File activity after suspicious process execution

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **Inputs** | `endpoint` |
| **Technique** | T1105 Ingress Tool Transfer (Command and Control) |

### Logic

For each alert RULE-002 produced, look for `file_create` events on the same
`(host, user)` within ten minutes after it. If any exist, raise one alert
whose evidence includes both the process and the files.

The window is configurable (`config.POST_EXECUTION_WINDOW_MINUTES`).

### Why it builds on RULE-002

The definition of "suspicious process" lives in exactly one place. If RULE-002
is tuned, this rule follows automatically - there is no second copy of the
logic to forget about.

### What makes this rule different

Neither half is interesting alone. Processes start constantly and files are
written constantly. The rule is about *sequence*: a flagged process, then a
file, close together, same account, same machine.

That is also its weakness, and the alert text says so. Temporal ordering is
not causation. The file may have been written by something else entirely that
happened to run in the same window. Confirming that the process wrote the file
needs file-provenance telemetry this dataset does not have.

### Benign causes

- A legitimate script writing its own output or log files.
- Software installation running under the same account.

---

## Coverage and gaps

What the five rules cover: credential attacks against a single account,
obfuscated execution, known-bad name resolution, known-bad destinations, and
one behavioural sequence.

What they do not cover, and would matter next:

- **Password spraying** - one password against many accounts. RULE-001 groups
  by account, so this pattern is invisible to it.
- **Impossible travel** - the same account authenticating from geographically
  incompatible locations. Needs geolocation data.
- **Beaconing** - regular, low-volume connections to one destination. Needs
  interval analysis rather than a watchlist, and would catch destinations no
  list knows about yet.
- **Lateral movement** - correlation across hosts. The current correlation
  layer is deliberately scoped to one host and one account.
- **Process lineage** - what launched the flagged process. This is the single
  most useful missing field: it separates PowerShell started by a deployment
  agent from PowerShell started by a mail client. The endpoint source does not
  record it, so no rule here can use it.

## Testing

`tests/test_detections.py` covers every rule twice: that it fires on the
pattern it describes, and that it stays quiet on activity that resembles it.
The negative cases are the ones that matter - a rule that cannot be kept quiet
is a rule that gets disabled.

Fixtures are small and hand-written. Tests that depend on the data generator
end up testing the generator.
