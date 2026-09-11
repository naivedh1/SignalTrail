"""Detection tests.

Each rule is checked twice: that it fires on the pattern it describes, and
that it stays quiet on activity that merely resembles it. The second half
matters more - a rule that cannot be kept quiet is a rule nobody will keep
enabled.
"""

from __future__ import annotations

import pytest

from conftest import make_event, make_frame

from src import detections
from src import schemas


# --------------------------------------------------------------------------
# RULE-001: repeated authentication failures
# --------------------------------------------------------------------------


def failure_events(count: int, spacing: int = 10, **overrides):
    return [
        make_event(
            f"EVT-f{index}",
            offset_seconds=index * spacing,
            src_ip="198.51.100.23",
            status=schemas.STATUS_FAILURE,
            **overrides,
        )
        for index in range(count)
    ]


def test_burst_of_failures_fires():
    alerts = detections.detect_auth_bruteforce(make_frame(failure_events(6)))

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-001"
    assert alerts[0]["evidence_count"] == 6


def test_below_threshold_does_not_fire():
    alerts = detections.detect_auth_bruteforce(make_frame(failure_events(4)))
    assert alerts == []


def test_failures_spread_beyond_the_window_do_not_fire():
    """Six failures across a working day are not a burst."""
    events = failure_events(6, spacing=3600)
    assert detections.detect_auth_bruteforce(make_frame(events)) == []


def test_failures_from_different_sources_are_not_grouped():
    """Grouping is per (user, host, source). Split sources stay below threshold."""
    events = []
    for index in range(6):
        events.append(
            make_event(
                f"EVT-s{index}",
                offset_seconds=index * 10,
                src_ip=f"198.51.100.{index}",
                status=schemas.STATUS_FAILURE,
            )
        )
    assert detections.detect_auth_bruteforce(make_frame(events)) == []


def test_successful_logins_are_not_counted_as_failures():
    events = failure_events(4) + [
        make_event("EVT-ok1", offset_seconds=50, src_ip="198.51.100.23",
                   status=schemas.STATUS_SUCCESS),
        make_event("EVT-ok2", offset_seconds=60, src_ip="198.51.100.23",
                   status=schemas.STATUS_SUCCESS),
    ]
    assert detections.detect_auth_bruteforce(make_frame(events)) == []


def test_threshold_is_configurable():
    events = make_frame(failure_events(3))
    assert detections.detect_auth_bruteforce(events, threshold=3)
    assert detections.detect_auth_bruteforce(events, threshold=4) == []


def test_one_burst_produces_one_alert_not_one_per_event():
    """Ten failures in a burst are a single finding, not ten queue items."""
    alerts = detections.detect_auth_bruteforce(make_frame(failure_events(10)))
    assert len(alerts) == 1
    assert alerts[0]["evidence_count"] == 10


def test_a_sustained_stream_does_not_re_report_the_same_failures():
    """Thirty failures over half an hour are a few bursts, not one per event.

    A scheduled job retrying a stale password produces a continuous stream.
    Sliding the window without remembering what has already been reported
    emits an alert per event, each one re-describing failures an analyst has
    already seen under a different alert id.
    """
    alerts = detections.detect_auth_bruteforce(make_frame(failure_events(30, spacing=60)))

    assert 0 < len(alerts) < 6

    claimed: set[str] = set()
    for alert in alerts:
        evidence = set(alert["evidence_event_ids"].split(","))
        assert not (evidence & claimed), "the same failure appears in two alerts"
        claimed |= evidence


def test_every_failure_in_a_stream_is_accounted_for():
    """Suppressing repeats must not drop failures from the evidence either."""
    events = failure_events(30, spacing=60)
    alerts = detections.detect_auth_bruteforce(make_frame(events))

    reported = {
        event_id
        for alert in alerts
        for event_id in alert["evidence_event_ids"].split(",")
    }
    assert reported == {event["event_id"] for event in events}


def test_bruteforce_reason_avoids_asserting_compromise():
    alerts = detections.detect_auth_bruteforce(make_frame(failure_events(6)))
    reason = alerts[0]["reason"].lower()

    assert "possible" in reason or "confirm" in reason
    assert "compromised" not in reason


# --------------------------------------------------------------------------
# RULE-002: encoded PowerShell
# --------------------------------------------------------------------------


def process_event(event_id, process_name, command_line, offset=0):
    return make_event(
        event_id,
        offset_seconds=offset,
        source_type="endpoint",
        event_type=schemas.EVENT_TYPE_PROCESS,
        action="process_start",
        status=schemas.STATUS_SUCCESS,
        process_name=process_name,
        command_line=command_line,
    )


def test_encoded_powershell_fires():
    events = make_frame(
        [process_event("EVT-ps", "powershell.exe",
                       "powershell.exe -NoProfile -EncodedCommand <DEMO_ONLY>")]
    )
    alerts = detections.detect_encoded_powershell(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == schemas.SEVERITY_HIGH
    assert alerts[0]["technique_id"] == "T1059.001"


def test_encoded_switch_matching_is_case_insensitive():
    events = make_frame(
        [process_event("EVT-ps", "PowerShell.exe", "PowerShell.exe -EncodedCommand ABC")]
    )
    assert len(detections.detect_encoded_powershell(events)) == 1


def test_ordinary_powershell_does_not_fire():
    events = make_frame(
        [process_event("EVT-ps", "powershell.exe", "powershell.exe -File C:\\ops\\inventory.ps1")]
    )
    assert detections.detect_encoded_powershell(events) == []


def test_encoded_switch_on_another_binary_does_not_fire():
    """The rule is about PowerShell, not about the word 'encoded'."""
    events = make_frame(
        [process_event("EVT-other", "custom_tool.exe", "custom_tool.exe -EncodedCommand ABC")]
    )
    assert detections.detect_encoded_powershell(events) == []


def test_file_events_are_not_scanned_as_processes():
    events = make_frame(
        [
            make_event(
                "EVT-file",
                source_type="endpoint",
                event_type=schemas.EVENT_TYPE_FILE,
                action="file_create",
                status=schemas.STATUS_SUCCESS,
                process_name="powershell.exe",
                command_line="powershell.exe -EncodedCommand <DEMO_ONLY>",
            )
        ]
    )
    assert detections.detect_encoded_powershell(events) == []


# --------------------------------------------------------------------------
# RULE-003: suspicious DNS
# --------------------------------------------------------------------------


def dns_event(event_id, domain, offset=0):
    return make_event(
        event_id,
        offset_seconds=offset,
        source_type="dns",
        event_type=schemas.EVENT_TYPE_DNS,
        action="dns_query",
        status=schemas.STATUS_SUCCESS,
        domain=domain,
    )


def test_watchlisted_domain_fires():
    events = make_frame([dns_event("EVT-dns", "demo-suspicious.example")])
    alerts = detections.detect_suspicious_dns(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-003"


def test_ordinary_domain_does_not_fire():
    events = make_frame([dns_event("EVT-dns", "updates.example.com")])
    assert detections.detect_suspicious_dns(events) == []


def test_dns_watchlist_is_injectable():
    events = make_frame([dns_event("EVT-dns", "another.example")])
    assert detections.detect_suspicious_dns(events, watchlist={"another.example"})
    assert detections.detect_suspicious_dns(events, watchlist={"unrelated.example"}) == []


def test_dns_alert_does_not_claim_a_connection_happened():
    events = make_frame([dns_event("EVT-dns", "demo-suspicious.example")])
    reason = detections.detect_suspicious_dns(events)[0]["reason"].lower()
    assert "does not" in reason or "check" in reason


# --------------------------------------------------------------------------
# RULE-004: suspicious destination
# --------------------------------------------------------------------------


def network_event(event_id, dst_ip, offset=0, action="connection_allowed"):
    return make_event(
        event_id,
        offset_seconds=offset,
        source_type="network",
        event_type=schemas.EVENT_TYPE_NETWORK,
        action=action,
        status=schemas.STATUS_SUCCESS,
        dst_ip=dst_ip,
        dst_port=443,
    )


def test_watchlisted_destination_fires():
    events = make_frame([network_event("EVT-net", "203.0.113.50")])
    alerts = detections.detect_suspicious_destination(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-004"


def test_ordinary_destination_does_not_fire():
    events = make_frame([network_event("EVT-net", "203.0.113.7")])
    assert detections.detect_suspicious_destination(events) == []


def test_blocked_connection_is_described_as_blocked():
    events = make_frame(
        [network_event("EVT-net", "203.0.113.50", action="connection_blocked")]
    )
    alerts = detections.detect_suspicious_destination(events)
    assert "blocked" in alerts[0]["reason"]


# --------------------------------------------------------------------------
# RULE-005: file activity after a flagged process
# --------------------------------------------------------------------------


def file_event(event_id, offset, host="WS-001", user="analyst_demo"):
    return make_event(
        event_id,
        offset_seconds=offset,
        host=host,
        user=user,
        source_type="endpoint",
        event_type=schemas.EVENT_TYPE_FILE,
        action="file_create",
        status=schemas.STATUS_SUCCESS,
        process_name="powershell.exe",
        file_path="C:\\Temp\\demo_payload.bin",
    )


def test_file_creation_after_flagged_process_fires():
    events = make_frame(
        [
            process_event("EVT-ps", "powershell.exe",
                          "powershell.exe -EncodedCommand <DEMO_ONLY>", offset=0),
            file_event("EVT-file", offset=120),
        ]
    )
    process_alerts = detections.detect_encoded_powershell(events)
    alerts = detections.detect_post_execution_file_activity(events, process_alerts)

    assert len(alerts) == 1
    # Both the process and the file are kept as evidence.
    assert alerts[0]["evidence_count"] == 2


def test_file_creation_outside_the_window_does_not_fire():
    events = make_frame(
        [
            process_event("EVT-ps", "powershell.exe",
                          "powershell.exe -EncodedCommand <DEMO_ONLY>", offset=0),
            file_event("EVT-file", offset=3600),
        ]
    )
    process_alerts = detections.detect_encoded_powershell(events)
    assert detections.detect_post_execution_file_activity(events, process_alerts) == []


def test_file_creation_on_another_host_does_not_fire():
    events = make_frame(
        [
            process_event("EVT-ps", "powershell.exe",
                          "powershell.exe -EncodedCommand <DEMO_ONLY>", offset=0),
            file_event("EVT-file", offset=120, host="WS-009"),
        ]
    )
    process_alerts = detections.detect_encoded_powershell(events)
    assert detections.detect_post_execution_file_activity(events, process_alerts) == []


def test_file_creation_without_a_flagged_process_does_not_fire():
    events = make_frame([file_event("EVT-file", offset=120)])
    assert detections.detect_post_execution_file_activity(events, []) == []


def test_post_execution_window_is_configurable():
    events = make_frame(
        [
            process_event("EVT-ps", "powershell.exe",
                          "powershell.exe -EncodedCommand <DEMO_ONLY>", offset=0),
            file_event("EVT-file", offset=1200),
        ]
    )
    process_alerts = detections.detect_encoded_powershell(events)
    assert detections.detect_post_execution_file_activity(events, process_alerts, window_minutes=30)
    assert detections.detect_post_execution_file_activity(events, process_alerts, window_minutes=5) == []


# --------------------------------------------------------------------------
# Engine behaviour
# --------------------------------------------------------------------------


def test_full_storyline_fires_every_rule(storyline_events):
    alerts = detections.run_detections(storyline_events)
    assert set(alerts["rule_id"]) == set(detections.RULES)


def test_quiet_activity_raises_nothing(quiet_events):
    assert detections.run_detections(quiet_events).empty


def test_detection_is_repeatable(storyline_events):
    """Same events in, same alert ids out - so re-running is safe."""
    first = detections.run_detections(storyline_events)
    second = detections.run_detections(storyline_events)
    assert first["alert_id"].tolist() == second["alert_id"].tolist()


def test_every_alert_carries_evidence(storyline_events):
    alerts = detections.run_detections(storyline_events)
    assert (alerts["evidence_count"] > 0).all()
    assert alerts["evidence_event_ids"].str.len().gt(0).all()


def test_evidence_ids_refer_to_real_events(storyline_events):
    alerts = detections.run_detections(storyline_events)
    known = set(storyline_events["event_id"])
    for value in alerts["evidence_event_ids"]:
        assert set(value.split(",")).issubset(known)


def test_alerts_use_the_defined_severity_scale(storyline_events):
    alerts = detections.run_detections(storyline_events)
    assert set(alerts["severity"]).issubset(set(schemas.SEVERITY_ORDER))


def test_empty_input_produces_an_empty_typed_frame():
    alerts = detections.run_detections(make_frame([]))
    assert alerts.empty
    assert list(alerts.columns) == list(schemas.ALERT_COLUMNS)


def test_every_rule_documents_its_false_positives():
    """Metadata is part of the rule, not an afterthought."""
    for rule in detections.RULES.values():
        assert rule.description
        assert rule.logic
        assert rule.inputs
        assert rule.false_positives
        assert rule.severity in schemas.SEVERITY_ORDER


def test_mitre_labels_resolve_to_known_techniques():
    for rule in detections.RULES.values():
        if rule.technique_id:
            assert rule.technique_id in schemas.MITRE_TECHNIQUES
            assert rule.technique_name
            assert rule.tactic


def test_rule_catalogue_covers_every_rule():
    catalogue = detections.rule_catalogue()
    assert set(catalogue["rule_id"]) == set(detections.RULES)


# --------------------------------------------------------------------------
# RULE-002 matching internals
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "process_name,expected",
    [
        ("powershell.exe", True),
        ("PowerShell.EXE", True),
        ("pwsh.exe", True),
        (r"C:\Windows\System32\powershell.exe", True),
        ("/usr/bin/pwsh.exe", True),
        # A different program whose name merely contains the real one.
        ("notpowershell.exe", False),
        ("powershell.exe.bak", False),
        ("powershell", False),
        ("", False),
        (None, False),
    ],
)
def test_powershell_binary_is_matched_on_the_file_name(process_name, expected):
    assert detections._is_powershell(process_name) is expected


@pytest.mark.parametrize(
    "token,expected",
    [
        # PowerShell resolves any unambiguous prefix to the full switch name.
        ("-EncodedCommand", True),
        ("-encodedcommand", True),
        ("-enc", True),
        ("-e", True),
        ("-E", True),
        ("-EncodedCommand:abc", True),
        ("/enc", True),
        # Not prefixes of the switch.
        ("-ec", False),
        ("-encx", False),
        ("-File", False),
        ("-NoProfile", False),
        ("--enc", False),
        ("e", False),
        ("-", False),
        ("", False),
    ],
)
def test_encoded_switch_is_matched_as_a_whole_token(token, expected):
    assert detections._is_encoded_switch(token) is expected


def test_switch_inside_a_quoted_argument_does_not_fire():
    """A quoted string containing "-e" is an argument, not a switch.

    Splitting on whitespace alone treats it as one, which fires RULE-002 on an
    ordinary command.
    """
    events = make_frame(
        [
            process_event(
                "EVT-ps",
                "powershell.exe",
                'powershell.exe -Command "Write-Host \'a -e b\'"',
            )
        ]
    )
    assert detections.detect_encoded_powershell(events) == []


def test_real_switch_after_a_quoted_value_still_fires():
    """A quoted value must not swallow the switches that follow it."""
    events = make_frame(
        [
            process_event(
                "EVT-ps",
                "powershell.exe",
                r'powershell.exe -ExecutionPolicy "Bypass" -e ABC',
            )
        ]
    )
    assert len(detections.detect_encoded_powershell(events)) == 1


def test_switch_after_a_terminating_parameter_does_not_fire():
    """-File and -Command hand the rest of the line to the script.

    PowerShell stops reading its own parameters at that point, so a later
    "-e" is an argument to the script - not a request to run an encoded
    command - and treating it as one is a false positive.
    """
    events = make_frame(
        [
            process_event("EVT-a", "powershell.exe",
                          "powershell.exe -File run.ps1 -e prod"),
            process_event("EVT-b", "powershell.exe",
                          "powershell.exe -Command Invoke-Thing -e prod"),
        ]
    )
    assert detections.detect_encoded_powershell(events) == []


def test_unbalanced_quotes_do_not_crash_the_rule():
    """Malformed input must not make the rule blind or raise."""
    events = make_frame(
        [
            process_event("EVT-a", "powershell.exe", 'powershell.exe -Command "oops'),
            process_event("EVT-b", "powershell.exe", 'powershell.exe -enc "oops'),
        ]
    )
    fired = {a["event_id"] for a in detections.detect_encoded_powershell(events)}
    assert fired == {"EVT-b"}


def test_switch_like_text_in_an_unrelated_argument_does_not_fire():
    events = make_frame(
        [
            process_event(
                "EVT-ps",
                "powershell.exe",
                "powershell.exe -File run.ps1 -Environment prod",
            )
        ]
    )
    assert detections.detect_encoded_powershell(events) == []
