"""End-to-end integration test — proves the whole pipeline (Signal
Normalizer -> Hypothesis Engine -> Exploit Agent -> Evidence Harness ->
Verdict Oracle) wires together correctly with REAL logic at every tier.
Only the network layer (httpx.MockTransport) and the LLM (FakeLLMClient)
are test doubles — everything else is the actual production code path.

Real gap found via independent review (2026-08-17): every other test file
in this suite exercises exactly ONE tier in isolation. Nothing catches a
cross-tier field-shape mismatch (e.g. if Hypothesis.provenance.location's
shape changed and Exploit Agent's own consumption of it silently broke)
before it reached a real target. The only prior "whole pipeline" proof was
a one-off manual script run once against a live Juice Shop instance
(.secweave/manual_test/identity_scenario_example.py) — never part of the
automated regression suite, so a regression introduced after that one run
would never be caught again.

This test intentionally starts from raw scanner JSON (not a hand-built
NormalizedSignal) so Signal Normalizer's own parsing is exercised too, not
skipped — the only tier this test does NOT cover end-to-end is Context
Store persistence (cli.py wires that in separately; it's already covered
by tests/test_context_store.py and tests/test_cli.py on its own).
"""

import json

import httpx

from evidence_harness.harness import EvidenceHarness
from exploit_agent.agent import ExploitAgent
from hypothesis_engine.engine import HypothesisEngine
from hypothesis_engine.llm_client.fake_client import FakeLLMClient
from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter
from shared.models.action import ActionPlanStatus
from shared.models.hypothesis import HypothesisStatus
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import ObservationRole, Verdict
from shared.models.signal import RawReference, SignalCoverage
from tests.factories import sample_authorization
from verdict_oracle.oracle import decide

# ----- Tier 1 input: a minimal but realistic ZAP Traditional JSON report -----
_RAW_ZAP_REPORT = {
    "site": [
        {
            "@name": "https://staging.example.com",
            "alerts": [
                {
                    "pluginid": "10202",
                    "alert": "Insecure Direct Object Reference",
                    "riskcode": "3",
                    "riskdesc": "High (Medium)",
                    "cweid": "639",
                    "desc": "The object reference is not properly checked against the caller's identity.",
                    "instances": [
                        {"uri": "https://staging.example.com/api/objects/42", "method": "GET"}
                    ],
                }
            ],
        }
    ]
}

_HYPOTHESIS_RESPONSE = json.dumps(
    {
        "verifiable": True,
        "expected_behavior": "The API only returns object 42 to the identity that owns it.",
        "suspected_behavior": "The API returns object 42 to any authenticated identity, "
        "regardless of ownership.",
        "observation_criteria": "Compare GET /api/objects/42 for the owner vs a different identity.",
    }
)

_PLAN_RESPONSE = json.dumps(
    {
        "plannable": True,
        "actions": [
            {
                "type": "read_only",
                "method": "GET",
                "target": "https://staging.example.com/api/objects/42",
                "description": "Main: read object 42 as a non-owner identity via the suspected IDOR path.",
            },
            {
                "type": "read_only",
                "method": "GET",
                "target": "https://staging.example.com/api/objects/42",
                "description": "Positive control: the owner reads their own object 42.",
            },
            {
                "type": "read_only",
                "method": "GET",
                "target": "https://staging.example.com/api/objects/42",
                "description": "Denied control: a different, unrelated identity is correctly denied "
                "via the normal access path.",
            },
        ],
    }
)


def test_full_pipeline_from_raw_scanner_json_to_confirmed_verdict(tmp_path):
    # ----- Tier 1: Signal Normalizer (real ZapAdapter, real parsing) -----
    signals = ZapAdapter().parse(
        raw_report=_RAW_ZAP_REPORT,
        raw_reference=RawReference(storage_path="x", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.PARTIAL,
    )
    assert len(signals) == 1
    signal = signals[0]
    assert signal.location.url == "https://staging.example.com/api/objects/42"

    # ----- Tier 2: Hypothesis Engine (real logic, fake LLM) -----
    engine = HypothesisEngine(FakeLLMClient(responses=[_HYPOTHESIS_RESPONSE]))
    hypothesis_result = engine.generate_hypothesis(signal)
    assert hypothesis_result.status == HypothesisStatus.HYPOTHESIS
    hypothesis = hypothesis_result.hypothesis
    # provenance.location must carry the ORIGINAL signal's location through
    # unchanged — this is exactly the kind of cross-tier field a per-tier
    # test can't catch drifting, since Exploit Agent's anti-fabrication
    # check below depends on it still containing the real host.
    assert hypothesis.provenance.location.url == signal.location.url

    # ----- Tier 3: Exploit Agent (real logic, fake LLM) -----
    agent = ExploitAgent(FakeLLMClient(responses=[_PLAN_RESPONSE]))
    plan_result = agent.plan(hypothesis)
    assert plan_result.status == ActionPlanStatus.PLANNED
    plan = plan_result.plan
    assert len(plan.actions) == 3
    main_action, positive_action, denied_action = plan.actions

    authorization = sample_authorization(target_id="tgt_e2e", identity="test-identity-e2e")
    review = agent.review_plan(plan, authorization, cap=10)
    assert review.approved is True, review.plan_check.checks

    # ----- Tier 4a: Evidence Harness (real logic, mocked network) -----
    marker = "e2e-marker-deadbeef"
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) == 1:
            # main: the suspected IDOR path leaks the marker
            return httpx.Response(200, text=f"leaked object data containing {marker}")
        if len(calls) == 2:
            # positive_control: the owner reads their own data successfully
            return httpx.Response(200, json={"id": 42, "owner": "test-identity-e2e"})
        # denied_control: a different identity is correctly denied
        return httpx.Response(403, json={"error": "forbidden"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    harness = EvidenceHarness(
        execution_id="exec_e2e",
        target_id="tgt_e2e",
        target_revision_id="rev_e2e",
        storage_dir=str(tmp_path),
        http_client=client,
    )

    obs_main = harness.capture(main_action, role=ObservationRole.MAIN, marker=marker, identity="attacker")
    obs_positive = harness.capture(positive_action, role=ObservationRole.POSITIVE_CONTROL, identity="owner")
    obs_denied = harness.capture(denied_action, role=ObservationRole.DENIED_CONTROL, identity="attacker")
    harness.close()

    assert len(calls) == 3  # exactly the 3 approved actions were sent, nothing more/fewer

    # ----- Tier 4b: Verdict Oracle (real logic) -----
    result = decide([obs_main, obs_positive, obs_denied], execution_status=ExecutionStatus.COMPLETED)

    assert result.verdict == Verdict.CONFIRMED, result.reason
    by_group = {r.group: r.status for r in result.predicate_results}
    assert by_group[ObservationRole.MAIN].value == "satisfied"
    assert by_group[ObservationRole.POSITIVE_CONTROL].value == "satisfied"
    assert by_group[ObservationRole.DENIED_CONTROL].value == "satisfied"


def test_full_pipeline_stops_at_not_plannable_when_hypothesis_has_no_real_endpoint():
    # The pipeline's OTHER correct outcome: a hypothesis whose signal has no
    # usable network location (a pure SAST finding) must be refused at the
    # planning tier, never silently produce a network action out of nothing
    # — exercised here via the real SemgrepAdapter, not a hand-built signal.
    from hypothesis_engine.signal_normalizer.semgrep_adapter import SemgrepAdapter

    raw_report = {
        "results": [
            {
                "check_id": "python.django.security.audit.sqli",
                "path": "app/views.py",
                "start": {"line": 42},
                "end": {"line": 42},
                "extra": {
                    "message": "Potential SQL injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89"]},
                    "lines": "cursor.execute(query % user_id)",
                },
            }
        ]
    }
    signals = SemgrepAdapter().parse(
        raw_report=raw_report,
        raw_reference=RawReference(storage_path="x", hash="sha256:0"),
        tool_version="1.78.0",
        coverage=SignalCoverage.COMPLETE,
    )
    assert len(signals) == 1
    signal = signals[0]

    engine = HypothesisEngine(
        FakeLLMClient(
            responses=[
                json.dumps(
                    {
                        "verifiable": True,
                        "expected_behavior": "Queries are parameterized.",
                        "suspected_behavior": "user_id is interpolated directly into the SQL string.",
                        "observation_criteria": "Review the query construction at app/views.py:42.",
                    }
                )
            ]
        )
    )
    hypothesis_result = engine.generate_hypothesis(signal)
    assert hypothesis_result.status == HypothesisStatus.HYPOTHESIS

    # No URL anywhere in this hypothesis (SastLocation has no network
    # target) — a real agent asked to plan a network action here has
    # nothing legitimate to point at.
    agent = ExploitAgent(FakeLLMClient(responses=[json.dumps({"plannable": False, "reason": "no endpoint"})]))
    plan_result = agent.plan(hypothesis_result.hypothesis)
    assert plan_result.status == ActionPlanStatus.NOT_PLANNABLE
