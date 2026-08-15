"""SPEC §4.3.4 / weekly plan W6's explicitly required test: "serialize toàn
bộ object mà Hypothesis Engine và Exploit Agent tạo ra (hypothesis, action
plan, log) → assert không object nào chứa giá trị marker của lượt chạy đó."

This is a leakage check, not a functional test of Hypothesis/ActionPlan
themselves (those are covered elsewhere). It exists because the blind
marker's entire value depends on Exploit Agent/any LLM never seeing it
(SPEC's own table: Hypothesis Engine and Exploit Agent/every LLM are the two
components explicitly marked "Không" for knowing the marker) — if it ever
leaked into a prompt or a stored Hypothesis/ActionPlan, an LLM could learn to
reflect it back without the target ever having done so, producing a false
CONFIRMED.
"""

import json

from evidence_harness.harness import EvidenceHarness
from exploit_agent.agent import ExploitAgent
from hypothesis_engine.llm_client.fake_client import FakeLLMClient
from tests.factories import sample_hypothesis

_VALID_PLAN_RESPONSE = json.dumps(
    {
        "plannable": True,
        "actions": [
            {
                "type": "read_only",
                "method": "GET",
                "target": "https://staging.example.com/api/objects/42",
                "description": "Read object 42 as owner identity.",
            },
        ],
    }
)


def test_marker_absent_from_hypothesis_and_action_plan_and_llm_prompt(tmp_path):
    harness = EvidenceHarness(
        execution_id="exec_isolation_test",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path),
    )
    marker = harness.generate_marker()

    hypothesis = sample_hypothesis()
    llm_client = FakeLLMClient(responses=[_VALID_PLAN_RESPONSE])
    agent = ExploitAgent(llm_client)
    plan_result = agent.plan(hypothesis)

    serialized_hypothesis = hypothesis.model_dump_json()
    serialized_plan_result = plan_result.model_dump_json()
    # The literal prompt text sent to the LLM — the strongest check, since
    # this is exactly what an LLM would need to see to ever reflect the
    # marker back without the target having done anything.
    sent_prompts = "\n".join(llm_client.calls)

    assert marker not in serialized_hypothesis
    assert marker not in serialized_plan_result
    assert marker not in sent_prompts
