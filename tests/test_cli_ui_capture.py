"""Real, non-mocked CLI-level tests for `execute --capture-ui-for` (SPEC
§4.3.2's UI_CAPTURE channel wired into the CLI) — a real local HTTP server
+ a real headless Chromium via Playwright, no MockTransport. Skips the
whole file cleanly if playwright isn't installed (see
evidence_harness/harness.py::capture_ui_state's own docstring for why this
is an optional capability).
"""

import http.server
import json
import threading
from pathlib import Path

import pytest

pytest.importorskip("playwright")

import cli


class _Handler(http.server.BaseHTTPRequestHandler):
    request_count = 0

    def do_GET(self):
        self.__class__.request_count += 1
        body = b"<html><body>secweave cli ui capture test page</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def real_server():
    _Handler.request_count = 0
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _plan_file(tmp_path, target: str, action_id: str) -> Path:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "hypothesis_id": "hyp_ui_capture_cli_test",
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": "hyp_ui_capture_cli_test",
                        "actions": [
                            {
                                "action_id": action_id,
                                "type": "read_only",
                                "method": "GET",
                                "target": target,
                                "description": "CLI UI capture sanity check.",
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return plan_path


def test_cli_execute_with_capture_ui_for_writes_a_real_screenshot(capsys, tmp_path, real_server):
    plan_path = _plan_file(tmp_path, real_server, "act_ui_test_1")

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_ui_capture_cli_test",
            "--plan-file",
            str(plan_path),
            "--allowed-action",
            f"GET {real_server}",
            "--capture-ui-for",
            "act_ui_test_1",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            "exec_ui_capture_cli_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            str(tmp_path / "context.db"),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "[ui-capture]" in captured.out

    execution_dir = tmp_path / "evidence" / "exec_ui_capture_cli_test"
    screenshots = list(execution_dir.glob("*_ui.png"))
    assert len(screenshots) == 1
    assert screenshots[0].read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    observation_lines = [
        json.loads(line)
        for line in (execution_dir / "observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    ui_observations = [o for o in observation_lines if o["channel"] == "ui_capture"]
    assert len(ui_observations) == 1
    assert ui_observations[0]["role"] == "setup"
    assert ui_observations[0]["access_result"] == "ambiguous"

    # Requesting the resource under test always sends 1 real HTTP GET
    # (via httpx, for the normal capture()) plus 1 more real navigation
    # (via Playwright, for the screenshot) — confirms the browser
    # genuinely hit the real server, not just the httpx-based capture.
    assert _Handler.request_count == 2


def test_cli_execute_only_captures_ui_for_the_declared_action_id(capsys, tmp_path, real_server):
    # A --capture-ui-for entry naming an action_id NOT in this plan must
    # not silently capture every action — the whole point is explicit,
    # per-action opt-in, not a blanket "capture everything" flag.
    plan_path = _plan_file(tmp_path, real_server, "act_ui_test_2")

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_ui_capture_cli_test",
            "--plan-file",
            str(plan_path),
            "--allowed-action",
            f"GET {real_server}",
            "--capture-ui-for",
            "act_some_other_action_not_in_this_plan",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            "exec_ui_capture_cli_test_2",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            str(tmp_path / "context.db"),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "[ui-capture]" not in captured.out
    # An entry that never matched anything must be flagged, not silently
    # cost nothing with no sign anything was wrong (e.g. a typo'd
    # action_id).
    assert "act_some_other_action_not_in_this_plan" in captured.err
    assert "CẢNH BÁO" in captured.err

    execution_dir = tmp_path / "evidence" / "exec_ui_capture_cli_test_2"
    assert list(execution_dir.glob("*_ui.png")) == []
    assert _Handler.request_count == 1  # only the normal HTTP capture, no browser navigation


def test_cli_execute_rejects_capture_ui_for_up_front_when_playwright_missing(capsys, monkeypatch, tmp_path, real_server):
    import cli.commands.execute as execute_module

    def _raise_not_installed():
        raise RuntimeError("capture_ui_state() cần package 'playwright' ... chưa cài trong môi trường này.")

    monkeypatch.setattr(execute_module, "verify_ui_capture_available", _raise_not_installed)
    plan_path = _plan_file(tmp_path, real_server, "act_ui_test_3")

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_ui_capture_cli_test",
            "--plan-file",
            str(plan_path),
            "--allowed-action",
            f"GET {real_server}",
            "--capture-ui-for",
            "act_ui_test_3",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            "exec_ui_capture_cli_test_3",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            str(tmp_path / "context.db"),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "playwright" in captured.err
    # Checked BEFORE any real action runs — the server must never have
    # been hit at all.
    assert _Handler.request_count == 0
