"""Real, non-mocked tests for EvidenceHarness.capture_ui_state() (SPEC
§4.3.2's UI_CAPTURE channel) — Playwright drives a genuine headless
Chromium against a genuine local HTTP server, no MockTransport involved
(a screenshot of a mocked transport wouldn't prove anything about a real
browser actually rendering something). Skips the whole file cleanly if
playwright isn't installed, rather than failing the suite for anyone who
hasn't run `pip install playwright && playwright install chromium` — see
capture_ui_state()'s own docstring for why this is an optional capability.
"""

import http.server
import threading

import httpx
import pytest

pytest.importorskip("playwright")

from evidence_harness.harness import EvidenceHarness
from shared.cost import CostCapExceededError, CostService
from shared.kill_switch import ExecutionStoppedError, KillSwitch, StopSource
from shared.models.action import ActionSpec, ActionType
from shared.models.observation import AccessResult, EvidenceChannel, ObservationRole


class _Handler(http.server.BaseHTTPRequestHandler):
    seen_cookie_headers = []

    def do_GET(self):
        self.__class__.seen_cookie_headers.append(self.headers.get("Cookie"))
        body = b"<html><body><h1>secweave ui capture test page</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def real_server():
    _Handler.seen_cookie_headers = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _action(target: str, **overrides) -> ActionSpec:
    defaults = dict(
        type=ActionType.READ_ONLY,
        method="GET",
        target=target,
        description="UI capture test action.",
    )
    defaults.update(overrides)
    return ActionSpec(**defaults)


def _harness(tmp_path, **kwargs) -> EvidenceHarness:
    return EvidenceHarness(
        execution_id=kwargs.pop("execution_id", "exec_ui_test"),
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path),
        **kwargs,
    )


def test_capture_ui_state_writes_a_real_png_with_correct_hash_and_size(tmp_path, real_server):
    import hashlib
    from pathlib import Path

    harness = _harness(tmp_path)
    observation = harness.capture_ui_state(_action(real_server))

    png_path = Path(observation.raw_evidence_ref)
    assert png_path.exists()
    real_bytes = png_path.read_bytes()
    assert real_bytes[:8] == b"\x89PNG\r\n\x1a\n"  # real PNG file signature, not a stub
    assert len(real_bytes) > 0
    assert observation.raw_evidence_size_bytes == len(real_bytes)
    assert observation.raw_evidence_hash == "sha256:" + hashlib.sha256(real_bytes).hexdigest()


def test_capture_ui_state_returns_setup_role_and_ambiguous_access_result(tmp_path, real_server):
    harness = _harness(tmp_path)
    observation = harness.capture_ui_state(_action(real_server), identity="alice")

    assert observation.role == ObservationRole.SETUP
    assert observation.access_result == AccessResult.AMBIGUOUS
    assert observation.channel == EvidenceChannel.UI_CAPTURE
    assert observation.status_code is None
    assert observation.response_contains_marker is None
    assert observation.request_contains_marker is None
    assert observation.identity == "alice"
    assert observation.execution_id == "exec_ui_test"


def test_capture_ui_state_shares_the_identity_cookie_jar_with_the_real_browser(tmp_path, real_server):
    # The whole point of reusing the identity's httpx cookie jar: the
    # rendered page must reflect the SAME session an HTTP-based capture()
    # for this identity would have seen, not an anonymous view.
    client = httpx.Client()
    client.cookies.set("session_token", "alice-real-session-abc123", domain="127.0.0.1", path="/")
    harness = _harness(tmp_path, http_client_factory=lambda: client)

    harness.capture_ui_state(_action(real_server), identity="alice")

    assert any(
        header is not None and "session_token=alice-real-session-abc123" in header
        for header in _Handler.seen_cookie_headers
    )


def test_capture_ui_state_handles_a_cookie_with_no_domain_set(tmp_path, real_server):
    # Real gap found via independent review: client.cookies.set(name,
    # value) with NO domain= argument leaves cookie.domain == "" (not
    # None) — passed straight through to Playwright's add_cookies() as
    # domain="", this used to raise for the WHOLE cookie list (it's
    # all-or-nothing), silently dropping every cookie, not just the one
    # missing a domain. A pre-seeded session cookie with no explicit
    # domain is a realistic pattern for a caller using
    # http_client_factory, not a contrived edge case.
    client = httpx.Client()
    client.cookies.set("no_domain_cookie", "value-without-domain")
    harness = _harness(tmp_path, http_client_factory=lambda: client)

    observation = harness.capture_ui_state(_action(real_server), identity="alice")

    from pathlib import Path

    assert Path(observation.raw_evidence_ref).exists()
    assert any(
        header is not None and "no_domain_cookie=value-without-domain" in header
        for header in _Handler.seen_cookie_headers
    )


def test_capture_ui_state_still_screenshots_a_real_navigation_failure(tmp_path):
    # An unreachable port must not crash capture_ui_state() — Chromium
    # still renders its own error page, which is itself real evidence of
    # what a visitor would see (SPEC P2: evidence before assertion).
    harness = _harness(tmp_path)
    observation = harness.capture_ui_state(_action("http://127.0.0.1:1/"))  # nothing listens on port 1

    from pathlib import Path

    assert Path(observation.raw_evidence_ref).exists()
    assert observation.access_result == AccessResult.AMBIGUOUS


def test_capture_ui_state_respects_kill_switch_stopped(tmp_path, real_server):
    kill_switch = KillSwitch(execution_id="exec_ui_stop", storage_dir=str(tmp_path / "kill_switch"))
    kill_switch.start()
    kill_switch.stop(source=StopSource.OPERATOR, reason="test stop before UI capture")

    harness = _harness(tmp_path, execution_id="exec_ui_stop", kill_switch=kill_switch)

    with pytest.raises(ExecutionStoppedError):
        harness.capture_ui_state(_action(real_server))


def test_capture_ui_state_respects_cost_cap(tmp_path, real_server):
    cost_service = CostService(execution_id="exec_ui_cost", storage_dir=str(tmp_path / "cost"), cap=1)
    harness = _harness(tmp_path, execution_id="exec_ui_cost", cost_service=cost_service)

    harness.capture_ui_state(_action(real_server))
    with pytest.raises(CostCapExceededError):
        harness.capture_ui_state(_action(real_server))


def test_capture_ui_state_raises_a_clear_error_when_playwright_is_not_installed(tmp_path, monkeypatch):
    import evidence_harness.harness as harness_module

    def _raise_not_installed():
        raise RuntimeError(
            "capture_ui_state() cần package 'playwright' (pip install playwright && playwright "
            "install chromium) — chưa cài trong môi trường này."
        )

    monkeypatch.setattr(harness_module, "_sync_playwright", _raise_not_installed)
    harness = _harness(tmp_path)

    with pytest.raises(RuntimeError, match="playwright"):
        harness.capture_ui_state(_action("http://127.0.0.1:1/"))


def test_verify_ui_capture_available_raises_a_clean_error_when_chromium_binary_is_missing(monkeypatch, tmp_path):
    # Real gap found via independent review: the plain package-import
    # check alone (_sync_playwright) cannot tell `pip install playwright`
    # apart from `pip install playwright && playwright install
    # chromium` — the far more common real misconfiguration, since it's
    # a separate, easy-to-forget step. Pointing PLAYWRIGHT_BROWSERS_PATH
    # at an empty directory reproduces a genuinely missing Chromium
    # binary for real (not a monkeypatched stub) — pw.chromium.launch()
    # raises playwright's OWN Error type here, which must come back as a
    # clean RuntimeError, not propagate raw.
    from evidence_harness.harness import verify_ui_capture_available

    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty_browsers_dir"))

    with pytest.raises(RuntimeError, match="[Cc]hromium"):
        verify_ui_capture_available()


def test_capture_ui_state_converts_a_real_playwright_error_into_a_clean_runtime_error(monkeypatch, tmp_path):
    # Same underlying gap as above, but for capture_ui_state() itself
    # (not just the CLI's up-front check) — a genuinely broken Chromium
    # install must not crash with a raw playwright.sync_api.Error deep
    # inside a real execute() run.
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty_browsers_dir"))
    harness = _harness(tmp_path)

    with pytest.raises(RuntimeError, match="[Cc]hromium|Error"):
        harness.capture_ui_state(_action("http://127.0.0.1:1/"))


def test_capture_ui_recording_writes_a_real_webm_with_correct_hash_and_size(tmp_path, real_server):
    import hashlib
    from pathlib import Path

    harness = _harness(tmp_path)
    observation = harness.capture_ui_recording(_action(real_server), record_seconds=0.3)

    video_path = Path(observation.raw_evidence_ref)
    assert video_path.exists()
    assert video_path.suffix == ".webm"
    real_bytes = video_path.read_bytes()
    assert len(real_bytes) > 0
    assert real_bytes[:4] == b"\x1a\x45\xdf\xa3"  # real WebM/Matroska file signature
    assert observation.raw_evidence_size_bytes == len(real_bytes)
    assert observation.raw_evidence_hash == "sha256:" + hashlib.sha256(real_bytes).hexdigest()


def test_capture_ui_recording_leaves_no_scratch_files_behind(tmp_path, real_server):
    harness = _harness(tmp_path)
    harness.capture_ui_recording(_action(real_server), record_seconds=0.3)

    # Only the final, renamed .webm should remain directly under the
    # execution's storage dir — no leftover scratch directory/file from
    # Playwright's own auto-named video output.
    remaining = list(tmp_path.glob("exec_ui_test/*"))
    scratch_dirs = [p for p in remaining if p.is_dir()]
    assert scratch_dirs == []
    webm_files = [p for p in remaining if p.suffix == ".webm"]
    assert len(webm_files) == 1


def test_capture_ui_recording_returns_setup_role_and_ambiguous_access_result(tmp_path, real_server):
    harness = _harness(tmp_path)
    observation = harness.capture_ui_recording(_action(real_server), identity="alice", record_seconds=0.3)

    assert observation.role == ObservationRole.SETUP
    assert observation.access_result == AccessResult.AMBIGUOUS
    assert observation.channel == EvidenceChannel.UI_CAPTURE
    assert observation.status_code is None
    assert observation.identity == "alice"


def test_capture_ui_recording_shares_the_identity_cookie_jar_with_the_real_browser(tmp_path, real_server):
    client = httpx.Client()
    client.cookies.set("session_token", "alice-recording-session-xyz", domain="127.0.0.1", path="/")
    harness = _harness(tmp_path, http_client_factory=lambda: client)

    harness.capture_ui_recording(_action(real_server), identity="alice", record_seconds=0.3)

    assert any(
        header is not None and "session_token=alice-recording-session-xyz" in header
        for header in _Handler.seen_cookie_headers
    )


def test_capture_ui_recording_respects_kill_switch_stopped(tmp_path, real_server):
    kill_switch = KillSwitch(execution_id="exec_ui_recording_stop", storage_dir=str(tmp_path / "kill_switch"))
    kill_switch.start()
    kill_switch.stop(source=StopSource.OPERATOR, reason="test stop before UI recording")

    harness = _harness(tmp_path, execution_id="exec_ui_recording_stop", kill_switch=kill_switch)

    with pytest.raises(ExecutionStoppedError):
        harness.capture_ui_recording(_action(real_server))


def test_capture_ui_recording_respects_cost_cap(tmp_path, real_server):
    cost_service = CostService(execution_id="exec_ui_recording_cost", storage_dir=str(tmp_path / "cost"), cap=1)
    harness = _harness(tmp_path, execution_id="exec_ui_recording_cost", cost_service=cost_service)

    harness.capture_ui_recording(_action(real_server), record_seconds=0.3)
    with pytest.raises(CostCapExceededError):
        harness.capture_ui_recording(_action(real_server), record_seconds=0.3)


def test_capture_ui_recording_converts_a_real_playwright_error_into_a_clean_runtime_error(monkeypatch, tmp_path):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty_browsers_dir"))
    harness = _harness(tmp_path)

    with pytest.raises(RuntimeError, match="[Cc]hromium|Error"):
        harness.capture_ui_recording(_action("http://127.0.0.1:1/"))
