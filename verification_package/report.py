"""Renders a `VerificationPackage` (SPEC §7) as a Markdown document a human
who isn't a SecWeave engineer can read directly — the CLI's other outputs
(`assemble-package --format json`, `--format table`) are either a raw 19-
field JSON blob or a 4-line terminal summary, neither meant to be handed to
a Sponsor/owner as the actual deliverable (SPEC §7: "hợp đồng đầu ra của
toàn hệ thống"). This module doesn't compute anything new — every value
here already exists in `package`; it only chooses an order and layout.

SPEC field #17 (Limitations) is deliberately rendered right after the
verdict, before any other detail — SPEC's own words: "trường nên đọc đầu
tiên ... để package không bị đọc rộng hơn phạm vi nó thực sự chứng minh."

`action_record` (field #9) is rendered with its `parameters` AS-IS, not
redacted here — those values are the plan's own recorded intent, not a
raw evidence transcript (redaction, SPEC §4.3.5, applies to the raw
artifact `capture()` writes, a different object entirely — see
evidence_harness/harness.py's module docstring). Field #9 exists so the
run is "đủ để lặp lại" (sufficient to reproduce), which for something like
a login step requires the real value, not a placeholder — silently
redacting here would misrepresent the record without actually protecting
anything (the same raw value already sits in the package's own JSON, which
this document is rendered FROM). A visible caveat is printed instead of a
guess at what to hide, matching this project's standing principle
(evidence_harness/harness.py's `_redact_body` docstring): never redact by
guessing at field names, only ever by explicit, caller-declared keys — and
no such declaration exists to apply after the fact here.
"""

from shared.models.verification_package import VerificationPackage

_CAVEAT = (
    "> ⚠ **Action record dưới đây giữ nguyên giá trị THẬT** (kể cả tham số của bước đăng nhập, nếu "
    "có) — SPEC field #9 yêu cầu action record \"đủ để lặp lại\", và tài liệu này không tự đoán trường "
    "nào cần che (nguyên tắc chung của dự án: chỉ che theo khai báo tường minh, không đoán theo tên "
    "trường). Cân nhắc kỹ trước khi chia sẻ tài liệu này ra ngoài nhóm vận hành trực tiếp."
)


def _escape_cell(value: object) -> str:
    """Keeps 1 Markdown table row on 1 physical line and stops a stray `|`
    in free text (a URL query string, an LLM-authored description) from
    silently truncating or misaligning the row."""
    text = str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def _bool_label(value: object) -> str:
    if value is None:
        return "—"
    return "có" if value else "không"


def render_markdown_report(package: VerificationPackage) -> str:
    lines: list[str] = []

    lines.append(f"# Verification Package — `{package.package_id}`")
    lines.append("")
    lines.append(f"**Verdict: {package.verdict.value.upper()}** — {package.verdict_reason}")
    lines.append("")
    lines.append("## Limitations (đọc trước tiên — SPEC field #17)")
    lines.append("")
    lines.append(package.limitations)
    lines.append("")

    lines.append("## Tóm tắt")
    lines.append("")
    lines.append(f"- **Target**: `{package.target_id}`")
    lines.append(f"- **Environment**: {package.environment.value}")
    lines.append(f"- **Revision**: `{package.revision}`")
    lines.append(f"- **Scenario**: {package.scenario}")
    lines.append(f"- **Execution ID**: `{package.execution_id}`")
    lines.append(f"- **Identities**: {', '.join(f'`{i}`' for i in package.identities)}")
    lines.append(f"- **Authorization reference**: {package.authorization_reference}")
    lines.append(f"- **Oracle rule version**: `{package.oracle_rule_version}`")
    lines.append("")

    lines.append("## Predicate results (SPEC §4.4.1)")
    lines.append("")
    lines.append("| Nhóm | Trạng thái | Lý do |")
    lines.append("|---|---|---|")
    for result in package.predicate_results:
        lines.append(
            f"| {result.group.value} | {result.status.value} | {_escape_cell(result.reason)} |"
        )
    if not package.predicate_results:
        lines.append("| _(không có predicate result nào — xem Limitations)_ | | |")
    lines.append("")

    lines.append(f"## Action record ({len(package.action_record)} hành động — SPEC field #9)")
    lines.append("")
    lines.append(_CAVEAT)
    lines.append("")
    lines.append("| # | Role | Method | Target | Mô tả | Parameters |")
    lines.append("|---|---|---|---|---|---|")
    for i, action in enumerate(package.action_record, start=1):
        lines.append(
            f"| {i} | {action.role.value} | {_escape_cell(action.method)} | {_escape_cell(action.target)} | "
            f"{_escape_cell(action.description)} | {_escape_cell(action.parameters)} |"
        )
    lines.append("")

    lines.append(
        f"## Normalized observations ({len(package.normalized_observations)} — SPEC field #12, "
        "kèm field #10/#11 vì luôn khớp 1:1)"
    )
    lines.append("")
    # `Channel` shown explicitly rather than left for a reader to infer
    # from `raw_evidence_ref`'s file extension — real gap found via
    # independent review: once UI_CAPTURE observations (screenshots/
    # videos, always role=setup/access_result=ambiguous) sit in the SAME
    # table as HTTP_TRANSACTION rows, distinguishing them by squinting at
    # a filename suffix is exactly the kind of implicit reading this
    # project's own reports avoid elsewhere.
    lines.append("| # | Role | Channel | Access result | Status code | Marker khớp? | Raw evidence ref | Hash |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, obs in enumerate(package.normalized_observations, start=1):
        marker = (
            "—"
            if obs.response_contains_marker is None and obs.request_contains_marker is None
            else f"response={_bool_label(obs.response_contains_marker)}, request={_bool_label(obs.request_contains_marker)}"
        )
        lines.append(
            f"| {i} | {obs.role.value} | {obs.channel.value} | {obs.access_result.value} | "
            f"{obs.status_code if obs.status_code is not None else '—'} "
            # `raw_evidence_hash` is NOT wrapped in a backtick code span like
            # elsewhere in this file — real gap found via independent
            # review: a value containing its own backtick would close the
            # span early, and (like every other free-text cell) it also
            # needs `_escape_cell` for the `|`/newline table-corruption risk
            # `_escape_cell`'s own docstring describes. Plain escaped text,
            # same styling as `raw_evidence_ref` right next to it, sidesteps
            # both failure modes at once instead of trying to escape
            # backticks INSIDE a code span (Markdown has no reliable way to
            # do that with a fixed single-backtick delimiter).
            f"| {marker} | {_escape_cell(obs.raw_evidence_ref)} | {_escape_cell(obs.raw_evidence_hash)} |"
        )
    lines.append("")

    lines.append("## Human review (SPEC §4.5, field #16)")
    lines.append("")
    if package.human_review_record is None:
        lines.append("_Chưa có review — package này là release candidate, chưa qua Gate 4._")
    else:
        review = package.human_review_record
        lines.append(f"- **Reviewer**: {review.reviewer}")
        lines.append(f"- **Thời điểm**: {review.reviewed_at.isoformat()}")
        lines.append(f"- **Quyết định**: {review.decision.value}")
        lines.append(f"- **Lý do**: {review.reason}")
        lines.append(f"- **Đã tự tay đối chiếu raw artifact**: {_bool_label(review.checked_raw_artifact)}")
    lines.append("")

    lines.append("## Retest reference (SPEC field #19)")
    lines.append("")
    lines.append(f"`{package.retest_reference}`" if package.retest_reference else "_Chưa có retest nào tham chiếu._")
    lines.append("")

    lines.append("## Bước tiếp theo đề xuất (SPEC field #18)")
    lines.append("")
    lines.append(package.next_action)
    lines.append("")

    missing = package.missing_fields_for_release()
    lines.append("## Trạng thái phát hành (binary schema completeness, SPEC §8.1)")
    lines.append("")
    if package.is_release_ready:
        lines.append("✅ **Đủ điều kiện phát hành** (đủ 19/19 trường bắt buộc).")
    else:
        lines.append("❌ **Chưa đủ điều kiện phát hành** — thiếu:")
        lines.append("")
        for field in missing:
            lines.append(f"- {field}")
    lines.append("")

    return "\n".join(lines)
