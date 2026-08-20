import argparse

from context_store.store import DEFAULT_DB_PATH
from shared.kill_switch import AutomaticThresholdReason, StopSource
from shared.models.verification_package import Environment, ReviewDecision

from cli.commands.assemble_package import cmd_assemble_package
from cli.commands.execute import cmd_execute
from cli.commands.hypothesize import cmd_hypothesize
from cli.commands.kill import cmd_kill
from cli.commands.mark_stale import cmd_mark_stale
from cli.commands.measure import cmd_measure
from cli.commands.normalize import cmd_normalize
from cli.commands.plan import cmd_plan
from cli.commands.report import cmd_report
from cli.commands.resume import cmd_resume
from cli.commands.retest import cmd_retest
from cli.commands.review_package import cmd_review_package
from cli.commands.show_hypothesis import cmd_show_hypothesis

DEFAULT_EVIDENCE_STORAGE_DIR = ".secweave/evidence"


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signal", required=True, help="Đường dẫn tới report JSON thô")
    parser.add_argument("--tool", required=True, choices=["semgrep", "trivy", "owasp_zap"])
    parser.add_argument("--tool-version", required=True, help="Version của tool đã sinh report")
    parser.add_argument("--coverage", default="unknown", choices=["complete", "partial", "unknown"])


def _add_context_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--context-db", default=DEFAULT_DB_PATH, help="Đường dẫn file SQLite Context Store (mặc định: %(default)s)"
    )


def _add_format_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", default="table", choices=["table", "json"])


def _add_llm_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--llm-mode",
        default="api",
        choices=["api", "agent"],
        help="api (mặc định, cần LLM_API_KEY/LLM_BASE_URL/LLM_MODEL) | "
        "agent (không cần API key, bắc cầu qua file để agent đang chat xử lý)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secweave", description="SecWeave controlled verification toolkit (MVP)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Chuẩn hoá 1 report thô (Semgrep/Trivy/OWASP ZAP) thành NormalizedSignal",
    )
    _add_report_args(normalize_parser)
    _add_format_arg(normalize_parser)
    normalize_parser.set_defaults(func=cmd_normalize)

    hypothesize_parser = subparsers.add_parser(
        "hypothesize",
        help="Sinh Hypothesis từ 1 report thô — dùng LLM API thật, hoặc bắc cầu qua agent (--llm-mode)",
    )
    _add_report_args(hypothesize_parser)
    hypothesize_parser.add_argument("--source", help="Đường dẫn file source code liên quan (tuỳ chọn)")
    hypothesize_parser.add_argument("--target-id", help="target_id để tra verified context (tuỳ chọn)")
    hypothesize_parser.add_argument(
        "--target-revision-id",
        help="target_revision_id HIỆN TẠI của target — bắt buộc nếu có --target-id. Context Store chỉ "
        "trả về verified/unverified context đã ghi cho ĐÚNG revision này; context của revision khác "
        "coi như không có (SPEC §4.6 staleness — tránh dùng nhầm kết luận cũ sau khi target đổi code). "
        "PHẢI là 1 định danh bất biến, content-addressed (vd git SHA) — 1 nhãn có thể bị đổi ý nghĩa "
        "theo thời gian (tag bị move, số build tái sử dụng) sẽ vô hiệu hoá cơ chế chống stale này.",
    )
    _add_llm_mode_arg(hypothesize_parser)
    _add_format_arg(hypothesize_parser)
    _add_context_db_arg(hypothesize_parser)
    hypothesize_parser.set_defaults(func=cmd_hypothesize)

    plan_parser = subparsers.add_parser(
        "plan",
        help="Soạn Action Plan từ 1 Hypothesis đã lưu, rồi check qua Policy/Cost Service (chưa thực thi)",
    )
    plan_parser.add_argument(
        "--hypothesis-id", required=True, help="hypothesis_id đã lưu trong Context Store (từ `hypothesize`)"
    )
    plan_parser.add_argument(
        "--allowed-action",
        action="append",
        help='1 entry allowlist, dạng "METHOD https://host/path/{param} [params:key1,key2=regex]" — có '
        "thể lặp lại flag này nhiều lần để cấp nhiều entry. Không truyền = allowlist rỗng = mọi action "
        "đều bị chặn. Phần 'params:...' tuỳ chọn: liệt kê tên field được phép xuất hiện trong "
        "ActionSpec.parameters (query string hoặc JSON body) của action đó — không ghi thì mặc định "
        "action PHẢI có parameters rỗng, không phải 'cho phép tất cả'. Mỗi key có thể kèm "
        "'=regex' (vd 'userId=^[0-9]+$') để bắt buộc GIÁ TRỊ của key đó khớp pattern, không chỉ tên "
        "key — key không có '=regex' thì vẫn nhận mọi giá trị như trước.",
    )
    plan_parser.add_argument(
        "--cap", type=int, default=10, help="Cap số hành động dự kiến tối đa trong plan (mặc định: %(default)s)"
    )
    plan_parser.add_argument(
        "--target-id",
        help="target_id dự kiến sẽ execute lên — tuỳ chọn, chỉ dùng để CẢNH BÁO (không chặn) nếu khác "
        "với target_id lúc hypothesis này được sinh ra qua `hypothesize --target-id`.",
    )
    plan_parser.add_argument(
        "--target-revision-id",
        help="revision dự kiến sẽ execute lên — tuỳ chọn, dùng cùng --target-id để CẢNH BÁO nếu khác "
        "với revision lúc hypothesis này được sinh ra (SPEC §4.6 staleness — 1 tầng cao hơn "
        "verified_observations, không chặn vì retest lại 1 hypothesis cũ trên revision mới là quy "
        "trình hợp lệ, chỉ cần biết để cân nhắc, không cần chặn).",
    )
    _add_llm_mode_arg(plan_parser)
    _add_format_arg(plan_parser)
    _add_context_db_arg(plan_parser)
    plan_parser.set_defaults(func=cmd_plan)

    show_hypothesis_parser = subparsers.add_parser(
        "show-hypothesis",
        help="Tra cứu lại (các) hypothesis đã sinh trước đó, theo hypothesis_id hoặc signal_id",
    )
    show_hypothesis_group = show_hypothesis_parser.add_mutually_exclusive_group(required=True)
    show_hypothesis_group.add_argument(
        "--hypothesis-id", help="Tra đúng 1 hypothesis (chỉ có ở bản ghi status=hypothesis)"
    )
    show_hypothesis_group.add_argument(
        "--signal-id",
        help="Tra tất cả bản ghi (kể cả not_verifiable) sinh ra từ 1 signal_id",
    )
    _add_format_arg(show_hypothesis_parser)
    _add_context_db_arg(show_hypothesis_parser)
    show_hypothesis_parser.set_defaults(func=cmd_show_hypothesis)

    def _add_execute_common_args(parser: argparse.ArgumentParser) -> None:
        # Shared by `execute` and `retest` — a retest run needs the exact
        # same inputs execute does, just repeated N times with fresh
        # execution_ids (see retest_parser below).
        parser.add_argument(
            "--hypothesis-id", required=True, help="hypothesis_id đã lưu trong Context Store (từ `hypothesize`)"
        )
        parser.add_argument(
            "--plan-file",
            help="Dùng lại ĐÚNG plan đã `secweave plan --format json > file` lập và duyệt trước đó, thay "
            "vì gọi LLM lập plan MỚI (LLM không xác định — 2 lần gọi có thể ra 2 plan khác nhau cho cùng "
            "1 hypothesis). Không truyền cờ này thì vẫn lập plan mới như trước, tiện cho test nhanh 1 "
            "bước nhưng KHÔNG đảm bảo thực thi đúng plan đã xem qua `secweave plan`. Khớp SPEC §5.1: "
            "'Plan & dry-run' phải feed thẳng plan sang 'Execute', không lập lại giữa chừng.",
        )
        parser.add_argument(
            "--allowed-action",
            action="append",
            help='Giống hệt `plan --allowed-action` — 1 entry allowlist, dạng "METHOD https://host/path/'
            '{param} [params:key1,key2=regex]", lặp lại flag để cấp nhiều entry.',
        )
        parser.add_argument(
            "--cap",
            type=int,
            default=10,
            help="Cap số hành động — dùng CHUNG cho cả cost-check lúc lập plan lẫn CostService lúc thực "
            "thi thật (mặc định: %(default)s). LƯU Ý: mỗi action_id trong --capture-ui-for/"
            "--capture-ui-video-for THỰC SỰ khớp 1 action trong plan tính THÊM 1 hành động thực tế "
            "vào cap này cho MỖI flag (ngoài HTTP capture bình thường của chính action đó, và cả 2 "
            "flag cùng lúc trên 1 action tính THÊM 2, không phải 1) — plan duyệt qua `plan --cap` "
            "không biết trước 2 flag này (chỉ có ở execute/retest), nên cần tự cộng thêm khi ước "
            "lượng cap đủ dùng.",
        )
        parser.add_argument("--target-id", required=True, help="target_id ghi vào evidence")
        parser.add_argument(
            "--target-revision-id",
            required=True,
            help="target_revision_id ghi vào evidence — PHẢI là 1 định danh bất biến, content-addressed "
            "(vd git SHA), không được rỗng (SPEC §4.6 staleness dựa vào giả định này để lọc context).",
        )
        parser.add_argument(
            "--execution-id", help="Định danh execution (mặc định: tự sinh mới mỗi lần chạy)"
        )
        parser.add_argument(
            "--storage-dir",
            default=DEFAULT_EVIDENCE_STORAGE_DIR,
            help="Thư mục lưu evidence + kill-switch/cost audit log (mặc định: %(default)s)",
        )
        parser.add_argument(
            "--identity",
            default="anonymous",
            help="Identity mặc định — dùng cho mọi role KHÔNG có --role-identity riêng (mặc định: "
            "%(default)s)",
        )
        parser.add_argument(
            "--role-identity",
            action="append",
            help='1 entry ánh xạ role -> identity, dạng "ROLE=LABEL" (vd "positive_control=owner"). Lặp '
            "lại flag để khai nhiều role. ROLE phải là 1 trong main/positive_control/denied_control/setup "
            "(ActionSpec.role, do Exploit Agent gắn khi lập plan cho 1 kịch bản 3-role) — LABEL chỉ là "
            "tên identity, không phải credential thật (Exploit Agent không tự lấy credential, chỉ tự gắn "
            "role). Role không có entry riêng ở đây dùng --identity mặc định.",
        )
        parser.add_argument(
            "--identity-logins",
            help="Đường dẫn file JSON: {label: {method, target, parameters, description?, token_json_path?, "
            "token_header?, token_prefix?}} — mỗi label sẽ được harness.login() thật trước khi plan chạy, "
            "nếu label đó được --identity hoặc --role-identity tham chiếu tới. Label không có entry trong "
            "file này chạy KHÔNG đăng nhập (client mới, chưa có session) — vẫn là 1 identity hợp lệ (vd "
            "denied_control ẩn danh). Bỏ trống token_json_path cho target dùng session kiểu cookie.",
        )
        parser.add_argument(
            "--sensitive-param",
            action="append",
            help="Tên field trong ActionSpec.parameters (hoặc query string cùng tên trong target) mà GIÁ "
            "TRỊ không được ghi ra đĩa trong transcript bằng chứng — lặp lại flag để khai nhiều field "
            "(vd --sensitive-param password --sensitive-param api_key). Chỉ ảnh hưởng bản ghi lưu lại, "
            "không ảnh hưởng request thật đã gửi. Không truyền = không field nào được coi là nhạy cảm "
            "ngoài header Authorization/Cookie/Set-Cookie (luôn redact sẵn).",
        )
        parser.add_argument(
            "--capture-ui-for",
            action="append",
            help="action_id (từ ActionSpec.action_id trong plan) mà, NGOÀI HTTP capture bình thường, "
            "còn chụp thêm 1 screenshot thật qua Playwright (SPEC §4.3.2, kênh UI_CAPTURE) — lặp lại "
            "flag để khai nhiều action. Chỉ mang tính trình bày/đối chiếu cho con người, KHÔNG ảnh "
            "hưởng verdict (role luôn là setup, access_result luôn ambiguous — Oracle không phán "
            "quyết dựa trên ảnh). Mỗi action khai ở đây tính THÊM 1 hành động thực tế vào --cap (xem "
            "--cap). Cần cài riêng `playwright` (pip install playwright && playwright install "
            "chromium) — kiểm tra ngay từ đầu, trước khi gửi bất kỳ action thật nào, nếu thiếu thì "
            "báo lỗi sạch thay vì crash giữa chừng.",
        )
        parser.add_argument(
            "--capture-ui-video-for",
            action="append",
            help="Giống hệt --capture-ui-for nhưng quay 1 video ngắn (SPEC §4.3.2's phần 'screen "
            "recording' của cùng kênh UI_CAPTURE) thay vì chụp ảnh tĩnh — lặp lại flag để khai nhiều "
            "action, dùng CẢ HAI flag cho cùng 1 action_id nếu muốn có cả ảnh lẫn video. Cũng tính "
            "THÊM 1 hành động thực tế vào --cap cho MỖI flag (dùng cả 2 flag cho cùng 1 action tính "
            "THÊM 2, không phải 1). Video chỉ quay được phần VIEWPORT (giới hạn của Playwright), khác "
            "với ảnh chụp toàn trang.",
        )
        parser.add_argument(
            "--capture-ui-video-seconds",
            type=float,
            default=1.5,
            help="Số giây quay video SAU KHI trang tải xong, áp dụng cho MỌI action trong "
            "--capture-ui-video-for (mặc định: %(default)s giây) — tăng lên nếu trang cần thời gian "
            "ổn định lâu hơn (animation, nội dung tải bất đồng bộ) trước khi hình ảnh đáng để làm "
            "bằng chứng.",
        )
        _add_llm_mode_arg(parser)
        _add_context_db_arg(parser)

    execute_parser = subparsers.add_parser(
        "execute",
        help="Thực thi THẬT các action đã approve của 1 plan (nối KillSwitch/CostService/"
        "EvidenceHarness) — SẼ GỬI REQUEST THẬT, chỉ chạy khi thực sự được phép trên target đó",
    )
    _add_execute_common_args(execute_parser)
    execute_parser.set_defaults(func=cmd_execute)

    retest_parser = subparsers.add_parser(
        "retest",
        help="Chạy lại CÙNG 1 plan đã đóng băng nhiều lần độc lập (SPEC §8.1: reproducibility) — đo tỷ "
        "lệ cùng verdict, KHÔNG được tự chọn lần 'đẹp nhất' để báo cáo",
    )
    _add_execute_common_args(retest_parser)
    retest_parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Số lần chạy lại độc lập (mặc định: %(default)s — SPEC §8.1 đề xuất tối thiểu 3, ngưỡng "
        "đạt yêu cầu đề xuất là >= 2/3 lần cùng verdict). Mỗi lần dùng 1 execution_id riêng, KHÔNG dùng "
        "chung kill-switch/cost — reset hoàn toàn giữa các lần để đo đúng khả năng lặp lại của HỆ "
        "THỐNG, không phải cộng dồn ngân sách qua nhiều lần.",
    )
    _add_format_arg(retest_parser)
    retest_parser.set_defaults(func=cmd_retest)

    kill_parser = subparsers.add_parser(
        "kill",
        help="Dừng 1 execution đang chạy — gọi được từ process/terminal khác với process đang chạy "
        "`execute` (SPEC §6.3: 5 nguồn người + 1 ngưỡng tự động)",
    )
    kill_parser.add_argument("--execution-id", required=True, help="execution_id cần dừng")
    kill_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Phải TRÙNG --storage-dir đã dùng khi `execute` execution này (mặc định: %(default)s)",
    )
    kill_parser.add_argument(
        "--source",
        required=True,
        choices=[s.value for s in StopSource],
        help="Nguồn dừng (SPEC §6.3)",
    )
    kill_parser.add_argument("--reason", required=True, help="Lý do dừng (ghi vào audit log)")
    kill_parser.add_argument("--actor", help="Người/hệ thống thực hiện lệnh dừng (tuỳ chọn)")
    kill_parser.add_argument(
        "--automatic-threshold-reason",
        choices=[r.value for r in AutomaticThresholdReason],
        help="BẮT BUỘC nếu --source=automatic_threshold — 1 trong 5 điều kiện SPEC §6.3",
    )
    kill_parser.set_defaults(func=cmd_kill)

    resume_parser = subparsers.add_parser(
        "resume",
        help="Đưa 1 execution đã STOPPED quay lại RUNNING — đường DUY NHẤT (SPEC §6.4 control #10), "
        "cần thiết để `execute` lại sau khi bị `kill`",
    )
    resume_parser.add_argument("--execution-id", required=True, help="execution_id cần resume")
    resume_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Phải TRÙNG --storage-dir đã dùng khi `execute`/`kill` execution này (mặc định: %(default)s)",
    )
    resume_parser.add_argument("--actor", help="Người/hệ thống thực hiện lệnh resume (tuỳ chọn)")
    resume_parser.add_argument(
        "--authorization-reference",
        required=True,
        help="Mô tả phê duyệt thật đã cho phép resume (vd 'owner re-approved qua email lúc ...') — "
        "bắt buộc ở mức CLI để không resume() mà không ghi lại lý do thật, dù bản thân "
        "KillSwitch.resume() cho phép để trống",
    )
    resume_parser.set_defaults(func=cmd_resume)

    assemble_package_parser = subparsers.add_parser(
        "assemble-package",
        help="Lắp Verification Package (SPEC §7) từ artifact thật của 1 lượt `execute` đã chạy — đọc "
        "lại observations.jsonl/actions.json/execution_status.json, không cần --plan-file gốc",
    )
    assemble_package_parser.add_argument("--execution-id", required=True, help="execution_id đã `execute`")
    assemble_package_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Phải TRÙNG --storage-dir đã dùng khi `execute` execution này (mặc định: %(default)s)",
    )
    assemble_package_parser.add_argument("--target-id", required=True, help="target_id — trường #2 SPEC §7")
    assemble_package_parser.add_argument(
        "--target-revision-id", required=True, help="Dùng làm revision — trường #4 SPEC §7"
    )
    assemble_package_parser.add_argument(
        "--environment",
        required=True,
        choices=[e.value for e in Environment],
        help="Trường #3 SPEC §7 — target không bao giờ được là production (NX-GO-02)",
    )
    assemble_package_parser.add_argument(
        "--authorization-reference",
        required=True,
        help="Mô tả phê duyệt thật đã cho phép lượt chạy này (trường #5 SPEC §7) — bắt buộc, không có "
        "giá trị mặc định, vì đây là phán đoán của con người không tự sinh được",
    )
    assemble_package_parser.add_argument(
        "--scenario", required=True, help="Mô tả kịch bản đã kiểm chứng (trường #6 SPEC §7) — bắt buộc"
    )
    assemble_package_parser.add_argument(
        "--limitations",
        required=True,
        help="Giới hạn thật của lượt chạy này (trường #17 SPEC §7, 'nên đọc đầu tiên') — bắt buộc",
    )
    assemble_package_parser.add_argument(
        "--next-action", required=True, help="Bước tiếp theo đề xuất (trường #18 SPEC §7) — bắt buộc"
    )
    _add_format_arg(assemble_package_parser)
    assemble_package_parser.set_defaults(func=cmd_assemble_package)

    review_package_parser = subparsers.add_parser(
        "review-package",
        help="Gate 4 — Human Review Loop tối thiểu (SPEC §4.5): gắn quyết định review của con người "
        "vào 1 Verification Package đã lắp qua `assemble-package`",
    )
    review_package_parser.add_argument(
        "--package-file", required=True, help="File JSON của package đã lắp (`assemble-package --format json`)"
    )
    review_package_parser.add_argument("--reviewer", required=True, help="Tên/định danh người review")
    review_package_parser.add_argument(
        "--decision", required=True, choices=[d.value for d in ReviewDecision], help="Quyết định của người review"
    )
    review_package_parser.add_argument(
        "--reason", required=True, help="Lý do cho quyết định — bắt buộc kể cả khi release"
    )
    review_package_parser.add_argument(
        "--checked-raw-artifact",
        action="store_true",
        help="Xác nhận ĐÃ tự tay đối chiếu ít nhất 1 raw evidence reference (in ra ở stderr) với "
        "normalized observation tương ứng (SPEC §4.5) — decision=release bắt buộc phải có cờ này",
    )
    review_package_parser.add_argument(
        "--retest-reference", help="Tham chiếu tới lượt retest (nếu decision=retest) — tuỳ chọn"
    )
    _add_format_arg(review_package_parser)
    _add_context_db_arg(review_package_parser)
    review_package_parser.set_defaults(func=cmd_review_package)

    mark_stale_parser = subparsers.add_parser(
        "mark-stale",
        help="SPEC §4.6 — đánh dấu cũ toàn bộ context đã lưu (verified + unverified) cho 1 target_id, "
        "vd sau khi biết revision đã đổi nhưng chưa xác định được phạm vi ảnh hưởng chính xác",
    )
    mark_stale_parser.add_argument("--target-id", required=True, help="target_id cần đánh dấu cũ")
    mark_stale_parser.add_argument(
        "--reason", required=True, help="Lý do đánh dấu cũ (SPEC §4.6: 'lý do một mẩu ngữ cảnh bị đánh dấu là cũ')"
    )
    _add_context_db_arg(mark_stale_parser)
    mark_stale_parser.set_defaults(func=cmd_mark_stale)

    measure_parser = subparsers.add_parser(
        "measure",
        help="SPEC §8.1 — gộp báo cáo các chỉ số đo được (schema completeness, ECS, reproducibility, "
        "control effectiveness, khả năng bàn giao) từ artifact thật của các lệnh khác, mỗi input tuỳ "
        "chọn",
    )
    measure_parser.add_argument(
        "--package-file", help="File JSON VerificationPackage (`assemble-package --format json`) — cho schema completeness"
    )
    measure_parser.add_argument(
        "--retest-summary", help="File tóm tắt do `secweave retest` sinh ra — cho reproducibility"
    )
    measure_parser.add_argument(
        "--execution-id", help="execution_id đã `execute` — cho control effectiveness"
    )
    measure_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Phải TRÙNG --storage-dir đã dùng khi `execute`/`retest` các execution liên quan (mặc "
        "định: %(default)s)",
    )
    measure_parser.add_argument(
        "--allowed-action",
        action="append",
        help='Giống hệt `plan --allowed-action` — 1 entry allowlist, dạng "METHOD https://host/path/'
        '{param} [params:key1,key2=regex]", lặp lại để cấp nhiều entry. Dùng để đối chiếu lại actions.json '
        "của --execution-id: action nào KHÔNG khớp bất kỳ entry nào được liệt vào "
        "actions_outside_allowlist (kỳ vọng SPEC §6.4: luôn là 0).",
    )
    _add_format_arg(measure_parser)
    measure_parser.set_defaults(func=cmd_measure)

    report_parser = subparsers.add_parser(
        "report",
        help="Render 1 VerificationPackage đã lắp thành 1 file Markdown đọc được trực tiếp (SPEC §7), "
        "thay vì JSON thô — không tính lại gì, chỉ trình bày lại",
    )
    report_parser.add_argument(
        "--package-file", required=True, help="File JSON của package đã lắp (`assemble-package --format json`)"
    )
    report_parser.add_argument(
        "--out", help="Đường dẫn file .md để ghi ra — không truyền thì in thẳng ra stdout"
    )
    report_parser.set_defaults(func=cmd_report)

    return parser
