# SecWeave

Feasibility pilot nội bộ (CSP) để kiểm tra: có thể vận hành một quy trình xác minh security finding **có phép, có bằng chứng độc lập, có kết luận tất định và có ngữ cảnh tái sử dụng** hay không.

Kiến trúc bốn tầng tách quyền: **Hypothesis Engine** → **Exploit Agent** → **Evidence Harness & Store** → **Deterministic Verdict Oracle**, với Human Review và Security Context Store bao quanh. Nguyên tắc cốt lõi: *bên tạo ra giả thuyết không được tự chấm bài của mình*.

## Cài đặt

Yêu cầu Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` thành `.env`, điền `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` — dùng được bất kỳ provider nào tương thích chuẩn OpenAI Chat Completions (đã thử: Groq, Google Gemini). `.env` bị `.gitignore` chặn, không bao giờ commit được.

## Chạy test

```bash
pytest
```

## Dùng CLI

13 lệnh, dùng report mẫu có sẵn trong `tests/fixtures/` để thử ngay.

Các file mẫu trong `tests/fixtures/` là output **thật** (không tự viết tay) từ Semgrep/Trivy/OWASP ZAP chạy thật vào SecWeave/OWASP Juice Shop — xem chú thích trong từng file. Ví dụ dưới dùng `zap_sample_report.json` vì nó có URL thật, đi được hết cả 4 bước; `semgrep_sample_report.json`/`trivy_sample_report.json` là whitebox (SAST/SCA, không có URL) nên `plan` sẽ trả `NOT_PLANNABLE` — đúng hành vi mong đợi, không phải lỗi (xem `--tool` bên dưới để thử các file đó).

**1. Chuẩn hoá report thô thành `NormalizedSignal`** (không cần API key):
```bash
python -m cli normalize --signal tests/fixtures/zap_sample_report.json --tool owasp_zap --tool-version 2.17.0
```
`--tool` nhận `semgrep` / `trivy` / `owasp_zap`. Thêm `--format json` để lấy output JSON.

**2. Sinh `Hypothesis` từ report** (gọi LLM thật, cần `.env`):
```bash
python -m cli hypothesize --signal tests/fixtures/zap_sample_report.json --tool owasp_zap --tool-version 2.17.0 --context-db .secweave/context.db
```
Không có API key thì thêm `--llm-mode agent` để bắc cầu qua agent đang chat cùng bạn thay vì gọi API.

**3. Soạn `ActionPlan` từ 1 hypothesis đã lưu, kiểm duyệt qua allowlist** (chưa thực thi request thật nào):
```bash
python -m cli plan --hypothesis-id <hyp_...> \
  --allowed-action "GET http://host.docker.internal:3000" \
  --context-db .secweave/context.db
```
`--allowed-action` lặp lại được nhiều lần; không truyền gì = allowlist rỗng = mọi hành động bị chặn (deny-by-default). LLM thật không tất định — có lúc chỉ đề xuất 1 action (khớp allowlist trên → `APPROVED`), có lúc đề xuất thêm action khác (vd `OPTIONS`, hay `GET` kèm tham số `Origin`) không có trong allowlist → `BLOCKED`. **Cả 2 kết quả đều đúng** — `BLOCKED` không phải lỗi, đó chính là deny-by-default hoạt động đúng khi allowlist không phủ hết plan. Muốn chắc `APPROVED`, thêm allowlist entry khớp với action thực tế LLM vừa đề xuất (đọc từ output ngay phía trên).

**4. Tra lại hypothesis đã sinh:**
```bash
python -m cli show-hypothesis --hypothesis-id <hyp_...>
```

**5. Thực thi plan đã duyệt, thu bằng chứng thật (`execute`)** — SẼ GỬI REQUEST THẬT, chỉ chạy khi thực sự được phép trên target đó:
```bash
python -m cli execute --hypothesis-id <hyp_...> \
  --allowed-action "GET http://host.docker.internal:3000" \
  --target-id tgt_juiceshop --target-revision-id rev_local_docker \
  --execution-id exec_demo_1 \
  --storage-dir .secweave/evidence --context-db .secweave/context.db
```
In ra verdict cuối (thường `inconclusive` cho finding 1-role như trên — thiếu positive/denied control, đúng hành vi, không phải lỗi). Ghi lại `--execution-id` (tự đặt hoặc đọc dòng `-> execution_id:` nếu không truyền) để dùng ở bước 7.

Kịch bản đủ 3-role (main/positive_control/denied_control, nhiều identity thật qua `--role-identity`/`--identity-logins`, blind marker qua `{{SECWEAVE_BLIND_MARKER}}`, ID tài nguyên động qua `{{FROM_STEP:step_id:json_path}}`) — xem `execute --help` và ví dụ đầy đủ tại `.secweave/manual_test/identity_scenario_example.py`.

**6. Đo tính lặp lại — chạy lại ĐÚNG 1 plan nhiều lần độc lập (`retest`)** — tuỳ chọn, cần đóng băng plan trước:
```bash
python -m cli plan --hypothesis-id <hyp_...> \
  --allowed-action "GET http://host.docker.internal:3000" \
  --context-db .secweave/context.db --format json > plan.json

python -m cli retest --hypothesis-id <hyp_...> --plan-file plan.json \
  --allowed-action "GET http://host.docker.internal:3000" \
  --target-id tgt_juiceshop --target-revision-id rev_local_docker \
  --storage-dir .secweave/evidence --context-db .secweave/context.db --runs 3
```
`--plan-file` bắt buộc cho `retest` (khác `execute`, nơi nó tuỳ chọn) — để LLM tự lập lại plan mỗi lần sẽ lẫn "LLM không tất định" với "hệ thống không lặp lại được". In ra verdict của TỪNG lần, không có đường nào để chỉ báo cáo lần "đẹp nhất"; lưu 1 file tóm tắt JSON — `retest_id` bên trong dùng cho `--retest-reference` ở bước 8.

**7. Lắp Verification Package đủ 19 trường (`assemble-package`)**:
```bash
python -m cli assemble-package --execution-id exec_demo_1 \
  --storage-dir .secweave/evidence \
  --target-id tgt_juiceshop --target-revision-id rev_local_docker \
  --environment sandbox --authorization-reference auth_local_test_1 \
  --scenario "Cross-Domain Misconfiguration tại host.docker.internal:3000" \
  --limitations "Chỉ có role=main, thiếu positive/denied control." \
  --next-action "Không cần thêm — quan sát trực tiếp." \
  --format json > package.json
```

**8. Con người review, quyết định release (`review-package`)**:
```bash
python -m cli review-package --package-file package.json \
  --context-db .secweave/context.db \
  --reviewer "<tên người review>" --decision release \
  --reason "Đã đối chiếu raw evidence, khớp normalized observation." \
  --checked-raw-artifact
```
In ra danh sách raw evidence reference cần tự tay đối chiếu TRƯỚC khi chạy lệnh này — bắt buộc, không phải gợi ý. `decision=release` bắt buộc kèm `--checked-raw-artifact`; `--decision retest`/`reject` không cần. `release` thành công sẽ promote observation sang `verified` trong Context Store.

**9. Dừng khẩn 1 execution đang chạy, từ terminal KHÁC (`kill`)**:
```bash
python -m cli kill --execution-id exec_demo_1 --storage-dir .secweave/evidence \
  --source operator --reason "Phát hiện hành vi ngoài dự kiến, dừng ngay để kiểm tra."
```
`--source` nhận 1 trong 6 nguồn (`operator`/`target_owner`/`infra_owner`/`data_isms_owner`/`incident_responder`/`automatic_threshold` — nguồn cuối bắt buộc kèm `--automatic-threshold-reason`).

**10. Cho 1 execution đã STOPPED chạy lại (`resume`, đường DUY NHẤT)**:
```bash
python -m cli resume --execution-id exec_demo_1 --storage-dir .secweave/evidence \
  --authorization-reference "Owner đã duyệt lại qua email lúc 14:00 20/08/2026"
```

**11. Đánh dấu 1 verified fact trong Context Store là đã cũ (`mark-stale`)**:
```bash
python -m cli mark-stale --target-id tgt_juiceshop \
  --reason "Target đã đổi revision, ngữ cảnh cũ có thể không còn đúng." \
  --context-db .secweave/context.db
```

**12. Tổng hợp chỉ số vào 1 báo cáo (`measure`)**:
```bash
python -m cli measure \
  --package-file package.json \
  --retest-summary .secweave/evidence/exec_demo_1_retest_summary.json \
  --execution-id exec_demo_1 \
  --storage-dir .secweave/evidence \
  --allowed-action "GET https://host.docker.internal:3000/rest/user/whoami" \
  --format json
```
Mỗi input tuỳ chọn (đo được gì thì đo, không có gì báo N/A chứ không giả định) — không cần chạy đúng 1 lần với đủ cả 3, có thể gọi riêng lẻ để đo từng chỉ số. `--execution-id` không truyền thì `--allowed-action` bị bỏ qua (chỉ dùng để đối chiếu allowlist với `actions.json` của 1 execution cụ thể).

**13. Xuất Verification Package ra Markdown đọc được trực tiếp (`report`)**:
```bash
python -m cli report --package-file package.json --out report.md
```
Không truyền `--out` thì in thẳng ra stdout. Không tính lại gì — chỉ trình bày lại đúng 19 trường đã có trong package.

Mỗi lệnh có `--help` riêng để xem đầy đủ tuỳ chọn.

---

**Ghi chú:** dự án đang ở giai đoạn Chặng 1 (discovery/preparation), chưa có active run trên target thật ngoài môi trường demo cục bộ; 678/678 test pass. Đặc tả kỹ thuật đầy đủ nằm ở `SECWEAVE_SPEC.md`, kế hoạch triển khai theo tuần ở `SECWEAVE_WEEKLY_PLAN.md`, biểu mẫu Gate 2 ở `TARGET_SANDBOX_AUTHORIZATION_TEMPLATE.md`.

**Phân loại:** NTQ INTERNAL.
