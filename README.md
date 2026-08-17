# SecWeave

Feasibility pilot nội bộ (CSP) để kiểm tra: có thể vận hành một quy trình xác minh security finding **có phép, có bằng chứng độc lập, có kết luận tất định và có ngữ cảnh tái sử dụng** hay không.

Kiến trúc bốn tầng tách quyền: **Hypothesis Engine** → **Exploit Agent** → **Evidence Harness & Store** → **Deterministic Verdict Oracle**, với Human Review và Security Context Store bao quanh. Nguyên tắc cốt lõi: *bên tạo ra giả thuyết không được tự chấm bài của mình*.

## Tài liệu

| File | Nội dung |
|---|---|
| [`SECWEAVE_SPEC.md`](./SECWEAVE_SPEC.md) | Đặc tả kiến trúc kỹ thuật: 4 tầng, mô hình dữ liệu, Verification Package, kiểm soát & an toàn |
| [`SECWEAVE_WEEKLY_PLAN.md`](./SECWEAVE_WEEKLY_PLAN.md) | Kế hoạch triển khai theo tuần (W1–W8), chiến lược test theo từng tầng |

## Trạng thái

Giai đoạn **Chặng 1 — Discovery/preparation**. Chưa có active run trên target nào. Xem điều kiện Gate 0–5 trong `SECWEAVE_SPEC.md` §6.

Đã chạy được thật (xem [Dùng CLI](#dùng-cli) dưới đây): Signal Normalizer (Semgrep/Trivy/OWASP ZAP), Hypothesis Engine, Exploit Agent (lập kế hoạch + tự kiểm duyệt qua allowlist — **chưa thực thi hành động thật**), Security Context Store. Evidence Harness (`evidence_harness/harness.py`) đã có bản lõi + blind marker + **identity/session thật theo từng identity**: mỗi identity có 1 `httpx.Client`/cookie-jar riêng, `login()` xử lý được cả session theo cookie lẫn bearer-token-trong-body (JWT — xác nhận thật với OWASP Juice Shop, `/rest/user/login` trả token trong JSON body chứ không phải cookie), tổng quát cho mọi target chứ không hard-code riêng cho web nào. Nhờ đó `positive_control`/`denied_control` giờ test được đúng nghĩa (2 tài khoản thật, cùng 1 resource) — đã dùng chính cơ chế này phát hiện lại đúng lỗ hổng IDOR thật của Juice Shop (tài khoản B đọc được basket của tài khoản A). Request/response headers (kể cả cookie/token) được redact trước khi ghi ra đĩa. Policy Service (`shared/policy.py`) kiểm cả `action.parameters` lẫn query string trong `target` (không chỉ path) — cú pháp allowlist `"METHOD url [params:key1,key2]"`.

**Verdict Oracle** (`verdict_oracle/oracle.py`+`predicates.py`) có predicate draft **và** bước gộp verdict cuối (`assemble_verdict`/`decide` — trả đúng 1 trong 3 `CONFIRMED`/`NOT_REPRODUCED`/`INCONCLUSIVE`), giờ enforce đủ 2 control SPEC không-ngoại-lệ tìm thấy còn thiếu qua audit toàn dự án (2026-08-16): (1) `execution_status` bắt buộc phải `COMPLETED` mới ra verdict cuối — STOPPED/RUNNING/... đều ép về INCONCLUSIVE (SPEC §3.4); (2) hash artifact được xác minh lại (đọc file thật, tính lại SHA-256) trước khi cho phép CONFIRMED — hash không khớp hoặc file không đọc được đều thành INSUFFICIENT_DATA (SPEC §6.4 control #8). Review thủ công 2026-08-17 (2 Agent review bị fail do hết session limit nên tự đọc code trực tiếp) tìm thêm 2 lỗi: hàm hash-check crash thay vì trả INSUFFICIENT_DATA nếu `raw_evidence_ref` chứa NUL byte (chưa khai thác được qua pipeline hiện tại, nhưng cùng dạng lỗi "except quá hẹp" đã gặp 2 lần trước); `VerdictResult` là model "quyết định an toàn" duy nhất chưa có validator tự kiểm tra tính nhất quán như 6 model khác cùng loại — giờ đã enforce `verdict=confirmed` bắt buộc cả 3 nhóm predicate đều `satisfied`.

**Kill-switch** (`shared/kill_switch.py`, SPEC §6.3/§5.3, weekly plan Tuần 6) đã có: `KillSwitch` là điểm dừng dùng chung cho 1 execution — 6 nguồn (`StopSource`: operator/target owner/infra owner/data-ISMS owner/incident responder/automatic threshold), gọi `stop()` từ bất kỳ nguồn nào cũng dừng ngay, không cần thương lượng trước, chạy đúng 1 lần cleanup (callable operator tự cung cấp — chưa có Gate 3 thật), ghi audit log JSONL (ai/khi nào/vì sao) tại `{storage_dir}/{execution_id}/kill_switch_audit_log.jsonl`. `resume()` là đường DUY NHẤT quay lại RUNNING — không có auto-resume/timer nào (đối chiếu với circuit-breaker pattern để tránh nhầm 2 khái niệm). `EvidenceHarness.capture()` nhận `kill_switch` optional, raise `ExecutionStoppedError` thay vì gửi request thật khi đã STOPPED — đây là kiểm tra trước-khi-gửi (cooperative), không ngắt ngang request đang bay giữa chừng. Đã qua 2 vòng review độc lập, cả 2 vòng đều tìm ra bug thật trong chính bản fix của vòng trước (status không phục hồi đúng khi tạo lại instance sau STOPPED; write audit log ngoài lock làm sai thứ tự khi so bằng physical file order — sửa bằng `sequence` số nguyên gán tại thời điểm chuyển trạng thái, không phụ thuộc lúc I/O thật sự chạy xong; log hỏng dòng cuối do crash giữa chừng làm `__init__` crash theo — sửa bằng fail-safe về STOPPED). `StopEvent` giờ có field `automatic_threshold_reason` cấu trúc (1 trong 5 điều kiện tự động ở SPEC §6.3) thay vì chỉ nhét vào `reason` dạng free-text — bắt buộc khi `source=automatic_threshold`, cấm khi không phải. Chưa có: nối kill-switch với CLI/API thật (xem hạn chế 2 lớp mô tả bên dưới).

**Cost Service thật** (`shared/cost.py::CostService`, SPEC P6/§6.4 control #9, weekly plan Tuần 6) đã có: đếm hành động THỰC TẾ đã thực thi qua `EvidenceHarness.capture()` (không chỉ dự kiến), lưu bền `cost_audit_log.jsonl` để sống sót qua restart, tự động gọi `kill_switch.stop(source=automatic_threshold, automatic_threshold_reason=action_count_exceeded)` và từ chối hành động sẽ vượt cap TRƯỚC khi gửi, không phải sau. Qua 1 vòng review độc lập ngay sau khi build (không đợi ai hỏi), tìm ra 4 lỗi thật: `KillSwitch.stop()` validate field mới quá trễ (sau khi đã flip status + chạy cleanup thật — sửa bằng validate ngay đầu hàm, trước mọi side effect); dòng log cuối bị crash dở dang (torn line) rồi bị merge với entry hợp lệ ghi sau đó, làm mất vĩnh viễn 1 hành động khỏi count qua lần restart thứ 2 (sửa bằng đảm bảo luôn xuống dòng trước khi ghi thêm); count trong bộ nhớ tăng trước khi ghi bền xuống đĩa, lệch vĩnh viễn nếu ghi lỗi (sửa bằng ghi trước, tăng count sau); cost check chạy trước `client.build_request()` nên 1 lỗi nội bộ của harness (không liên quan gì đến target) vẫn tiêu tốn 1 slot cost mà không có bằng chứng nào (sửa bằng dời check ra sau khi build_request() thành công). Cả 4 đã sửa, 2 lỗi rủi ro cao nhất có mutation-test, tổng 398 test pass.

Kill-switch nối CLI/API thật: xác nhận có 2 lớp hạn chế, chưa cái nào được giải quyết — (1) chưa có lệnh/entrypoint nào để trigger `stop()` từ ngoài process đang chạy; (2) quan trọng hơn, `KillSwitch._status` chỉ tồn tại trong bộ nhớ của 1 instance — 1 process khác gọi `stop()` trên audit log dùng chung chỉ ghi thêm dòng log, KHÔNG đổi được trạng thái của instance đang thực sự chạy active run, nên dù có lệnh CLI cũng chưa dừng được gì đang chạy giữa chừng nếu process đó không tự poll lại log.

**Hardening 2026-08-16** (audit toàn dự án tìm ra 9 lỗ hổng thật ở các tầng chưa từng được review kiểu adversarial, tất cả đã sửa + có regression test): Signal Normalizer không còn crash mất trắng cả report khi 1 field container (`results`/`Vulnerabilities`/`site`/`alerts`/...) là `null` thay vì thiếu hẳn; JSON lồng quá sâu không còn crash bằng `RecursionError` không bắt được. Hypothesis Engine: prompt có delimiter mang mã xác thực ngẫu nhiên riêng từng lần gọi (cả cho `source_snippet` lẫn phần đánh dấu từng SIGNAL khi gộp batch qua `--llm-mode agent`) — dữ liệu không đáng tin (source code, response thật) không còn giả mạo được ranh giới dữ liệu/instruction; chế độ batch của agent-bridge giờ yêu cầu response là JSON object có key rõ ràng (không phải mảng theo vị trí) để không bị gán nhầm câu trả lời sang signal khác. Context Store: lỗi tạo thư mục chứa DB và lỗi đọc dữ liệu (trước đây không bắt exception nào) giờ đều thành lỗi CLI sạch, không còn traceback thô; `show-hypothesis --format json` và `hypothesize --format json` giờ trả về field `location` cùng 1 dạng object lồng nhau, không còn khác nhau.

**Hardening 2026-08-17** (review lần đầu tiên soi toàn bộ lõi `evidence_harness/harness.py` — trước đó chỉ review riêng phần identity và phần kill-switch — tìm ra 8 lỗ hổng thật, rồi review lần 2 xác minh chính các bản fix đó tìm ra thêm 5 lỗi nữa, tất cả đã sửa + có regression test + mutation-test): `login()` không còn để lộ secret thật vĩnh viễn trên đĩa nếu trích token thất bại (giờ xoá toàn bộ response body khi không rõ secret nằm ở đâu), và từ chối token null/rỗng thay vì âm thầm gửi "Bearer None". Transcript giờ ghi đúng URL thật đã gửi (không phải `action.target` nguyên văn — httpx's `params=` có thể thay thế query string sẵn có), và redact được cả secret nằm trong query string của `action.target`. `capture()` giờ raise lỗi rõ ràng thay vì crash khi dùng lại 1 identity sau `close()`. Marker check không còn phân biệt hoa/thường. Response có giới hạn kích thước (10 MiB, tránh OOM) — khi bị cắt bớt, marker không tìm thấy được báo "chưa chắc" thay vì "chắc chắn không có", và phần thân giữ lại được kích thước tối đa thay vì mất trắng. Body không phải UTF-8 được lưu dạng base64 (không mất dữ liệu) thay vì decode lossy im lặng, có đọc charset khai báo trong Content-Type trước khi thử UTF-8.

**Hardening 2026-08-17 (vòng 2)** (review lần đầu soi toàn bộ `exploit_agent/agent.py`, LLM client dùng thật (`openai_compatible_client.py`), `cli.py`, `shared/policy.py` — tất cả trước giờ chỉ được review từng phần nhỏ — tìm ra 7 lỗi thật, review lần 2 xác minh chính các bản fix đó tìm thêm 3 lỗi nữa, cộng với đóng 3 lỗ hổng cũ đã biết nhưng chưa sửa; tổng 13, tất cả đã sửa + có regression test, 2 lỗi rủi ro cao nhất có mutation-test): LLM client không còn crash mơ hồ khi provider trả `content: null` hoặc URL cấu hình sai (`LLM_BASE_URL`); field `reason` từ LLM không phải string không còn làm crash `HypothesisResult`/`ActionPlanResult`. Cơ chế chống fabricate host (Exploit Agent) đổi từ so khớp chuỗi con sang regex có ranh giới token thật (loại cả `\w`, `.`, và `-` — vì hostname thật hay có gạch nối) để không bị bypass bằng cách nhúng host giả vào giữa 1 chuỗi/tên miền không liên quan. `strip_markdown_json_fence` (dùng chung Hypothesis Engine + Exploit Agent) đổi từ "luôn lấy fence ĐẦU" (bug gốc) → "lấy fence CUỐI hợp lệ JSON" (vẫn có bug, chỉ đổi chiều) → cuối cùng nhận thêm `expected_keys` để chọn đúng fence có field tên đúng như engine gọi nó mong đợi, không đoán theo vị trí nữa. `Authorization` không còn nhận datetime thiếu timezone. `ActionPlan` không cho tạo plan rỗng (0 action) — trước đó sẽ được "approve" một cách vô nghĩa. `cli.py` đọc `--source` giờ bắt đủ lỗi file (không tìm thấy/là thư mục/không đọc được/không phải UTF-8) và ép `encoding="utf-8"` tường minh thay vì phụ thuộc locale hệ điều hành.

**Verification Package** (`shared/models/verification_package.py` + `verification_package/assembler.py`, SPEC §7, 2026-08-17) đã có: `VerificationPackage` đủ 19 trường (đánh số khớp bảng SPEC), `assemble_verification_package()` build từ artifact thật của 1 lượt chạy — tự gọi `decide()` trên đúng 1 danh sách observation dùng chung cho mọi trường khác (không nhận verdict tính sẵn riêng, tránh 2 nguồn sự thật lệch nhau), `action_record` chỉ giữ action thực sự tạo ra observation (không phải toàn bộ plan). `missing_fields_for_release()`/`is_release_ready` implement đúng "binary schema completeness" của §8.1 — khác ECS (rubric riêng, còn Proposed/TBD). Qua 1 vòng review ngay sau khi build, tìm ra 7 lỗi thật: `verdict`/`predicate_results` lưu tách rời không đồng bộ với nhau (validator của `VerdictResult` không tự áp dụng sang model này); `raw_evidence_references`/`artifact_hashes` chỉ kiểm độ dài, có thể bị hoán đổi vị trí cho nhau; `action_record` có thể thiếu ActionSpec cho action đã thực sự chạy, hoặc trùng lặp action_id; assembler crash khó hiểu với danh sách observation rỗng; `is_release_ready` không kiểm nội dung thật của human review (reviewer từ chối vẫn báo "sẵn sàng release"); lý do thật của verdict (`VerdictResult.reason`) bị bỏ qua, không có trong package. Cả 7 đã sửa + có test + 3 lỗi rủi ro cao nhất có mutation-test (mutation-test còn phát hiện 2 lỗi trong chính test tự viết — fixture bị trùng lặp khiến test "pass" vì lý do sai).

Chưa có: redaction policy đầy đủ theo danh mục thật (§4.3.5, cần chốt cùng owner ở Gate 3 — hiện chỉ có floor tối thiểu), manifest cấp package (§4.3.3). Human Review Loop: chưa hiện thực (có sẵn model `HumanReviewRecord`/`ReviewDecision` nhưng chưa có workflow/CLI thật). Kill-switch nối CLI/API thật: chưa hiện thực (xem 2 lớp hạn chế ở trên).

## Cài đặt

Yêu cầu Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` thành `.env`, điền `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` — dùng được bất kỳ provider nào tương thích chuẩn OpenAI Chat Completions (đã thử: Groq, Google Gemini). `.env` bị `.gitignore` chặn, không bao giờ commit được.

`tests/test_end_to_end.py` (2026-08-17, sau khi xác nhận trước đó không có test nào nối các tầng lại với nhau) nối thật Signal Normalizer → Hypothesis Engine → Exploit Agent → Evidence Harness → Verdict Oracle trong 1 test (chỉ mock network + LLM, còn lại là logic thật 100%) — verdict cuối ra đúng `CONFIRMED` cho 1 kịch bản IDOR 3 role, cộng 1 test cho nhánh `NOT_PLANNABLE` (finding SAST thuần, không có network location). Đã mutation-test: cố tình phá đường truyền field `location` từ signal sang hypothesis, xác nhận test bắt được lỗi ngay.

## Chạy test

```bash
pytest
```

## Dùng CLI

4 lệnh, dùng report mẫu có sẵn trong `tests/fixtures/` để thử ngay.

Các file mẫu trong `tests/fixtures/` là output **thật** (không tự viết tay) từ Semgrep/Trivy/OWASP ZAP chạy thật vào SecWeave/OWASP Juice Shop — xem chú thích trong từng file. Ví dụ dưới dùng `zap_sample_report.json` vì nó có URL thật, đi được hết cả 4 bước; `semgrep_sample_report.json`/`trivy_sample_report.json` là whitebox (SAST/SCA, không có URL) nên `plan` sẽ trả `NOT_PLANNABLE` — đúng hành vi mong đợi, không phải lỗi (xem `--tool` bên dưới để thử các file đó).

**1. Chuẩn hoá report thô thành `NormalizedSignal`** (không cần API key):
```bash
python cli.py normalize --signal tests/fixtures/zap_sample_report.json --tool owasp_zap --tool-version 2.17.0
```
`--tool` nhận `semgrep` / `trivy` / `owasp_zap`. Thêm `--format json` để lấy output JSON.

**2. Sinh `Hypothesis` từ report** (gọi LLM thật, cần `.env`):
```bash
python cli.py hypothesize --signal tests/fixtures/zap_sample_report.json --tool owasp_zap --tool-version 2.17.0 --context-db .secweave/context.db
```
Không có API key thì thêm `--llm-mode agent` để bắc cầu qua agent đang chat cùng bạn thay vì gọi API.

**3. Soạn `ActionPlan` từ 1 hypothesis đã lưu, kiểm duyệt qua allowlist** (chưa thực thi request thật nào):
```bash
python cli.py plan --hypothesis-id <hyp_...> \
  --allowed-action "GET http://host.docker.internal:3000" \
  --context-db .secweave/context.db
```
`--allowed-action` lặp lại được nhiều lần; không truyền gì = allowlist rỗng = mọi hành động bị chặn (deny-by-default). LLM thật không tất định — có lúc chỉ đề xuất 1 action (khớp allowlist trên → `APPROVED`), có lúc đề xuất thêm action khác (vd `OPTIONS`, hay `GET` kèm tham số `Origin`) không có trong allowlist → `BLOCKED`. **Cả 2 kết quả đều đúng** — `BLOCKED` không phải lỗi, đó chính là deny-by-default hoạt động đúng khi allowlist không phủ hết plan. Muốn chắc `APPROVED`, thêm allowlist entry khớp với action thực tế LLM vừa đề xuất (đọc từ output ngay phía trên).

**4. Tra lại hypothesis đã sinh:**
```bash
python cli.py show-hypothesis --hypothesis-id <hyp_...>
```

Mỗi lệnh có `--help` riêng để xem đầy đủ tuỳ chọn.

**Phân loại:** NTQ INTERNAL.
