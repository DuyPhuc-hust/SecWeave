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

**Verdict Oracle** (`verdict_oracle/oracle.py`+`predicates.py`) có predicate draft **và** bước gộp verdict cuối (`assemble_verdict`/`decide` — trả đúng 1 trong 3 `CONFIRMED`/`NOT_REPRODUCED`/`INCONCLUSIVE`), giờ enforce đủ 2 control SPEC không-ngoại-lệ tìm thấy còn thiếu qua audit toàn dự án (2026-08-16): (1) `execution_status` bắt buộc phải `COMPLETED` mới ra verdict cuối — STOPPED/RUNNING/... đều ép về INCONCLUSIVE (SPEC §3.4); (2) hash artifact được xác minh lại (đọc file thật, tính lại SHA-256) trước khi cho phép CONFIRMED — hash không khớp hoặc file không đọc được đều thành INSUFFICIENT_DATA (SPEC §6.4 control #8).

**Kill-switch** (`shared/kill_switch.py`, SPEC §6.3/§5.3, weekly plan Tuần 6) đã có: `KillSwitch` là điểm dừng dùng chung cho 1 execution — 6 nguồn (`StopSource`: operator/target owner/infra owner/data-ISMS owner/incident responder/automatic threshold), gọi `stop()` từ bất kỳ nguồn nào cũng dừng ngay, không cần thương lượng trước, chạy đúng 1 lần cleanup (callable operator tự cung cấp — chưa có Gate 3 thật), ghi audit log JSONL (ai/khi nào/vì sao) tại `{storage_dir}/{execution_id}/kill_switch_audit_log.jsonl`. `resume()` là đường DUY NHẤT quay lại RUNNING — không có auto-resume/timer nào (đối chiếu với circuit-breaker pattern để tránh nhầm 2 khái niệm). `EvidenceHarness.capture()` nhận `kill_switch` optional, raise `ExecutionStoppedError` thay vì gửi request thật khi đã STOPPED — đây là kiểm tra trước-khi-gửi (cooperative), không ngắt ngang request đang bay giữa chừng. Đã qua 2 vòng review độc lập, cả 2 vòng đều tìm ra bug thật trong chính bản fix của vòng trước (status không phục hồi đúng khi tạo lại instance sau STOPPED; write audit log ngoài lock làm sai thứ tự khi so bằng physical file order — sửa bằng `sequence` số nguyên gán tại thời điểm chuyển trạng thái, không phụ thuộc lúc I/O thật sự chạy xong; log hỏng dòng cuối do crash giữa chừng làm `__init__` crash theo — sửa bằng fail-safe về STOPPED). Chưa có: nối kill-switch với CLI/API thật, Cost Service thật (đếm hành động + tự gọi `stop()` khi vượt cap — kill-switch chỉ là điểm dừng dùng chung, không tự phát hiện điều kiện nào trong 5 điều kiện tự động).

**Hardening 2026-08-16** (audit toàn dự án tìm ra 9 lỗ hổng thật ở các tầng chưa từng được review kiểu adversarial, tất cả đã sửa + có regression test): Signal Normalizer không còn crash mất trắng cả report khi 1 field container (`results`/`Vulnerabilities`/`site`/`alerts`/...) là `null` thay vì thiếu hẳn; JSON lồng quá sâu không còn crash bằng `RecursionError` không bắt được. Hypothesis Engine: prompt có delimiter mang mã xác thực ngẫu nhiên riêng từng lần gọi (cả cho `source_snippet` lẫn phần đánh dấu từng SIGNAL khi gộp batch qua `--llm-mode agent`) — dữ liệu không đáng tin (source code, response thật) không còn giả mạo được ranh giới dữ liệu/instruction; chế độ batch của agent-bridge giờ yêu cầu response là JSON object có key rõ ràng (không phải mảng theo vị trí) để không bị gán nhầm câu trả lời sang signal khác. Context Store: lỗi tạo thư mục chứa DB và lỗi đọc dữ liệu (trước đây không bắt exception nào) giờ đều thành lỗi CLI sạch, không còn traceback thô; `show-hypothesis --format json` và `hypothesize --format json` giờ trả về field `location` cùng 1 dạng object lồng nhau, không còn khác nhau.

Chưa có: redaction policy đầy đủ theo danh mục thật (§4.3.5, cần chốt cùng owner ở Gate 3 — hiện chỉ có floor tối thiểu), manifest cấp package (§4.3.3). Human Review Loop: chưa hiện thực.

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
