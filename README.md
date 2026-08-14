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

Đã chạy được thật (xem [Dùng CLI](#dùng-cli) dưới đây): Signal Normalizer (Semgrep/Trivy/OWASP ZAP), Hypothesis Engine, Exploit Agent (lập kế hoạch + tự kiểm duyệt qua allowlist — **chưa thực thi hành động thật**), Security Context Store. Chưa hiện thực: Evidence Harness, Verdict Oracle (chỉ có predicate draft, chưa kiểm chứng bằng dữ liệu thật), Human Review Loop.

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

**1. Chuẩn hoá report thô thành `NormalizedSignal`** (không cần API key):
```bash
python cli.py normalize --signal tests/fixtures/semgrep_sample_report.json --tool semgrep --tool-version 1.78.0
```
`--tool` nhận `semgrep` / `trivy` / `owasp_zap`. Thêm `--format json` để lấy output JSON.

**2. Sinh `Hypothesis` từ report** (gọi LLM thật, cần `.env`):
```bash
python cli.py hypothesize --signal tests/fixtures/semgrep_sample_report.json --tool semgrep --tool-version 1.78.0 --context-db .secweave/context.db
```
Không có API key thì thêm `--llm-mode agent` để bắc cầu qua agent đang chat cùng bạn thay vì gọi API.

**3. Soạn `ActionPlan` từ 1 hypothesis đã lưu, kiểm duyệt qua allowlist** (chưa thực thi request thật nào):
```bash
python cli.py plan --hypothesis-id <hyp_...> \
  --allowed-action "GET https://staging.example.com/api/objects/{id}" \
  --context-db .secweave/context.db
```
`--allowed-action` lặp lại được nhiều lần; không truyền gì = allowlist rỗng = mọi hành động bị chặn (deny-by-default).

**4. Tra lại hypothesis đã sinh:**
```bash
python cli.py show-hypothesis --hypothesis-id <hyp_...>
```

Mỗi lệnh có `--help` riêng để xem đầy đủ tuỳ chọn.

**Phân loại:** NTQ INTERNAL.
