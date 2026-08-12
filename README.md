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

**Phân loại:** NTQ INTERNAL.
