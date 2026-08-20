# Target/Sandbox Authorization — template (chưa điền tên/ký)

Sản phẩm Chặng 2 theo `SECWEAVE_WEEKLY_PLAN.md` (W3, sau khi Gate 1 ở W2 đã
mở Chặng 2): biểu mẫu cho **Gate 2 — Target/Sandbox Authorization**, ký bởi
owner của target/sandbox được chọn ở Gate 1. Đây là **template rỗng** —
không đại diện cho bất kỳ target thật nào
(kể cả NxKeeper), không được điền thông tin suy đoán, chỉ điền khi có
owner thật ký thật.

Tham chiếu bắt buộc: `SECWEAVE_SPEC.md` §6.2 (9 mục hồ sơ Gate 2),
§6.5 (9 tiêu chí Go/No-Go `NX-GO-01…09` phải đạt trước khi tới bước này),
model `Authorization` (`shared/models/entities.py`).

**Điều khoản không đổi (SPEC §6.2 bảng "Không cho phép gì"):** hồ sơ này,
một khi ký, **không** cho phép bất kỳ hành động nào ngoài scope/allowlist/
caps/window/expiry đã ghi dưới đây. Muốn chạy 1 scenario cụ thể vẫn cần
thêm Gate 3 (Execution Release) — ký hồ sơ này **chưa** được phép chạy gì.

---

## 1. Định danh

| Trường | Giá trị |
|---|---|
| Authorization ID | *(sinh tự động khi tạo record — để trống ở bước soạn thảo)* |
| Layer | `target_authorization` (cố định — xem `AuthorizationLayer`) |
| Approved by (owner) | *(họ tên + vai trò người ký — phải là owner thật của target/sandbox, không phải Sponsor)* |
| Approved at | *(ngày ký — điền khi ký, không điền trước)* |

## 2. Scope — target & revision

| Trường | Giá trị |
|---|---|
| Target ID | *(đúng 1 target — khớp `Target` entity đã qua Gate 1, SPEC §3.1)* |
| Target Revision ID | *(đúng 1 revision, pin cụ thể — theo `NX-GO-04`, không để "latest"/trôi)* |
| Môi trường | ☐ Production ☐ Staging ☐ Sandbox tự dựng *(nếu Production — dừng, SPEC không cho phép Gate 2 trên production ở MVP)* |

## 3. Identity

| Trường | Giá trị |
|---|---|
| Identity được cấp | *(tên/loại tài khoản test do owner cấp — không phải credential thật của người dùng thật)* |
| Số lượng identity | *(tối thiểu 2 nếu scenario cần positive/denied control — SPEC §4.3.4)* |
| Nguồn cấp credential | *(owner cấp qua kênh nào — không commit vào repo, không gửi qua kênh không mã hoá)* |

## 4. Allowlist hành động

| Method | URL / pattern | Tham số cho phép | Loại hành động |
|---|---|---|---|
| *(để trống — điền khi có scenario cụ thể ở Gate 3)* | | | ☐ read_only ☐ test_data_creation |

> Cú pháp thật khi nạp vào hệ thống: `"METHOD url [params:key1,key2]"` (Policy Service, `shared/policy.py`). Không có dòng nào trong bảng này = không hành động nào được phép (deny-by-default).

## 5. Cửa sổ thời gian (window)

| Trường | Giá trị |
|---|---|
| Window start | *(thời điểm bắt đầu hiệu lực)* |
| Window end | *(thời điểm hết hiệu lực — không có nghĩa là auto-run hết cửa sổ)* |

## 6. Caps (giới hạn)

| Trường | Giá trị |
|---|---|
| Cap số hành động / execution | *(số nguyên — nạp vào Cost Service qua `--cap`)* |
| Cap khác (nếu có) | *(vd rate limit, số identity đồng thời)* |

## 7. Stop-work

| Trường | Giá trị |
|---|---|
| Đầu mối liên hệ dừng khẩn | *(tên + kênh liên hệ 24/7 nếu cần dừng ngay)* |
| Xác nhận: agent/model không có quyền từ chối lệnh dừng | ☐ Đã xác nhận (SPEC §5.3) |

## 8. Cleanup

| Trường | Giá trị |
|---|---|
| Kế hoạch dọn dẹp sau chạy | *(vd xoá test data đã tạo, revert seed — ai làm, khi nào)* |
| Callable cleanup đã cấp (nếu có) | *(Gate 3 mới thật sự cần — ghi placeholder ở đây nếu owner muốn định hình sớm)* |

## 9. Expiry & thu hồi

| Trường | Giá trị |
|---|---|
| Expiry | *(ngày hồ sơ này hết hạn, kể cả chưa dùng hết window)* |
| Thu hồi | Có thể thu hồi bất cứ lúc nào bởi owner — không cần lý do, không cần thương lượng trước (SPEC §6.2) |

---

## Ghi chú khi điền thật

- Mọi ô trống ở trên **không được suy đoán/điền tạm** — để trống và ghi `TBD` cho tới khi có xác nhận thật từ owner.
- Hồ sơ này **không** thay thế Gate 3 (Execution Release) — mục 4 (allowlist) ở Gate 2 có thể rộng hơn scenario thật sẽ chạy; Gate 3 mới freeze đúng 1 scenario cụ thể.
- Không log/lưu bất kỳ credential thật nào kèm theo file này.
