# Scanner rules bổ sung

SecWeave không tự chạy Semgrep/Trivy/OWASP ZAP — nó chỉ ingest report do CI/CD
đã chạy sẵn (xem README chính). Thư mục này chứa **rule Semgrep tuỳ chỉnh** mà
pipeline CI/CD của target nên thêm vào bước Semgrep hiện có, để đóng phần
khoảng trống đã xác nhận thật: `--config auto` (ruleset cộng đồng mặc định)
không có rule nào theo dõi được loại lỗi **Broken Object Level
Authorization / IDOR** (CWE-639) — giá trị định danh (userId/username/id)
lấy từ URL, dùng để tra dữ liệu, mà không đối chiếu với danh tính đang đăng
nhập.

## Cách dùng

Thêm các rule này CÙNG với ruleset mặc định trong bước Semgrep của CI/CD:

```bash
semgrep --config auto --config scanner_rules/semgrep/idor_identity_from_url_param.yaml \
        --config scanner_rules/semgrep/bola_missing_auth_check.yaml \
        --json --output semgrep_report.json .
```

Report JSON kết quả (bao gồm cả finding từ rule tuỳ chỉnh) đưa thẳng vào
`python -m cli normalize`/`hypothesize` như bình thường — `SemgrepAdapter` không cần
sửa gì, vì shape JSON của 1 custom rule giống hệt rule lấy từ registry.

## Rule hiện có

| File | Ngôn ngữ | Lỗi nhắm tới | Đã xác nhận thật trên |
|---|---|---|---|
| `idor_identity_from_url_param.yaml` | JavaScript/TypeScript (Express-style) | định danh lấy từ `req.params`, không đối chiếu `req.session` (kể cả khi đối chiếu đó nằm trong 1 điều kiện `if`) | OWASP NodeGoat (`app/routes/allocations.js`, commit `c5cb68a`) — 1/1 finding đúng vị trí lỗi thật |
| `bola_missing_auth_check.yaml` | Python (Flask-style) | view function (kể cả method nhiều tham số/class-based view) nhận định danh qua URL nhưng thân hàm không gọi `token_validator(...)` | VAmPI (`api_views/users.py`, commit `f16052d`) — 1/1 finding đúng `get_by_username`; im lặng đúng trên 3 hàm khác cùng file có gọi `token_validator` |

Cả 2 rule đã chạy bằng Semgrep thật (`.venv/bin/semgrep`/`returntocorp/semgrep:1.172.0`)
trên đúng file nguồn thật đã dùng để phát hiện IDOR/BOLA thủ công trước đây
trong dự án — không phải rule viết xong chưa test. Output thật của 2 lần
chạy đó được lưu làm fixture ở
`tests/fixtures/nodegoat_idor_custom_rule_semgrep_report.json` và
`tests/fixtures/vampi_bola_custom_rule_semgrep_report.json`, có test tương
ứng trong `tests/test_semgrep_adapter.py`.

**Đã qua 1 vòng review độc lập (2026-08-18)**, tìm ra 5 lỗi thật trong bản
đầu tiên — tất cả đã sửa, xác nhận lại bằng Semgrep thật trên case cụ thể
review đưa ra, có regression test riêng cho từng lỗi
(`test_idor_rule_stays_silent_when_session_check_is_inside_an_if_condition`,
`test_idor_rule_stays_silent_on_anonymous_handlers_with_a_session_check`,
`test_idor_rule_catches_bracket_notation_param_access`,
`test_bola_rule_catches_multi_parameter_view_functions` trong
`tests/test_semgrep_adapter.py`):
1. **False positive** — rule JS chỉ nhận diện `req.session` khi đứng riêng 1
   statement, nên cách viết tự nhiên nhất (`if (req.session.userId !==
   userId) {...}`) vẫn bị báo lỗi dù đã kiểm tra đúng. Sửa bằng deep-expression
   ellipsis của Semgrep (`<... $REQ.session ...>`) để tìm `req.session` ở bất
   kỳ đâu trong thân hàm, kể cả trong điều kiện.
2. **False positive** — rule JS chỉ nhận diện handler có tên (function
   declaration có tên, hoặc arrow gán vào biến có tên) — idiom phổ biến nhất
   của Express, callback ẩn danh truyền thẳng vào `router.get(...)`, vẫn bị
   báo lỗi dù có session check đúng. Sửa bằng cách thêm pattern cho function
   expression/arrow ẩn danh.
3. **False negative** — `req.params['userId']` (bracket notation) không bị
   bắt dù lỗi y hệt `req.params.userId`. Sửa bằng thêm pattern
   `$REQ.params[$ID]` + nới `metavariable-regex` chấp nhận dấu ngoặc kép mà
   Semgrep giữ lại trong text của string-literal metavariable.
4. **False negative** — rule Python chỉ nhận diện định danh khi nó là tham
   số DUY NHẤT của hàm, bỏ sót method nhiều tham số (`def get(self,
   user_id)`, class-based view) và hàm có tham số khác đi kèm. Sửa bằng
   thêm pattern `def $FUNC(..., $ID, ...):` khớp `$ID` ở bất kỳ vị trí nào.
5. **Tài liệu phóng đại** — bản đầu của file README này khẳng định rule "im
   lặng đúng trên bản đã sửa dùng req.session" như 1 tính chất tổng quát,
   trong khi thực ra chỉ đúng với đúng 1 kiểu code đã thử — mục Giới hạn bên
   dưới giờ liệt kê rõ những gì CHƯA thử/CHƯA chắc, thay vì khẳng định
   chung chung.

## Giới hạn đã biết

- Đây là rule theo **idiom cụ thể** (định danh từ URL param + thiếu đối
  chiếu session/token check), không phải bộ phát hiện IDOR tổng quát cho mọi
  ngôn ngữ/framework — cần viết thêm rule tương tự nếu target dùng framework
  khác (Django, Spring, .NET...).
- Rule JS **chưa** nhận diện được `req['params'].userId` (bracket notation
  ngay trên chính `params`, khác với bracket notation trên key như
  `req.params['userId']` — cái đó ĐÃ được xử lý). Đây là cách viết rất hiếm
  gặp trong code thật; chưa đủ giá trị để thêm pattern riêng, nhưng nếu code
  target dùng style này, rule sẽ bỏ sót.
- Cả 2 rule đều là pattern/heuristic tĩnh — không có bảo đảm hình thức nào
  rằng mọi biến thể cú pháp hợp lệ khác của cùng lỗi đều được bắt, hay mọi
  cách viết hợp lệ của một auth check đúng đều được nhận diện là an toàn.
  Danh sách 5 lỗi ở trên là những gì ĐÃ được review tìm ra và sửa — không
  phải bằng chứng rule giờ hoàn hảo, chỉ là rule đã qua 1 vòng kiểm tra đối
  kháng thay vì chỉ tự test theo đúng ý người viết.
- Cũng như mọi rule Semgrep khác, đây là **tín hiệu, không phải kết luận**
  (nguyên tắc P1, SPEC §1.1) — vẫn phải qua Hypothesis Engine → Exploit Agent
  → Evidence Harness → Oracle như bình thường, có thể ra `NOT_REPRODUCED`
  nếu là false positive.
- Semgrep CLI miễn phí (không `semgrep login`) trả `signal_context` là chuỗi
  placeholder `"requires login"` thay vì đoạn code thật cho rule không thuộc
  registry công khai (đã gặp hiện tượng này từ trước với cả rule `auto`, xem
  `tests/test_semgrep_adapter.py::test_semgrep_adapter_maps_fields_correctly`).
  Dùng `hypothesize --source <file>` để bù lại ngữ cảnh source thật cho LLM.
- Semgrep đặt tên (`rule.id`) cho 1 rule local theo đường dẫn tương đối của
  file config — chạy đúng lệnh trong "Cách dùng" ở trên sẽ ra id dạng
  `scanner_rules.semgrep.express-identity-from-url-param-without-session-check`,
  không phải id trần trong file YAML.
