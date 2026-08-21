# SecWeave — Kế hoạch triển khai theo tuần & Chiến lược test

> **Về tài liệu này.** Đây là bản triển khai chi tiết của lịch trình đã có trong `A.html` (Mục 13 — Kế hoạch thực hiện) và kiến trúc đã có trong `SECWEAVE_SPEC.md`. Tài liệu này trả lời **"mỗi tuần làm gì cụ thể, test thế nào, chức năng nào xong"** — ở mức có thể giao việc và chấm được, không chỉ ở mức WBS.
>
> **Lưu ý bắt buộc phải giữ khi đọc:** theo `A.html` (Mục 9.3, 13.3, 23.1), **chỉ W1–W2 (Chặng 1) là lịch đã xin duyệt**. W3–W8 (Chặng 2) là **planning labels, conditional, TBD sau Gate 1** — lịch calendar thật sẽ được chốt lại khi Sponsor mở Chặng 2, không phải cam kết hôm nay. Ngày dương lịch ghi dưới đây (tính từ kickoff dự kiến 01/08/2026) chỉ để có mốc tham chiếu làm việc, **không phải ngày đã chốt**. Không có tuần nào trong Chặng 2 được phép có active run trên target thật nếu chưa qua đúng Gate 2 (Authorization) và Gate 3 (Execution Release) — xem `SECWEAVE_SPEC.md` §6.2.

---

## Mục lục

0. [Tổng quan lịch trình](#0-tổng-quan-lịch-trình)
1. [Chiến lược test tổng thể](#1-chiến-lược-test-tổng-thể)
2. [Tuần 1 — Khởi động (WP0 → Gate 0)](#tuần-1--khởi-động-wp0--gate-0)
3. [Tuần 2 — Discovery (WP1 → Gate 1)](#tuần-2--discovery-wp1--gate-1)
4. [Tuần 3 — Thiết kế chi tiết & Authorization (WP2 → Gate 2)](#tuần-3--thiết-kế-chi-tiết--authorization-wp2--gate-2)
5. [Tuần 4 — Hypothesis Engine (WP3a)](#tuần-4--hypothesis-engine-wp3a)
6. [Tuần 5 — Exploit Agent + Policy/Identity (WP3b)](#tuần-5--exploit-agent--policyidentity-wp3b)
7. [Tuần 6 — Evidence Harness, Oracle, Kill-switch, Dry-run (WP3c+WP3d → Gate 3)](#tuần-6--evidence-harness-oracle-kill-switch-dry-run-wp3cwp3d--gate-3)
8. [Tuần 7 — Active run, Retest, Review (WP4 → Gate 4)](#tuần-7--active-run-retest-review-wp4--gate-4)
9. [Tuần 8 — Đo lường, Bàn giao, Closeout (WP5+WP6 → Gate 5)](#tuần-8--đo-lường-bàn-giao-closeout-wp5wp6--gate-5)
10. [Ma trận truy vết: tuần → chức năng → test → tiêu chí nghiệm thu](#10-ma-trận-truy-vết-tuần--chức-năng--test--tiêu-chí-nghiệm-thu)

---

## 0. Tổng quan lịch trình

| Tuần | Ngày (dự kiến, từ kickoff 01/08/2026) | WP | Gate cuối tuần | Trọng tâm một câu |
|---|---|---|---|---|
| **W1** | 01/08 – 07/08 | WP0 (32h) | Gate 0 | Khởi động, tiếp nhận approved artifacts, mở OQ-014 |
| **W2** | 08/08 – 14/08 | WP1 (48h) | **Gate 1** | Discovery Report, map, baseline offline, gap register |
| **W3** | 15/08 – 21/08 | WP2 (40h) | Gate 2 | Thiết kế hero scenario, allowlist, hồ sơ Authorization |
| **W4** | 22/08 – 28/08 | WP3a (40h) | — | Hiện thực Hypothesis Engine + Signal Normalizer |
| **W5** | 29/08 – 04/09 | WP3b (48h) | — | Hiện thực Exploit Agent + Policy/Identity |
| **W6** | 05/09 – 11/09 | WP3c+WP3d (96h)* | Gate 3 | Evidence Harness, Oracle, kill-switch, dry-run sạch |
| **W7** | 12/09 – 18/09 | WP4 (32h) | Gate 4 | Active run, retest, Verification Package, human review |
| **W8** | 19/09 – 25/09 | WP5+WP6 (48h) | **Gate 5** | Đo tiêu chí, bàn giao, Pilot Decision Package |

\* WP3c (Evidence Harness, 48h) và WP3d (Oracle + Context Store, 48h) được gộp nhãn W6 trong `A.html` Mục 13.3. Vì tổng 96 giờ vượt năng lực 1 tuần của 2 người (trần 40h/người/tuần, Mục 14.2 A.html), **W6 trong thực tế nhiều khả năng cần kéo dài hơn 1 tuần dương lịch** — đây là điểm rủi ro lịch trình cần theo dõi (xem cảnh báo ở [Tuần 6](#tuần-6--evidence-harness-oracle-kill-switch-dry-run-wp3cwp3d--gate-3)), không phải mâu thuẫn cần "sửa cho khớp" — A.html tự nhận lịch W3–W8 là planning labels, không phải commitment giờ-tuần chính xác.

**Ba việc không cắt trong mọi trường hợp trượt tiến độ** (A.html Mục 15.4): cơ chế cấp phép, kill-switch, human review. Nếu phải cắt phạm vi, thứ tự cắt là: bỏ kịch bản stretch → bỏ kênh bằng chứng UI (giữ HTTP+log) → giảm tập predicate về mức tối thiểu → chuyển mục tiêu active run sang "bàn giao harness + hồ sơ điều kiện còn thiếu".

---

## 1. Chiến lược test tổng thể

Vì hệ thống có bốn tầng với bốn loại trách nhiệm khác nhau ([SPEC §2.3](./SECWEAVE_SPEC.md#23-bảng-phân-quyền-bốn-tầng--được--không-được-làm-gì)), mỗi tầng cần một **loại test khác nhau** — dùng test sai loại cho một tầng sẽ không phát hiện đúng lớp lỗi mà tầng đó dễ mắc. Bảng dưới là từ điển dùng chung cho mọi tuần bên dưới, tránh phải định nghĩa lại mỗi lần.

| Loại test | Áp dụng cho tầng | Mục đích | Công cụ dự kiến |
|---|---|---|---|
| **Unit test** | Mọi tầng | Đúng logic một hàm/class độc lập | `pytest` |
| **Golden-file / fixture test** | Signal Normalizer, Oracle | Input cố định đã biết trước → output phải khớp bit-for-bit với kết quả đã duyệt trước | `pytest` + thư mục `fixtures/` |
| **Property/negative test** | Hypothesis Engine, Oracle | Với input mơ hồ/thiếu, hệ thống phải trả về đúng trạng thái "không đủ dữ liệu" — **không tự bịa kết luận** | `pytest` (input ngẫu nhiên có chủ đích, không dùng thư viện tên trùng với domain object `Hypothesis`) |
| **Adversarial/safety test** | Exploit Agent, Policy Service | Chủ động thử hành động vi phạm allowlist/scope để xác nhận bị chặn 100% | Script test nội bộ, chạy trong CI |
| **Integration test (mocked target)** | Toàn luồng 4 tầng | Dữ liệu chảy đúng giữa các tầng, không cần target thật | `pytest` + `respx`/`responses` (mock `httpx`) |
| **Kill-switch drill** | Toàn hệ thống | Mọi nguồn dừng (5 người + 1 ngưỡng tự động, SPEC §6.3) đều dừng được thật, có cleanup + audit log | Chạy tay trong dry-run, có checklist |
| **Dry-run acceptance test** | Toàn hệ thống, trên target/sandbox thật | Xác nhận luồng chạy sạch (0 tác động) trước khi owner ký Execution Release (Gate 3) | Chạy tay, có checklist ký duyệt |
| **Reproducibility test** | Oracle + toàn luồng | Retest ≥ 3 lần cùng scenario/revision, đo tỷ lệ cùng verdict (ngưỡng đề xuất ≥ 2/3, SPEC §8.1) | Script chạy lại tự động |
| **Handover/runbook test** | Toàn hệ thống | Người thứ hai chạy lại chỉ bằng tài liệu, không hỏi tác giả | Chạy tay, có checklist |

**Nguyên tắc xuyên suốt:** test cho tầng nào thì phải tôn trọng đúng ràng buộc "được/không được làm" của tầng đó ([SPEC §2.3](./SECWEAVE_SPEC.md#23-bảng-phân-quyền-bốn-tầng--được--không-được-làm-gì)). Ví dụ: test Oracle **không** được viết theo kiểu "gọi LLM để kiểm tra LLM" — Oracle là rule code thuần nên test của nó phải là unit test tất định 100%, không có tính ngẫu nhiên nào được phép lọt vào assertion.

---

## Tuần 1 — Khởi động (WP0 → Gate 0)

**Mục tiêu:** có Gate 0 (phê duyệt thời gian/nguồn lực Chặng 1), có kênh liên hệ Discovery, có khung code rỗng nhưng đúng schema để tuần sau viết tiếp lên.

**Input cần có trước khi bắt đầu:** phê duyệt Gate 0 của Sponaor; tên đầu mối owner target/sandbox do Sponsor chỉ định (A.html Mục 14.4, hạng mục 1).

**Công việc kỹ thuật cụ thể:**
- Setup repository `secweave` (Git): cấu trúc thư mục theo 4 tầng (`hypothesis_engine/`, `exploit_agent/`, `evidence_harness/`, `verdict_oracle/`, `context_store/`, `shared/` cho Config/Identity/Policy/Logging/Cost) + `tests/`.
- Setup môi trường: Python venv, `requirements.txt` khung (Pydantic, httpx, pytest, Semgrep CLI) — **chưa** cài Playwright/Docker (chưa cần đến UI/sandbox tuần này).
- Viết skeleton data model bằng Pydantic cho các entity ở [SPEC §3.1](./SECWEAVE_SPEC.md#31-entity-chính-và-quan-hệ): `Organization`, `Project`, `System`, `Target`, `TargetRevision`, `Authorization` — chỉ định nghĩa field + type, chưa có logic nghiệp vụ.
- Viết skeleton `NormalizedSignal` model (theo [SPEC §4.1.1](./SECWEAVE_SPEC.md#411-chuẩn-hoá-tín-hiệu-đầu-vào--normalizedsignal)) và `scope_status` enum ([SPEC §3.3](./SECWEAVE_SPEC.md#33-state-machine--scope_status)) — dùng lại nguyên schema đã chốt trong SECWEAVE_SPEC.md, không thiết kế lại.
- Gửi **OQ-014** tới ISMS (chính sách kiểm thử chủ động nội bộ) — deadline W1 theo A.html Phụ lục B.
- Liên hệ owner target/sandbox candidate qua kênh tổ chức: đề nghị approved artifacts + đặt lịch phỏng vấn cho W2.
- Mở **OQ tracker** (bảng theo dõi OQ-001, OQ-013…OQ-019) và **gap register** rỗng (sẽ điền dần từ W2).

**Chức năng hoàn thiện cuối tuần (Definition of Done):**
- Repo khởi tạo, chạy được `pytest` (dù chưa có test thật, CI xanh với 0 test hoặc test khung).
- Toàn bộ Pydantic model của entity + `NormalizedSignal` + `scope_status` compile được, `.model_json_schema()` xuất ra JSON schema hợp lệ.
- Không có bất kỳ dòng code nào gọi ra ngoài mạng tới target thật (đúng ràng buộc Chặng 1).

**Kế hoạch test:**
- Unit test schema: mỗi entity Pydantic — test tạo instance hợp lệ pass, thiếu field bắt buộc phải raise `ValidationError`.
- Test tĩnh (code review, không phải test tự động): grep toàn repo xác nhận không có `httpx.get/post` nào trỏ tới domain/IP thật ngoài `localhost`/fixture — đưa vào checklist review PR.
- Review checklist: gap register đã có đủ khung cho 11 mục "Unverified/TBD" đã liệt kê trong A.html §2.1 (backend/frontend stack, repo access, staging, reset, auth, role model, test identity, data policy, network constraint, AI-provider data policy, người có thẩm quyền ký).

**Rủi ro cần theo dõi:** R-08 (ISMS chưa trả lời OQ-014 — nếu cuối W1 chưa có phản hồi, ghi nhận là dấu hiệu sớm, chưa phải trigger dừng ST-3 vì hạn chính thức là "trước active run").

---

## Tuần 2 — Discovery (WP1 → Gate 1)

**Mục tiêu:** đủ thông tin có nguồn (provenance) để Gate 1 quyết định target (NxKeeper / sandbox / No-Go).

**Input cần có:** approved artifacts từ owner (kiến trúc sơ bộ, thông tin auth/role nếu có tài liệu); ~2 giờ phỏng vấn owner (A.html Mục 14.4, hạng mục 3).

**Công việc kỹ thuật cụ thể:**
- Phỏng vấn owner NxKeeper qua kênh tổ chức; ghi âm/note có kiểm soát; **mọi fact ghi vào Discovery Report kèm nguồn** (artifact nào, ai nói, lúc nào) — phần chưa xác minh ghi `Unverified/TBD`, không suy diễn.
- Viết **Discovery Report** (theo cấu trúc value floor A.html §1.5.1, hiện vật #1).
- Vẽ **System Interaction and Dependency Map**: liệt kê dependency biết được từ approved inputs, gắn `scope_status` dự kiến (`CONTEXT_ONLY` cho hầu hết ở giai đoạn này — chưa có gì là `TARGET` thật vì chưa qua Gate 2).
- Đánh giá **9 tiêu chí Go/No-Go** (`NX-GO-01…09`, SPEC §6.5) dựa hoàn toàn trên approved inputs + owner statement — ghi rõ với mỗi tiêu chí: **Đạt / Không đạt / Chưa đủ dữ liệu** kèm nguồn trích dẫn.
- **Baseline offline/tabletop:** Nam và Phúc **độc lập** viết tay hypothesis + tiêu chí quan sát cho một hero scenario giả định (ví dụ broken access control giữa project/tenant, theo giả thuyết lý thuyết ở A.html §2.1) chỉ dựa trên Discovery Report — không chạm hệ thống. Đây là cách kiểm `NX-GO-05` (kịch bản kiểm chứng được bằng máy) mà không cần runtime.
- Soạn **draft Evidence Protocol / Verification Package spec** — thực chất là copy & rà lại schema 19 trường đã có ở [SPEC §7](./SECWEAVE_SPEC.md#7-verification-package--19-trường), đánh dấu baseline cho Chặng 1.
- Soạn **Target/Sandbox Authorization template** (chưa điền tên/ký) theo 8 mục bắt buộc ở [SPEC §6.2](./SECWEAVE_SPEC.md#62-approval-vs-authorization-vs-execution-release--ba-khái-niệm-không-được-lẫn).
- Chuẩn bị **Gate 1 decision record**: khuyến nghị NxKeeper / chuyển sandbox / No-Go, kèm bằng chứng cho từng tiêu chí.

**Chức năng hoàn thiện cuối tuần:**
- Discovery Report + Map + gap register hoàn chỉnh, có provenance cho mọi fact.
- Bộ hypothesis + tiêu chí quan sát viết tay (tabletop) cho ít nhất 1 hero scenario — đây **không phải code**, là bằng chứng phương pháp (method baseline), dùng làm input thiết kế thật ở W3.

**Kế hoạch test:**
- **So sánh tabletop độc lập:** đối chiếu hypothesis Nam viết với hypothesis Phúc viết cho cùng scenario. Nếu hai bản khác nhau về tiêu chí quan sát (một bên viết được predicate máy đọc được, một bên không) → dấu hiệu Discovery Report còn thiếu thông tin, cần hỏi lại owner trước khi kết luận `NX-GO-05`.
- **Checklist đối chiếu 9 tiêu chí:** mỗi tiêu chí phải có ô "nguồn trích dẫn" điền được — tiêu chí nào không điền được nguồn thì tự động là "Chưa đủ dữ liệu", không được đoán là "Đạt".
- **Review Gate 1:** họp với Sponsor + owner liên quan, đối chiếu Discovery Report với chín tiêu chí, ra quyết định target.

**Gate 1 — checkpoint quan trọng nhất trong Chặng 1.** Ba nhánh có thể xảy ra (SPEC §6.5 + A.html §16.3):
1. **NxKeeper đạt đủ 9 tiêu chí** → tiếp tục sang W3 với NxKeeper là target.
2. **NxKeeper không đạt, sandbox đạt điều kiện** → tiếp tục sang W3 nhưng dựng sandbox tự dựng (A.html §16.4), báo cáo cuối phải mang nhãn "NxKeeper Integration Not Demonstrated".
3. **Cả hai không đạt** → No-Go, dừng dự án tại đây, bàn giao 7 hiện vật value floor (A.html §1.5.1), không có W3–W8.

**Rủi ro cần theo dõi:** R-01 (không target đạt tiêu chí), R-02 (chưa xin được Authorization đúng hạn — theo dõi sớm dù Gate 2 ở W3), R-10 (OQ-013 "ai sẽ dùng đầu ra sau MVP" — nếu câu trả lời là "không ai" → trigger dừng ST-2 ngay tại Gate 1 này, bất kể kỹ thuật có sẵn sàng hay không).

---

## Tuần 3 — Thiết kế chi tiết & Authorization (WP2 → Gate 2)

> **Điều kiện vào tuần này:** Gate 1 đã mở Chặng 2 (nhánh 1 hoặc 2 ở trên). Nếu Gate 1 là No-Go, dự án dừng ở W2 và các tuần từ đây không diễn ra.

**Mục tiêu:** có hồ sơ Target/Sandbox Authorization đã ký (Gate 2) — nhưng **vẫn chưa được chạy** (Gate 2 ≠ Execution Release).

**Công việc kỹ thuật cụ thể:**
- Chốt **hero scenario** cụ thể dựa trên kết quả Discovery (ví dụ: một endpoint đọc object theo `project_id` không kiểm tra quyền sở hữu — nếu đây là dạng được Discovery xác nhận khả thi).
- Viết **Hypothesis chính thức** cho hero scenario theo cấu trúc bắt buộc ([SPEC §4.1](./SECWEAVE_SPEC.md#41-tầng-1--hypothesis-engine)): hành vi kỳ vọng / hành vi nghi ngờ / tiêu chí quan sát / provenance — bản này thay thế bản tabletop viết tay ở W2, giờ đủ chi tiết để lập trình predicate.
- Thiết kế **allowlist hành động** cụ thể: danh sách chính xác method+endpoint được phép gọi, loại dữ liệu mồi cần tạo, khối lượng request tối đa.
- Thiết kế **3 nhóm predicate** (chính / positive control / denied control, [SPEC §4.4.1](./SECWEAVE_SPEC.md#441-ba-nhóm-predicate)) ở dạng đặc tả (chưa code) — xác định: dùng blind marker được không (điều kiện `NX-GO-06`/`NX-GO-09`, [SPEC §4.3.4](./SECWEAVE_SPEC.md#434-blind-marker)), nếu không thì dùng predicate nào thay thế.
- Thiết kế **kế hoạch reset/cleanup** dữ liệu mồi (TTL, cơ chế xoá).
- Nếu dùng sandbox: viết `Dockerfile`/`docker-compose.yml` cho reference app, định nghĩa behavior đã biết trước (để predicate có "đáp án đúng" kiểm được).
- Soạn và trình ký **hồ sơ Target/Sandbox Authorization** chính thức: owner, scope, revision (pin theo `NX-GO-04`), identity, allowed/prohibited actions, window, caps, stop-work contact, cleanup, expiry.
- Trả lời **OQ-015** (intake/severity/notification/remediation handoff khi có `CONFIRMED`) và chốt vào hồ sơ Gate 2.

**Chức năng hoàn thiện cuối tuần:**
- Hồ sơ Authorization đã ký, có đủ 8 mục bắt buộc.
- Đặc tả predicate + allowlist ở dạng tài liệu (chưa phải code chạy) đủ chi tiết để tuần sau lập trình thẳng không cần thiết kế lại.
- (Nếu sandbox) container chạy được cục bộ, có thể reset về trạng thái sạch bằng một lệnh.

**Kế hoạch test:**
- **Review chéo predicate:** người không viết hero scenario (Phúc nếu Nam viết, và ngược lại) đọc đặc tả predicate, tự hỏi "với bộ predicate này, một response ngẫu nhiên có thể vô tình làm `CONFIRMED` sai không?" — nếu có kịch bản false-positive rõ ràng, phải sửa trước khi trình Gate 2.
- **Checklist hồ sơ Authorization:** đối chiếu với 8 mục bắt buộc ([SPEC §6.2](./SECWEAVE_SPEC.md#62-approval-vs-authorization-vs-execution-release--ba-khái-niệm-không-được-lẫn)) — thiếu mục nào thì hồ sơ không hợp lệ, không tiếp tục.
- (Nếu sandbox) **smoke test container:** `docker-compose up` → gọi 1 endpoint biết trước kết quả → `docker-compose down && up` → gọi lại, xác nhận trạng thái sạch (không có state rò rỉ giữa hai lần chạy) — điều kiện tiên quyết để reproducibility test ở W7 có ý nghĩa.

**Rủi ro cần theo dõi:** R-03 (kịch bản hero không kiểm chứng được bằng máy — nếu review chéo phát hiện vấn đề này, phải quay lại sửa predicate trước khi sang W4, không mang nợ kỹ thuật này sang tuần sau); R-12 (ràng buộc hợp đồng khách hàng — `NX-GO-01` phải xác nhận lại ở bước ký chính thức, không chỉ dựa vào đánh giá sơ bộ ở Gate 1).

---

## Tuần 4 — Hypothesis Engine (WP3a)

**Mục tiêu:** Hypothesis Engine chạy được thật (có gọi LLM), sinh giả thuyết có cấu trúc từ tín hiệu thật của target/sandbox đã chọn.

**Công việc kỹ thuật cụ thể:**
- Implement các adapter chuẩn hoá tín hiệu ([SPEC §4.1.1](./SECWEAVE_SPEC.md#411-chuẩn-hoá-tín-hiệu-đầu-vào--normalizedsignal)): `SemgrepAdapter` (bắt buộc, đường mặc định), và `TrivyAdapter`/`ZapAdapter` **chỉ nếu** ngôn ngữ/loại target phù hợp và đã được xác nhận ở Discovery — không lắp thêm adapter "cho đủ" nếu target không cần.
  - Với ZAP: **chỉ implement adapter đọc report có sẵn** (passive/baseline), **không** implement code tự kích hoạt active scan trong tuần này — đúng cảnh báo governance ở [SPEC §10.1](./SECWEAVE_SPEC.md#101-tech-stack).
- Implement `Signal Normalizer` orchestrator: nhận report thô → chọn đúng adapter theo `source.tool` → trả `NormalizedSignal`.
- Implement `Hypothesis Engine` core: input = `NormalizedSignal` + source code đã duyệt + context `verified` từ Context Store (rỗng ở lượt đầu) → gọi LLM (Kiro/provider đã duyệt) để sinh hypothesis → validate output khớp schema `Hypothesis` bắt buộc 4 trường ([SPEC §4.1](./SECWEAVE_SPEC.md#41-tầng-1--hypothesis-engine)).
- Implement quy tắc "không kiểm chứng được": nếu LLM không tạo ra được đủ 4 trường hợp lệ, Engine phải trả trạng thái từ chối rõ ràng, không cố "vá" bằng giá trị rỗng/giả.
- Chạy Hypothesis Engine trên **Semgrep output thật** của source code target/sandbox đã duyệt đọc — sinh hypothesis thử nghiệm cho đúng hero scenario đã chốt ở W3, đối chiếu với hypothesis viết tay ở W3.
- Implement Security Context Store tối thiểu (SQLite, [SPEC §4.6](./SECWEAVE_SPEC.md#46-security-context-store)) — chỉ phần đọc `verified` context (chưa có gì để đọc thật ở lượt đầu, nhưng interface phải tồn tại từ tuần này vì Hypothesis Engine phụ thuộc vào nó).

**Chức năng hoàn thiện cuối tuần:**
- Chạy được lệnh (ví dụ) `secweave hypothesize --signal semgrep_report.json --target-revision-id <rev>` → xuất ra một `Hypothesis` JSON hợp lệ hoặc thông báo "không kiểm chứng được" — toàn bộ **không gửi request nào ra target**, chỉ đọc source + gọi LLM.
- `NormalizedSignal` sinh từ Semgrep report thật của target khớp đúng schema đã đặc tả.

**Kế hoạch test:**
- **Unit test adapter (golden-file):** với `fixtures/semgrep_sample_report.json` cố định → assert `NormalizedSignal` output khớp bit-for-bit bản đã duyệt trước, đặc biệt đúng ánh xạ `rule.id`, `severity.raw→normalized`, `location` theo bảng ánh xạ ([SPEC §4.1.1](./SECWEAVE_SPEC.md#411-chuẩn-hoá-tín-hiệu-đầu-vào--normalizedsignal)).
- **Test CWE cụ thể:** dùng 1 file mẫu có lỗi biết trước (ví dụ SQLi giả lập cùng ngôn ngữ với target) → chạy Semgrep → Normalizer → assert `rule.cwe` chứa `CWE-89`.
- **Negative/property test:** đưa `NormalizedSignal` cố ý thiếu context (ví dụ severity `info`, không có snippet) → assert Hypothesis Engine trả về "không kiểm chứng được ở phạm vi hiện tại", **không** tự sinh hypothesis mơ hồ để "có gì đó trả về".
- **Test ranh giới thuật ngữ:** assert không có object `NormalizedSignal` hay `Hypothesis` nào có field tên là `evidence` — chỉ được dùng `signal_context` — bảo vệ đúng cảnh báo ở [SPEC §4.1.1](./SECWEAVE_SPEC.md#411-chuẩn-hoá-tín-hiệu-đầu-vào--normalizedsignal).
- **Review thủ công (Phúc review Nam, hoặc ngược lại):** đọc hypothesis do Engine sinh ra cho hero scenario, xác nhận tiêu chí quan sát đủ cụ thể để viết predicate ở W5 — nếu không, đây là tín hiệu cần tinh chỉnh prompt/Engine trước khi sang tuần sau, không phải nợ kỹ thuật mang tiếp.

**Rủi ro cần theo dõi:** R-05 (không được cấp quyền Codex Security beta — nếu adapter đó nằm trong kế hoạch, có phương án fallback là bỏ, dùng Semgrep làm đường mặc định, không chặn tuần này).

---

## Tuần 5 — Exploit Agent + Policy/Identity (WP3b)

**Mục tiêu:** có action plan hợp lệ, đối chiếu allowlist tự động — nhưng **vẫn chưa gửi request nào tới target** (chưa qua Gate 3).

**Công việc kỹ thuật cụ thể:**
- Implement **Policy Service**: đọc allowlist từ hồ sơ Gate 2 (dạng file cấu hình đã ký ở W3), expose `is_allowed(action: ActionSpec) -> PolicyDecision` trả về pass/fail + lý do.
- Implement **Identity Service**: quản lý test identity theo hồ sơ Gate 2 — **không** có đường nào trong code đọc/dùng tài khoản cá nhân của Nam/Phúc.
- Implement **Exploit Agent core**: input = `Hypothesis` (từ W4) → gọi LLM để soạn action plan (chuỗi hành động dự kiến) → với **mỗi hành động**, gọi Policy Service kiểm tra → nếu có ≥1 hành động fail, toàn bộ plan bị chặn (không tự động lược bỏ hành động fail rồi chạy phần còn lại — đúng nguyên tắc deny-by-default).
- Implement khung **Cost Service**: đếm số hành động dự kiến trong plan, so với cap (giờ mới đếm dự kiến, tuần sau mới đếm hành động thật).
- Viết **predicate nhóm 1/2/3** ở dạng code (`predicate_fn(observation: NormalizedObservation) -> PredicateResult`) theo đặc tả đã chốt ở W3 — **DRAFT, chưa freeze** (freeze diễn ra ở Gate 3, W6).
- Chạy **dry-run trên giấy**: đối chiếu action plan sinh ra với allowlist bằng tay, xác nhận Policy Service ra quyết định giống người xem xét bằng tay — chưa có Evidence Harness thật nên chưa gửi gì đi.

**Chức năng hoàn thiện cuối tuần:**
- Exploit Agent sinh action plan từ Hypothesis W4, mọi hành động trong plan đã qua Policy check, có log lý do pass/fail.
- Predicate code tồn tại và unit-test được độc lập với Evidence Harness (dùng observation giả lập).

**Kế hoạch test:**
- **Adversarial test Policy Service (bắt buộc):** viết ≥ 5 `ActionSpec` cố ý vi phạm allowlist theo từng kiểu (method sai, endpoint ngoài danh sách, hành động DELETE/UPDATE dữ liệu hiện hữu, vượt cap số lượng, ngoài cửa sổ thời gian) → assert **100%** bị `is_allowed() == False` kèm lý do đúng. Đây là test nền cho chỉ số "0 hành động ngoài allowlist" ([SPEC §8.1](./SECWEAVE_SPEC.md#81-bốn-nhóm-chỉ-số)) — phải xanh tuyệt đối trước khi sang W6.
- **Unit test Identity Service:** assert không có code path nào trả về giá trị đọc từ biến môi trường/config cá nhân (kiểm bằng cách mock hết nguồn identity, chỉ chấp nhận identity từ hồ sơ Gate 2 đã nạp).
- **Unit test predicate (golden-file):** với `NormalizedObservation` giả lập cố định cho từng nhóm (chính/positive control/denied control) → assert đúng verdict-per-predicate (satisfied/unsatisfied/insufficient_data).
- **Integration test có mock:** Hypothesis (fixture từ W4) → Exploit Agent → action plan → Policy Service, toàn bộ chạy end-to-end nhưng **không** có `httpx` thật nào được gọi (chưa cần vì Evidence Harness chưa build) — xác nhận contract dữ liệu giữa Tầng 1 và Tầng 2 đúng như [SPEC §3.1](./SECWEAVE_SPEC.md#31-entity-chính-và-quan-hệ).

**Rủi ro cần theo dõi:** R-07 (phạm vi phình — nếu trong lúc viết allowlist có ai đề nghị "thử luôn cho endpoint khác", đây là tín hiệu scope creep, từ chối và ghi vào backlog hậu-MVP, không đưa vào allowlist tuần này).

---

## Tuần 6 — Evidence Harness, Oracle, Kill-switch, Dry-run (WP3c+WP3d → Gate 3)

> **Đây là tuần an toàn-trọng yếu nhất của Chặng 2** — Gate 3 là điểm duy nhất mở khóa active run trên target/sandbox thật. Không có đường tắt qua tuần này.

**Mục tiêu:** toàn bộ pipeline 4 tầng chạy thông (dry-run, không tác động thật), Execution Release được ký.

**Công việc kỹ thuật cụ thể:**
- Implement **Evidence Harness**: wrapper quanh `httpx`, mọi request/response đi qua đây được lưu tự động (transcript đầy đủ), tính hash SHA-256 từng artifact, gắn metadata bắt buộc (timestamp, identity, execution_id, target, revision, channel, size) — theo [SPEC §4.3.2](./SECWEAVE_SPEC.md#432-kênh-thu-bằng-chứng-active-run-sau-gate-3).
- Implement **blind marker mechanism** ([SPEC §4.3.4](./SECWEAVE_SPEC.md#434-blind-marker)) — nếu điều kiện áp dụng được: sinh random string, ghi seed manifest ở vùng chỉ Harness+Oracle đọc, cơ chế inject vào dữ liệu mồi **qua đường setup riêng, không qua context của Exploit Agent/LLM nào**.
- Implement **redaction**: áp danh sách field nhạy cảm (đã chốt cùng owner) trước khi lưu bất kỳ artifact.
- Implement **kill-switch**: một lệnh/API dừng được execution đang `RUNNING` → chuyển `STOPPED`, trigger cleanup đã duyệt, ghi audit log — gọi được từ ≥ 5 vai trò khác nhau theo [SPEC §6.3](./SECWEAVE_SPEC.md#63-kill-switch--stop-work--năm-nguồn-người--một-ngưỡng-tự-động).
- Implement **Cost Service thật**: đếm request/hành động thực tế trong lúc chạy, tự động trigger `STOPPED` khi chạm cap.
- Implement **Verdict Oracle**: đọc `NormalizedObservation` do Harness sinh → chạy predicate (đã viết ở W5) → trả đúng 1 trong 3 verdict theo logic ở [SPEC §4.4.3](./SECWEAVE_SPEC.md#443-version-hóa-rule).
- **Freeze** tại cuối tuần (điều kiện bắt buộc để có Gate 3): allowlist, tập predicate/controls, mọi cap, kế hoạch cleanup, kill-switch, và **rubric/threshold ECS** (OQ-019/UD-02, [SPEC §7](./SECWEAVE_SPEC.md#7-verification-package--19-trường)) — ghi toàn bộ vào Execution Release.
- **Dry-run sạch:** chạy toàn bộ pipeline trên target/sandbox thật nhưng chỉ với hành động **không tác động** (ví dụ GET vào dữ liệu mồi test đã biết trước, không phải request thật của hero scenario) để xác nhận: Harness ghi đúng artifact/hash, seed manifest hoạt động, Cost Service đếm đúng, kill-switch dừng được giữa chừng.

**Chức năng hoàn thiện cuối tuần:**
- Pipeline 4 tầng chạy thông từ Hypothesis → action plan → Evidence Harness (thật, có network call tới sandbox/staging) → Oracle → verdict, trong một dry-run không tác động.
- Execution Release đã ký, mọi thứ cần freeze đã freeze.

**Kế hoạch test (an toàn là ưu tiên số 1 tuần này — không rút gọn):**
- **Unit test toàn vẹn hash:** lưu artifact → sửa 1 byte trong bản lưu → assert Oracle **từ chối** `CONFIRMED` do hash mismatch (control #8, [SPEC §6.4](./SECWEAVE_SPEC.md#64-mười-ba-control-không-có-ngoại-lệ-trong-mvp)).
- **Unit test cách ly blind marker:** serialize toàn bộ object mà Hypothesis Engine và Exploit Agent tạo ra (hypothesis, action plan, log) → assert **không object nào** chứa giá trị marker của lượt chạy đó.
- **Unit test redaction:** artifact test có field giả dạng secret (password/token mẫu) → assert sau redaction field đó bị che, không xuất hiện trong bản lưu cuối.
- **Kill-switch drill (bắt buộc, có checklist ký):** trong dry-run, kích hoạt dừng từ **từng nguồn** — operator, owner (giả lập), ngưỡng cost cap tự động — mỗi nguồn thử riêng một lần → assert 100% chuyển `STOPPED`, cleanup chạy đúng kế hoạch đã duyệt, audit log ghi đủ ai/khi nào/vì sao.
- **Cost cap test:** đặt cap thấp giả lập, chạy dry-run vượt cap → assert hệ thống tự `STOPPED` **trước khi** vượt cap thật.
- **Dry-run acceptance (ký duyệt):** owner target/sandbox xem lại log dry-run, xác nhận 0 tác động ngoài dự kiến → ký Execution Release. **Nếu owner không ký được trong tuần này, không có Gate 3, không có W7 — không tự chuyển sang chạy thật khi chưa ký.**

**Rủi ro cần theo dõi:** R-09 (tác động ngoài ý muốn — mọi lần dry-run phát hiện bất kỳ hành động lọt ra ngoài allowlist, dù chỉ 1 lần, phải dừng và sửa Policy Service trước khi xin ký, không được xem là "chấp nhận được vì hiếm"); rủi ro lịch trình đã nêu ở §0 (96 giờ WP3c+WP3d có thể cần hơn 1 tuần — nếu vậy, ưu tiên kill-switch + Oracle tất định đúng trước, có thể dịch phần đo ECS chi tiết sang đầu W7 mà không ảnh hưởng Gate 3, vì threshold chỉ cần *freeze giá trị*, không cần đã có dữ liệu đo).

---

## Tuần 7 — Active run, Retest, Review (WP4 → Gate 4)

**Mục tiêu:** có ít nhất một Verification Package hoàn chỉnh, đã qua human review.

**Công việc kỹ thuật cụ thể:**
- Chạy **active run đầu tiên** cho hero scenario, đúng theo Execution Release đã freeze ở W6 — không đổi allowlist/predicate/cap giữa chừng.
- Evidence Harness thu raw evidence thật (HTTP transcript, screenshot/video nếu kịch bản có UI, log ứng dụng trong cửa sổ chạy).
- Oracle chạy predicate trên observation thật → verdict thật (`CONFIRMED`/`NOT REPRODUCED`/`INCONCLUSIVE`).
- **Retest ≥ 3 lần** cùng scenario/revision (script tự động lặp lại toàn bộ luồng) — ghi tỷ lệ cùng verdict.
- Soạn **Verification Package** đầy đủ 19 trường ([SPEC §7](./SECWEAVE_SPEC.md#7-verification-package--19-trường)), đặc biệt trường 17 (Limitations) viết cẩn thận, đúng phạm vi đã kiểm.
- Gửi package cho **người review/releaser** (Gate 4, OQ-016): họ đối chiếu ≥ 1 raw artifact với normalized observation, kiểm hash, schema, verdict/limitations → quyết định release / yêu cầu retest / bác bỏ.
- Nếu verdict là `CONFIRMED`: xử lý theo quy trình A.html §9.9 — gửi owner hệ thống trong vòng 1 ngày làm việc, **không** tự tạo ticket, **không** tự thông báo rộng.

**Chức năng hoàn thiện cuối tuần:**
- Verification Package đầu tiên tồn tại, đủ 19 trường, đã qua Gate 4.
- Số liệu retest (x/3 lần cùng verdict) đã có, dù đạt hay không đạt ngưỡng đề xuất.

**Kế hoạch test:**
- **Acceptance test theo 3 nhóm predicate:** xác nhận package có đủ kết quả của **cả 3 nhóm** predicate (chính/positive control/denied control) — thiếu nhóm 2 (positive control) thì **tuyệt đối không được** `CONFIRMED`, bất kể nhóm 1 thế nào (control #13, [SPEC §6.4](./SECWEAVE_SPEC.md#64-mười-ba-control-không-có-ngoại-lệ-trong-mvp)).
- **Reproducibility test:** đối chiếu verdict qua 3 lần retest — nếu tỷ lệ < 2/3 cùng verdict, **bắt buộc ghi vào Limitations**, không được chọn verdict "đẹp nhất" trong 3 lần để báo cáo (đây là hành vi bị cấm, tương đương gian lận bằng chứng).
- **Review checklist Gate 4:** người review xác nhận đã tự tay đối chiếu ≥ 1 raw artifact (không chỉ đọc summary do AI viết ở trường Report) — bắt buộc theo [SPEC §4.5](./SECWEAVE_SPEC.md#45-human-review-loop).
- **Handover dry-run (chuẩn bị cho W8):** người thứ hai (không phải người viết action plan gốc) đọc package độc lập, thử diễn giải lại verdict + Limitations mà không hỏi tác giả — nếu hiểu sai, đây là tín hiệu package viết chưa đủ rõ, sửa trước khi coi là "final".

**Rủi ro cần theo dõi:** R-04 (kết quả flaky — nếu retest cho kết quả khác nhau, không giấu, không chạy thêm lần thứ 4-5-6 để "chọn kết quả tốt hơn"; ghi đúng x/3 và để Human Review quyết định release/retest); R-13 (nếu `CONFIRMED` thật xuất hiện, theo đúng OQ-015 đã chốt ở Gate 2 — không tự sáng tạo quy trình mới giữa chừng).

---

## Tuần 8 — Đo lường, Bàn giao, Closeout (WP5+WP6 → Gate 5)

**Mục tiêu:** Pilot Decision Package hoàn chỉnh, bàn giao ở mức "người khác chạy lại được", Sponsor ra quyết định hậu-MVP.

**Công việc kỹ thuật cụ thể:**
- Đo đủ **4 nhóm chỉ số** ([SPEC §8.1](./SECWEAVE_SPEC.md#81-bốn-nhóm-chỉ-số)): schema completeness, ECS theo rubric đã freeze ở Gate 3, tỷ lệ lặp lại (từ W7), hiệu quả kiểm soát (đối chiếu toàn bộ audit log của dự án với allowlist).
- Viết **runbook**: hướng dẫn cài đặt/chạy, danh mục dependency + biến môi trường, ghi chú các chỗ dễ hỏng đã gặp trong quá trình làm (ví dụ: adapter nào từng lỗi, predicate nào từng phải sửa).
- **Handover test chính thức:** người thứ hai chạy lại toàn bộ kịch bản **chỉ bằng runbook**, không hỏi tác giả — ghi nhận thành công/không thành công, đây là số liệu chính thức cho chỉ số "khả năng bàn giao".
- Soạn **Pilot Decision Package** (13 phần bắt buộc, A.html §20.2): kết quả Discovery; quyết định target; mô tả prototype; package mẫu; công sức thực tế vs planning envelope; chi phí thực tế vs cap; schema completeness; ECS; kết quả lặp lại; kết quả kiểm soát an toàn; kết quả bàn giao; giới hạn đã biết; khuyến nghị bước tiếp.
- Đánh giá **pilot outcome** (thành công / thành công một phần / thất bại) theo tiêu chí A.html §19 — nhắc lại: verdict của hero scenario **không** tự quyết định outcome này.
- Chuẩn bị đề xuất cho Sponsor tại Gate 5: **UD-04** (chủ sở hữu sau MVP: O-1 tiếp tục / O-2 bàn giao / O-3 đóng băng có ý thức) và **UD-01** (CI/CD advisory — chỉ nêu dữ liệu độ tin cậy thu được, không tự đề xuất chặn build).

**Chức năng hoàn thiện cuối tuần:**
- Runbook + Pilot Decision Package hoàn chỉnh, lưu ở nơi Sponsor chỉ định (OQ-017).
- Toàn bộ test suite từ W1–W7 chạy xanh một lần cuối trước khi đóng gói.

**Kế hoạch test:**
- **Final regression:** chạy lại toàn bộ unit test + integration test đã viết từ W1 đến W7 trong một lần, xác nhận không có regression do các thay đổi freeze ở W6/W7.
- **Audit log full review:** đối chiếu 100% audit log của toàn bộ Chặng 2 với allowlist đã ký — mục tiêu là xác nhận đúng con số "0 hành động ngoài allowlist" cho **toàn bộ** dự án, không chỉ tuần có test adversarial (W5); nếu phát hiện vi phạm nào trước đó chưa từng bị bắt, phải ghi vào Pilot Decision Package, không được bỏ qua vì "dự án đã xong".
- **Checklist đủ 13 phần Pilot Decision Package** — thiếu phần nào thì gói chưa đủ điều kiện trình Gate 5.
- **Handover test** đã mô tả trên — là bài test cuối cùng và quan trọng nhất của cả dự án: nếu người thứ hai **không** chạy lại được, R-06 (không ai duy trì sau MVP) trở thành rủi ro đã hiện thực hoá ngay trong pilot, không phải rủi ro giả định — phải ghi thẳng vào Pilot Decision Package.

**Rủi ro cần theo dõi:** R-06 (không người duy trì — quyết định O-1/O-2/O-3 phải chốt tại Gate 5 này, không để trôi sau closeout).

---

## 10. Ma trận truy vết: tuần → chức năng → test → tiêu chí nghiệm thu

| Tuần | Chức năng chính giao | Test then chốt | Tiêu chí nghiệm thu tham chiếu |
|---|---|---|---|
| W1 | Data model skeleton, OQ tracker | Unit test schema Pydantic | — (chưa có Gate kỹ thuật) |
| W2 | Discovery Report, Map, 9 tiêu chí Go/No-Go | So sánh tabletop độc lập | Gate 1 (A.html §9.3) |
| W3 | Hero scenario, allowlist, Authorization đã ký | Review chéo predicate, checklist hồ sơ | Gate 2 |
| W4 | Signal Normalizer + Hypothesis Engine | Golden-file adapter, negative test | — |
| W5 | Exploit Agent + Policy/Identity | Adversarial test allowlist (100% chặn) | Chỉ số "0 hành động ngoài allowlist" (SPEC §8.1) |
| W6 | Evidence Harness + Oracle + kill-switch, dry-run sạch | Kill-switch drill, hash integrity test | Gate 3 |
| W7 | Verification Package đầu tiên, human review | Reproducibility test, acceptance 3 nhóm predicate | Gate 4, chỉ số lặp lại ≥ 2/3 |
| W8 | Runbook, Pilot Decision Package | Handover test, audit log full review | Gate 5, tiêu chí thành công A.html §19 |

---

*Tài liệu này triển khai chi tiết lịch trình ở `A.html` Mục 13 và kiến trúc ở `SECWEAVE_SPEC.md`. Khi có mâu thuẫn về phạm vi/điều kiện phê duyệt, `A.html` vẫn là nguồn authoritative — lịch tuần cụ thể ở đây chỉ có giá trị thực thi sau khi Gate tương ứng đã mở.*
