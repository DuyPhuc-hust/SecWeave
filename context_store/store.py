import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.id_generator import generate_id
from shared.models.hypothesis import HypothesisResult, HypothesisStatus
from shared.models.signal import NormalizedSignal

DEFAULT_DB_PATH = ".secweave/context.db"

# SPEC §4.6: "Kết luận 'an toàn' không có thời hạn" is explicitly one of the
# things this store must NEVER hold — every verified fact must expire on its
# own, not rely solely on a human remembering to mark it stale. SPEC doesn't
# name an exact duration, so this is a judgment call, not a spec value: 90
# days matches the common quarterly re-verification cadence used elsewhere in
# security/compliance tooling (e.g. OWASP DefectDojo's "risk acceptance"
# feature — real prior art checked, not assumed — requires an expiration
# date for exactly this reason: to stop "accepted risk" from silently
# becoming "forgotten risk"). Callers can override per-call if a target's own
# policy needs a different window.
DEFAULT_VALID_FOR_DAYS = 90

# SPEC §4.6's write-path diagram has a real content this dict encodes: a
# verified_observation's status is either "unverified" (Evidence Harness just
# captured it, no independent human confirmation yet) or "verified" (Human
# Review released the package it came from). This is DELIBERATELY a separate
# axis from `stale` (below) — real prior art checked: OWASP Dependency-Track
# keeps "is this actually exploitable" (an analysis STATE) and "should this
# be hidden from view" (a SUPPRESSED boolean) as two independent fields for
# exactly this reason (confirmed via its docs: NOT_AFFECTED/FALSE_POSITIVE
# findings still get suppressed as a distinct, separate action) — conflating
# "was this ever confirmed" with "do we still trust it today" would make it
# impossible to tell "never verified" apart from "was verified, later
# superseded by a code change."
STATUS_UNVERIFIED = "unverified"
STATUS_VERIFIED = "verified"

# SPEC's own wording for this table's content is "quan sát đã xác nhận bằng
# bằng chứng" (an observation confirmed by evidence) and "lý do một mẩu ngữ
# cảnh bị đánh dấu là cũ" (the REASON a piece of context is marked stale) —
# both explicitly plain-language, unlike some prior-art formats. Real prior
# art checked and deliberately NOT copied: VEX (CISA/OpenVEX, confirmed via
# its spec) requires `status=not_affected` to carry one of exactly 5 fixed
# justification codes (component_not_present, vulnerable_code_not_present,
# etc.) — a closed vocabulary makes automated cross-tool comparison possible,
# which matters for VEX's use case (many tools/vendors exchanging exploitability
# claims about the same CVE) but isn't this store's problem (single tool,
# single team, reason is read by a human reviewer or an LLM prompt, not
# machine-compared against another tool's taxonomy). Forcing SPEC's plain
# "lý do" into a fixed enum would be inventing a constraint SPEC never asked
# for — kept as free text on purpose.

_LEGACY_MIGRATION_SENTINEL = ""  # see _migrate_add_missing_columns' verified_at note


def _require_revision(revision: str) -> None:
    """A blank revision would silently match every legacy row backfilled
    to '' (see _migrate_add_missing_columns' `revision` note) — those
    rows mean "we don't actually know what revision this was," not "this
    matches any/every revision," so an empty value here is always a
    caller mistake, not a legitimate query.

    This store treats `revision` as CONTENT-ADDRESSED and
    IMMUTABLE (SPEC §10.1: "Quản lý phiên bản | Git | Gắn revision vào
    package" — i.e. a git SHA, not a mutable label). Exact-string matching
    (this function + get_verified_context/get_unverified_context's own
    `revision = ?`) is only a valid staleness guard under that assumption
    — the SAME string genuinely means the SAME code. A caller passing a
    MUTABLE label instead (a moved tag, a reused build counter, a branch
    name) would silently reopen the exact staleness gap this mechanism
    exists to close: an old fact verified under an earlier meaning of that
    label would look fresh again the moment the label is reused. Nothing
    in this class can detect that misuse — it's a contract on the
    caller's own revision identifier, not something checkable here.
    """
    if not revision:
        raise ValueError(
            "revision không được rỗng — SecurityContextStore không đối chiếu 'không rõ revision' với "
            "'khớp mọi revision'; nếu chưa biết revision hiện tại của target, đừng gọi hàm này."
        )


class SecurityContextStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        if db_path != ":memory:":
            try:
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                # A plain OSError here (e.g. a parent path component is an
                # existing regular file, not a directory) would otherwise
                # escape uncaught past every cli.py call site, which only
                # catches sqlite3.Error around construction. Re-raised as
                # sqlite3.OperationalError (a sqlite3.Error subclass) so
                # "the store couldn't be opened" has exactly ONE exception
                # type to catch, regardless of whether the failure was
                # directory creation or the sqlite connection itself.
                raise sqlite3.OperationalError(
                    f"Không tạo được thư mục chứa Context Store tại '{db_path}': {exc}"
                ) from exc
        self._conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS verified_observations (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                package_id TEXT,
                valid_until TEXT,
                stale INTEGER NOT NULL DEFAULT 0,
                stale_reason TEXT,
                revision TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hypotheses (
                row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                hypothesis_id TEXT UNIQUE,
                signal_id TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                status TEXT NOT NULL,
                expected_behavior TEXT,
                suspected_behavior TEXT,
                observation_criteria TEXT,
                reason TEXT,
                coverage TEXT NOT NULL,
                location TEXT,
                created_at TEXT NOT NULL,
                target_id TEXT,
                revision TEXT
            )
            """
        )
        self._migrate_add_missing_columns()
        self._conn.commit()

    def _migrate_add_missing_columns(self) -> None:
        # "CREATE TABLE IF NOT EXISTS" doesn't add new columns to a table
        # that already existed before (e.g. a .secweave/context.db created by
        # an older version of the code) — without this, every subsequent
        # call touching a new column would break with "no such column"
        # instead of a clear error. The MVP doesn't need a full migration
        # framework yet, just enough to not lose old data when the schema
        # adds a new column.
        existing_hyp_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(hypotheses)")}
        if "location" not in existing_hyp_columns:
            self._conn.execute("ALTER TABLE hypotheses ADD COLUMN location TEXT")
        # A hypothesis carries no record of which target_id/revision it was
        # generated for on its own — without these columns, a stale
        # hypothesis generated against an old revision could be
        # `plan`ned/`execute`d later with no automatic cross-check at all.
        # NULL (not backfilled to '' — unlike verified_observations'
        # `revision`, this is genuinely optional metadata, not something
        # every write path is required to always know) for pre-existing
        # rows AND for any new hypothesize() call made without
        # --target-id — see
        # _load_hypothesis_from_context_store's own warning logic for how a
        # NULL here is treated (never compared, since there's nothing to
        # compare against).
        if "target_id" not in existing_hyp_columns:
            self._conn.execute("ALTER TABLE hypotheses ADD COLUMN target_id TEXT")
        if "revision" not in existing_hyp_columns:
            self._conn.execute("ALTER TABLE hypotheses ADD COLUMN revision TEXT")

        existing_vo_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(verified_observations)")}
        # Every row in a pre-existing DB was written under the OLD schema,
        # which had no unverified/verified distinction at all — the only
        # meaning-preserving backfill is to treat every such row as already
        # STATUS_VERIFIED (it was already being served by the old
        # get_verified_context() as trusted fact) with no expiry (NULL
        # valid_until — see get_verified_context()'s own handling: a NULL
        # valid_until on an old row is treated as "not yet migrated to the
        # new expiry model," not as "never expires," and is excluded rather
        # than silently trusted forever).
        if "created_at" not in existing_vo_columns:
            # Pre-existing rows never had a separate "first captured" vs
            # "verified" timestamp (the old schema only had verified_at) —
            # backfilling with verified_at's own value is the closest
            # meaning-preserving default (both timestamps are equal for a
            # row where we don't actually know when it was first captured).
            self._conn.execute("ALTER TABLE verified_observations ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
            self._conn.execute("UPDATE verified_observations SET created_at = verified_at WHERE created_at = ''")
        if "execution_id" not in existing_vo_columns:
            self._conn.execute("ALTER TABLE verified_observations ADD COLUMN execution_id TEXT NOT NULL DEFAULT ''")
        if "status" not in existing_vo_columns:
            self._conn.execute(
                f"ALTER TABLE verified_observations ADD COLUMN status TEXT NOT NULL DEFAULT '{STATUS_VERIFIED}'"
            )
        if "package_id" not in existing_vo_columns:
            self._conn.execute("ALTER TABLE verified_observations ADD COLUMN package_id TEXT")
        if "valid_until" not in existing_vo_columns:
            self._conn.execute("ALTER TABLE verified_observations ADD COLUMN valid_until TEXT")
        if "stale" not in existing_vo_columns:
            self._conn.execute("ALTER TABLE verified_observations ADD COLUMN stale INTEGER NOT NULL DEFAULT 0")
        if "stale_reason" not in existing_vo_columns:
            self._conn.execute("ALTER TABLE verified_observations ADD COLUMN stale_reason TEXT")
        if "revision" not in existing_vo_columns:
            # Without this column, get_verified_context() would keep
            # serving a still-fresh (stale=0, valid_until not expired)
            # fact from an OLD revision as trusted context even after the
            # target's code had since changed, with nothing to detect the
            # mismatch automatically short of an operator remembering to
            # call mark_stale(). A pre-existing row has no way to know
            # what revision it was really verified against, so it
            # backfills to '' — same "unknown, therefore not
            # trustworthy" treatment as a migrated NULL valid_until
            # above, not "matches every revision."
            self._conn.execute("ALTER TABLE verified_observations ADD COLUMN revision TEXT NOT NULL DEFAULT ''")

    def record_unverified_observation(
        self, target_id: str, execution_id: str, description: str, revision: str
    ) -> str:
        """Write path step 1 (SPEC §4.6 diagram: "Evidence Harness --ghi
        quan sát, trạng thái = unverified--> Context Store"). Called by
        EvidenceHarness.capture() right after a real observation is
        captured — this is NOT evidence of a confirmed vulnerability, only a
        mechanical record that "this observation happened," pending
        independent human review. `verified_at`/`valid_until` are left at
        the "not yet" sentinel (see get_verified_context/get_unverified_
        context for how each field is interpreted) until
        promote_execution_to_verified() runs.

        `description` must never contain a blind marker's actual value or
        any credential (SPEC §4.6's explicit "never store" list) — callers
        are trusted to pass a mechanical summary (action + access_result +
        status_code), never raw response content.

        `revision` (e.g. EvidenceHarness's own target_revision_id) is what
        lets get_verified_context/get_unverified_context automatically stop
        serving this fact once the target has moved past this revision —
        see this class's revision-staleness fix for the full reasoning.
        Required, non-empty (see _require_revision) — an empty value would
        otherwise silently match legacy pre-migration rows, which are
        deliberately backfilled to '' to mean "unknown, not trustworthy."
        """
        _require_revision(revision)
        observation_id = generate_id("ctxobs")
        try:
            self._conn.execute(
                """
                INSERT INTO verified_observations (
                    id, target_id, execution_id, description, status,
                    created_at, verified_at, package_id, valid_until, stale, stale_reason, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, NULL, ?)
                """,
                (
                    observation_id,
                    target_id,
                    execution_id,
                    description,
                    STATUS_UNVERIFIED,
                    datetime.now(timezone.utc).isoformat(),
                    _LEGACY_MIGRATION_SENTINEL,  # verified_at column is NOT NULL (pre-existing constraint,
                    # can't be relaxed via ALTER TABLE without a full table rebuild) — "" means
                    # "not verified yet," distinct from a real ISO timestamp; status=unverified is the
                    # authoritative signal, this is only a placeholder to satisfy the column constraint.
                    revision,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không ghi được unverified observation cho target_id '{target_id}': {exc}") from exc
        return observation_id

    def promote_execution_to_verified(
        self, execution_id: str, package_id: str, valid_for_days: int = DEFAULT_VALID_FOR_DAYS
    ) -> int:
        """Write path step 2 (SPEC §4.6 diagram: "Human Review --phát hành
        package -> chuyển verified--> Context Store"). Called by
        `secweave review-package` when decision=release — promotes every
        still-unverified observation from this execution to verified, with
        a real expiry (never the unbounded "safe conclusion" SPEC forbids).
        Idempotent-ish: rows already verified (e.g. a 2nd release attempt on
        the same execution) are left untouched, not re-stamped with a new
        expiry — a real reviewer decision should extend trust once, not
        silently refresh it every time someone re-runs this command.
        Returns the number of rows actually promoted.

        `valid_for_days` must be a positive integer, bounded at 3650 (10
        years) — generous for this store's purpose, but still a real
        bound. Without one, a non-positive value would silently promote a
        row to status='verified' with `valid_until` already in the past —
        since this method only ever matches WHERE status='unverified',
        that row could never be promoted again with a correct expiry,
        permanently losing it from get_verified_context(); an absurdly
        large value (near datetime's max representable range) would raise
        an uncaught OverflowError instead of the RuntimeError every other
        failure mode here produces.
        """
        if not 1 <= valid_for_days <= 3650:
            raise ValueError(
                f"valid_for_days phải trong khoảng 1..3650, nhận được: {valid_for_days}"
            )
        now = datetime.now(timezone.utc)
        valid_until = (now + timedelta(days=valid_for_days)).isoformat()
        try:
            cursor = self._conn.execute(
                """
                UPDATE verified_observations
                SET status = ?, verified_at = ?, package_id = ?, valid_until = ?
                WHERE execution_id = ? AND status = ?
                """,
                (STATUS_VERIFIED, now.isoformat(), package_id, valid_until, execution_id, STATUS_UNVERIFIED),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không promote được execution_id '{execution_id}' thành verified: {exc}") from exc
        return cursor.rowcount

    def mark_stale(self, target_id: str, reason: str) -> int:
        """SPEC §4.6's staleness principle, applied literally: "khi có thay
        đổi mà không xác định được chính xác phạm vi ảnh hưởng, hệ thống
        đánh dấu cũ RỘNG HƠN thay vì giữ lại dữ kiện có khả năng sai" (mark a
        BROADER scope stale rather than risk keeping a fact that might now
        be wrong) — so this marks EVERY row for target_id, both verified and
        unverified, not just a narrower subset. A human/operator calls this
        when they know target_id's revision changed but don't know exactly
        which prior findings are still valid — "thà phân tích lại thừa còn
        hơn xây giả thuyết trên nền cũ" (better to over-reanalyze than build
        on stale ground). Returns the number of rows marked.
        """
        try:
            cursor = self._conn.execute(
                "UPDATE verified_observations SET stale = 1, stale_reason = ? WHERE target_id = ? AND stale = 0",
                (reason, target_id),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đánh dấu stale cho target_id '{target_id}': {exc}") from exc
        return cursor.rowcount

    def get_verified_context(self, target_id: str, revision: str) -> List[Dict[str, Any]]:
        # SPEC §4.6 diagram: "giả thuyết lượt sau CHỈ dựa trên verified" —
        # this is the ONLY read path Hypothesis Engine's prompt is built
        # from (see hypothesis_engine/engine.py), so it must never return a
        # stale row or one that's merely unverified. A NULL valid_until on a
        # verified row only happens for rows migrated from the pre-expiry
        # schema (see _migrate_add_missing_columns) — treated as "unknown
        # expiry, so no longer trustworthy" and excluded, not as "trusted
        # forever" (SPEC's explicit ban on unbounded safe conclusions
        # applies here too, not just to newly-written rows).
        #
        # `revision` filters to rows verified against THIS EXACT revision —
        # without it, a fact verified against an old revision would keep
        # being served as trusted context after the target's code had
        # since changed, with nothing detecting the mismatch automatically
        # short of an operator remembering to call mark_stale(). This is a
        # structural read-time guard, not a substitute for mark_stale() —
        # it silently excludes stale-revision rows from THIS query, it
        # doesn't persist anything, so a caller that queries with the
        # WRONG revision by mistake can't accidentally mark real facts
        # stale.
        _require_revision(revision)
        try:
            cursor = self._conn.execute(
                """
                SELECT id, description, verified_at FROM verified_observations
                WHERE target_id = ? AND status = ? AND stale = 0 AND revision = ?
                  AND valid_until IS NOT NULL AND valid_until > ?
                """,
                (target_id, STATUS_VERIFIED, revision, datetime.now(timezone.utc).isoformat()),
            )
            return [
                {"id": row[0], "description": row[1], "verified_at": row[2]}
                for row in cursor.fetchall()
            ]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đọc được verified context cho target_id '{target_id}': {exc}") from exc

    def get_unverified_context(self, target_id: str, revision: str) -> List[Dict[str, Any]]:
        """SPEC §4.6 diagram's dashed arrow: "unverified: chỉ tra cứu, có
        nhãn cảnh báo" — Hypothesis Engine MAY look this up, but every
        result must carry an explicit warning label so nothing downstream
        can mistake it for confirmed fact. Stale unverified rows are
        excluded for the same reason SPEC's staleness principle exists at
        all: a fact that's merely unverified AND stale has strictly less
        going for it than a fresh unverified one. `revision` filters the
        same way get_verified_context() does — see its docstring.
        """
        _require_revision(revision)
        try:
            cursor = self._conn.execute(
                "SELECT id, description, created_at FROM verified_observations "
                "WHERE target_id = ? AND status = ? AND stale = 0 AND revision = ?",
                (target_id, STATUS_UNVERIFIED, revision),
            )
            return [
                {
                    "id": row[0],
                    "description": row[1],
                    "created_at": row[2],
                    "warning": "CHƯA XÁC MINH — quan sát này chưa qua Human Review, không phải bằng chứng đã "
                    "xác nhận (SPEC §4.6). Chỉ dùng để tham khảo, không được coi là kết luận.",
                }
                for row in cursor.fetchall()
            ]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đọc được unverified context cho target_id '{target_id}': {exc}") from exc

    def record_hypothesis(
        self,
        result: HypothesisResult,
        signal: NormalizedSignal,
        target_id: Optional[str] = None,
        revision: Optional[str] = None,
    ) -> None:
        """`target_id`/`revision` are OPTIONAL, unlike verified_observations'
        `revision` (required there) — a hypothesis can legitimately be
        generated with no target_id at all (`hypothesize` without
        --target-id is a supported, common case: no context lookup, just
        turn a signal into a hypothesis). When both ARE known, storing them
        lets a later `plan`/`execute` warn if the hypothesis is being acted
        on for a different target/revision than it was generated for — see
        _load_hypothesis_from_context_store's cross-check.
        """
        is_hypothesis = result.status == HypothesisStatus.HYPOTHESIS
        try:
            self._conn.execute(
                """
                INSERT INTO hypotheses (
                    hypothesis_id, signal_id, source_tool, status,
                    expected_behavior, suspected_behavior, observation_criteria,
                    reason, coverage, location, created_at, target_id, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.hypothesis.hypothesis_id if is_hypothesis else None,
                    signal.signal_id,
                    signal.source.tool,
                    result.status.value,
                    result.hypothesis.expected_behavior if is_hypothesis else None,
                    result.hypothesis.suspected_behavior if is_hypothesis else None,
                    result.hypothesis.observation_criteria if is_hypothesis else None,
                    result.reason,
                    signal.source.coverage.value,
                    result.hypothesis.provenance.location.model_dump_json() if is_hypothesis else None,
                    datetime.now(timezone.utc).isoformat(),
                    target_id,
                    revision,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không ghi được hypothesis vào Context Store: {exc}") from exc

    _HYPOTHESIS_COLUMNS = (
        "hypothesis_id", "signal_id", "source_tool", "status", "expected_behavior",
        "suspected_behavior", "observation_criteria", "reason", "coverage", "location",
        "created_at", "target_id", "revision",
    )

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        try:
            cursor = self._conn.execute(
                f"SELECT {', '.join(self._HYPOTHESIS_COLUMNS)} FROM hypotheses WHERE hypothesis_id = ?",
                (hypothesis_id,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đọc được hypothesis_id '{hypothesis_id}': {exc}") from exc
        if row is None:
            return None
        return dict(zip(self._HYPOTHESIS_COLUMNS, row))

    def get_hypotheses_by_signal_id(self, signal_id: str) -> List[Dict[str, Any]]:
        # A NOT_VERIFIABLE record has no hypothesis_id (no Hypothesis was ever
        # created), so get_hypothesis() can't look it up — querying by
        # signal_id is the only way to retrieve "a hypothesis that was
        # rejected along with its reason" (SPEC §4.6).
        try:
            cursor = self._conn.execute(
                f"SELECT {', '.join(self._HYPOTHESIS_COLUMNS)} FROM hypotheses "
                "WHERE signal_id = ? ORDER BY row_id",
                (signal_id,),
            )
            return [dict(zip(self._HYPOTHESIS_COLUMNS, row)) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đọc được hypotheses cho signal_id '{signal_id}': {exc}") from exc

    def close(self) -> None:
        self._conn.close()
