"""Cross-process advisory lock for one execution's on-disk audit state
(KillSwitch's kill_switch_audit_log.jsonl, CostService's
cost_audit_log.jsonl). Each class's own `threading.Lock` only provides
mutual exclusion between calls made through the SAME instance — it does
nothing for two SEPARATE processes racing to read-then-write the SAME
audit log for the SAME execution_id (e.g. `secweave execute` running in
one terminal and `secweave kill` in another, both pointed at the same
`--execution-id`/`--storage-dir`). POSIX file locking (`fcntl.flock`)
closes that: whichever process acquires the lock first blocks every
other locker until it releases, so a read-current-state-then-decide-
then-write critical section can no longer straddle 2 processes'
concurrent attempts — this is what actually PREVENTS a genuine
`sequence` tie/duplicate from occurring across processes, rather than
only failing safe (assuming STOPPED, or refusing the action) after the
fact once one has already happened.

POSIX-only (`fcntl` doesn't exist on Windows) — this project targets
Linux/macOS, matching every other artifact-storage assumption already
made elsewhere in this codebase (e.g. `O_APPEND` atomicity for the audit
logs themselves is documented as "local disk only", not verified on
network filesystems either).

Advisory only, same as every flock-based lock: a process that opens the
audit log directly without going through this helper could still race
past it. Every real call site in this codebase (KillSwitch, CostService)
goes through this same class, so that's not a gap in practice for THIS
codebase — just the general property of advisory locking, stated for
whoever reads this file next.
"""

import fcntl
from pathlib import Path


class ExecutionFileLock:
    """One instance per KillSwitch/CostService instance, opened ONCE at
    construction and held open for that instance's lifetime — flock locks
    are scoped to the OPEN FILE DESCRIPTION, not the path or the process,
    so re-opening the lock file on every acquire (instead of reusing one
    file handle) would make 2 acquire calls from 2 DIFFERENT processes
    correctly contend, but would also make repeated acquires from the
    SAME open handle pointlessly re-open a file each time for no
    protective benefit.

    Does NOT provide mutual exclusion between 2 THREADS of the SAME
    process sharing this same instance/handle — POSIX flock() grants a
    lock request immediately when it's requested again via the SAME open
    file description, since a single lock holder cannot conflict with
    itself. Callers still need their own `threading.Lock` (as KillSwitch/
    CostService already have) for that; this class only ever adds
    protection against a DIFFERENT process/open file description.

    `lock_filename` is REQUIRED and must be distinct per class, even
    though KillSwitch and CostService share the SAME
    `{storage_dir}/{execution_id}/` directory — a real bug found via
    independent review: pointing both classes at one shared generic lock
    file meant a single thread holding, say, KillSwitch's file lock while
    (directly or via a `cleanup` callback) trying to acquire CostService's
    file lock would be requesting a CONFLICTING lock via a DIFFERENT open
    file description on the literal same file — flock() has no same-
    thread/same-process exemption across different file descriptions, so
    that thread deadlocks against itself. Giving each class its own lock
    file removes the possibility entirely rather than relying on callers
    never combining them in one thread.
    """

    def __init__(self, execution_dir: Path, lock_filename: str) -> None:
        execution_dir.mkdir(parents=True, exist_ok=True)
        self._handle = open(execution_dir / lock_filename, "a+")

    def __enter__(self) -> "ExecutionFileLock":
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
