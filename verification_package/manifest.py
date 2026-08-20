"""Package-level artifact manifest — SPEC §4.3.3: "Mỗi artifact được băm
khi ghi; package chứa manifest liệt kê hash → phát hiện thay đổi ngoài ý
muốn." Distinct from VerificationPackage's own field #10/#11
(raw_evidence_references/artifact_hashes), which only cover the raw
evidence transcripts backing normalized_observations — this manifest
covers EVERY on-disk artifact one execution produces (raw evidence
transcripts, seed_manifest.json, actions.json, observations.jsonl,
execution_status.json, cost/kill-switch audit logs), since
EvidenceHarness/CostService/KillSwitch all share the same
`{storage_dir}/{execution_id}/` directory convention for whatever they
each write.

Detection only, same limit SPEC §4.3.3 states explicitly: no digital
signing, no WORM storage, no timestamp authority — this only lets a later
re-hash be compared against what was recorded here, so an unwanted
change (or one that should be investigated) doesn't have to be taken on
faith.
"""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field

PACKAGE_MANIFEST_FILENAME = "package_manifest.json"


class ArtifactManifestEntry(BaseModel):
    filename: str = Field(min_length=1)
    sha256_hash: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)


class ArtifactManifest(BaseModel):
    execution_id: str = Field(min_length=1)
    generated_at: datetime
    entries: List[ArtifactManifestEntry]


def build_artifact_manifest(storage_dir: str, execution_id: str) -> List[ArtifactManifestEntry]:
    """Hashes every FILE under `{storage_dir}/{execution_id}/`,
    RECURSIVELY — every real artifact this codebase writes there
    (actions.json, observations.jsonl, raw evidence transcripts,
    screenshots, videos, audit logs) lives flat, with no subdirectory
    involved. Recursion exists for a narrower reason: a best-effort
    cleanup failure (e.g. capture_ui_recording()'s own scratch-directory
    removal failing due to a permission issue) could leave a stray file
    inside a nested scratch directory that a flat, non-recursive scan
    would silently never hash or track at all — invisible to the exact
    tamper/change-detection mechanism this manifest exists to provide.
    Recursing costs nothing extra when (the overwhelming majority of the
    time) nothing is nested, and closes that gap on the rare occasion
    something is.

    Each entry's `filename` is the path RELATIVE to the execution
    directory (e.g. "actions.json", or a nested
    ".ui_video_scratch_abc123/leftover.webm" for a stray file) rather
    than a bare basename — so 2 files that happen to share a basename in
    different subdirectories can't collide, and a reader can tell at a
    glance whether an entry is an expected top-level artifact or
    something unexpected found nested. Sorted by that relative path for
    deterministic output. Excludes `PACKAGE_MANIFEST_FILENAME` by its
    TOP-LEVEL relative path only — a manifest can't meaningfully include
    its own hash (chicken-and-egg: the file doesn't have its final bytes
    until after this function returns), and a stale leftover from a PRIOR
    `assemble-package` run for the same execution_id would otherwise show
    up as a phantom entry that changes every re-run for no reason
    connected to any real evidence.

    Raises FileNotFoundError if the directory itself doesn't exist —
    callers (assemble-package) already require this directory to hold
    observations.jsonl/actions.json/execution_status.json before reaching
    this point, so this should never trigger in practice; a plain, honest
    error is better than silently returning an empty list if it somehow
    does.
    """
    execution_dir = Path(storage_dir) / execution_id
    if not execution_dir.is_dir():
        raise FileNotFoundError(f"Không tìm thấy thư mục execution '{execution_dir}'")
    candidates = []
    for path in execution_dir.rglob("*"):
        # Real gap found via independent review: `path.is_file()` follows
        # a symlink to determine the type — so a symlink TO a file
        # (anywhere in the tree, at any depth) would be silently
        # dereferenced and hashed as if it were a real artifact this
        # codebase wrote, potentially exposing/vouching-for a file
        # entirely OUTSIDE the execution directory under an innocuous-
        # looking relative path. `is_symlink()` is checked explicitly so
        # only files this codebase actually wrote (never a symlink) are
        # ever included — nothing this codebase's own artifact-writing
        # code creates is a symlink, so this excludes nothing legitimate.
        if path.is_symlink() or not path.is_file():
            continue
        relative_path = path.relative_to(execution_dir).as_posix()
        if relative_path == PACKAGE_MANIFEST_FILENAME:
            continue
        candidates.append((relative_path, path))

    entries = []
    for relative_path, path in sorted(candidates, key=lambda item: item[0]):
        raw_bytes = path.read_bytes()
        entries.append(
            ArtifactManifestEntry(
                filename=relative_path,
                sha256_hash=f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}",
                size_bytes=len(raw_bytes),
            )
        )
    return entries
