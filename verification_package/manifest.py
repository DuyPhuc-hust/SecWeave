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
    """Hashes every FILE directly under `{storage_dir}/{execution_id}/`
    (not recursive — nothing this codebase writes there is nested in a
    subdirectory today), sorted by filename for deterministic output.
    Excludes `PACKAGE_MANIFEST_FILENAME` itself by name — a manifest can't
    meaningfully include its own hash (chicken-and-egg: the file doesn't
    have its final bytes until after this function returns), and a stale
    leftover from a PRIOR `assemble-package` run for the same execution_id
    would otherwise show up as a phantom entry that changes every re-run
    for no reason connected to any real evidence.

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
    entries = []
    for path in sorted(execution_dir.iterdir()):
        if not path.is_file() or path.name == PACKAGE_MANIFEST_FILENAME:
            continue
        raw_bytes = path.read_bytes()
        entries.append(
            ArtifactManifestEntry(
                filename=path.name,
                sha256_hash=f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}",
                size_bytes=len(raw_bytes),
            )
        )
    return entries
