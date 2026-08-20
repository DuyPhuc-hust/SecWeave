import hashlib
import json

import pytest

from verification_package.manifest import (
    PACKAGE_MANIFEST_FILENAME,
    ArtifactManifest,
    ArtifactManifestEntry,
    build_artifact_manifest,
)


def test_build_artifact_manifest_hashes_every_file_in_the_execution_dir(tmp_path):
    execution_dir = tmp_path / "exec_1"
    execution_dir.mkdir()
    (execution_dir / "actions.json").write_bytes(b'[{"a": 1}]')
    (execution_dir / "observations.jsonl").write_bytes(b'{"o": 1}\n')

    entries = build_artifact_manifest(str(tmp_path), "exec_1")

    assert {e.filename for e in entries} == {"actions.json", "observations.jsonl"}
    actions_entry = next(e for e in entries if e.filename == "actions.json")
    expected_hash = "sha256:" + hashlib.sha256(b'[{"a": 1}]').hexdigest()
    assert actions_entry.sha256_hash == expected_hash
    assert actions_entry.size_bytes == len(b'[{"a": 1}]')


def test_build_artifact_manifest_is_sorted_by_filename(tmp_path):
    execution_dir = tmp_path / "exec_1"
    execution_dir.mkdir()
    (execution_dir / "z_file.json").write_bytes(b"z")
    (execution_dir / "a_file.json").write_bytes(b"a")

    entries = build_artifact_manifest(str(tmp_path), "exec_1")

    assert [e.filename for e in entries] == ["a_file.json", "z_file.json"]


def test_build_artifact_manifest_excludes_its_own_output_file(tmp_path):
    # A phantom self-referential entry would otherwise show up (and change
    # every re-run) once assemble-package has already written
    # package_manifest.json once for this execution_id — see this
    # function's own docstring for why that's excluded by name.
    execution_dir = tmp_path / "exec_1"
    execution_dir.mkdir()
    (execution_dir / "actions.json").write_bytes(b"[]")
    (execution_dir / PACKAGE_MANIFEST_FILENAME).write_text(
        json.dumps({"execution_id": "exec_1", "generated_at": "2026-01-01T00:00:00Z", "entries": []})
    )

    entries = build_artifact_manifest(str(tmp_path), "exec_1")

    assert {e.filename for e in entries} == {"actions.json"}


def test_build_artifact_manifest_recurses_into_subdirectories(tmp_path):
    # Real gap found via independent review: this used to be non-
    # recursive on the assumption that nothing this codebase writes is
    # ever nested — true for every INTENDED artifact, but a best-effort
    # cleanup failure (e.g. capture_ui_recording()'s own scratch-
    # directory removal failing) could leave a stray file inside a
    # nested subdirectory that a flat scan would silently never hash or
    # track at all. Nested files are now included, named by their path
    # RELATIVE to the execution directory (not a bare basename), so they
    # can't collide with a same-named top-level file and a reader can
    # tell at a glance that they're nested.
    execution_dir = tmp_path / "exec_1"
    execution_dir.mkdir()
    (execution_dir / "actions.json").write_bytes(b"[]")
    (execution_dir / "a_subdir").mkdir()
    (execution_dir / "a_subdir" / "nested.json").write_bytes(b"{}")

    entries = build_artifact_manifest(str(tmp_path), "exec_1")

    assert {e.filename for e in entries} == {"actions.json", "a_subdir/nested.json"}
    nested_entry = next(e for e in entries if e.filename == "a_subdir/nested.json")
    assert nested_entry.sha256_hash == "sha256:" + hashlib.sha256(b"{}").hexdigest()
    assert nested_entry.size_bytes == 2


def test_build_artifact_manifest_catches_a_leftover_scratch_file_from_a_failed_cleanup(tmp_path):
    # The motivating scenario for recursion: capture_ui_recording()'s own
    # scratch-directory cleanup is best-effort (a permission issue could
    # make it fail without raising) — a leftover ".ui_video_scratch_*"
    # directory with a stray video file inside it must still show up in
    # the manifest, not be silently invisible to the exact tamper/change
    # detection this file exists to provide.
    execution_dir = tmp_path / "exec_1"
    execution_dir.mkdir()
    (execution_dir / "actions.json").write_bytes(b"[]")
    scratch_dir = execution_dir / ".ui_video_scratch_abc123"
    scratch_dir.mkdir()
    (scratch_dir / "page@somehash.webm").write_bytes(b"leftover video bytes")

    entries = build_artifact_manifest(str(tmp_path), "exec_1")

    assert {e.filename for e in entries} == {"actions.json", ".ui_video_scratch_abc123/page@somehash.webm"}


def test_build_artifact_manifest_never_follows_a_symlink_to_a_file_outside_the_execution_dir(tmp_path):
    # Real gap found via independent review: recursion (rglob) means
    # path.is_file() — which FOLLOWS a symlink to determine its type —
    # could dereference a symlink anywhere in the tree, at any depth, and
    # silently hash/vouch-for a file entirely OUTSIDE the execution
    # directory under an innocuous-looking relative path. Nothing this
    # codebase's own artifact-writing code ever creates is a symlink, so
    # excluding them entirely loses no legitimate artifact.
    execution_dir = tmp_path / "exec_1"
    execution_dir.mkdir()
    (execution_dir / "actions.json").write_bytes(b"[]")
    scratch_dir = execution_dir / ".ui_video_scratch_xyz"
    scratch_dir.mkdir()
    outside_file = tmp_path / "outside_secret.txt"
    outside_file.write_bytes(b"super secret data that must never be hashed by this function")
    (scratch_dir / "cache_ref.tmp").symlink_to(outside_file)

    entries = build_artifact_manifest(str(tmp_path), "exec_1")

    assert {e.filename for e in entries} == {"actions.json"}


def test_build_artifact_manifest_raises_file_not_found_for_a_missing_execution_dir(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_artifact_manifest(str(tmp_path), "exec_never_ran")


def test_artifact_manifest_entry_rejects_negative_size():
    with pytest.raises(ValueError):
        ArtifactManifestEntry(filename="x.json", sha256_hash="sha256:abc", size_bytes=-1)


def test_artifact_manifest_model_round_trips_through_json():
    manifest = ArtifactManifest(
        execution_id="exec_1",
        generated_at="2026-01-01T00:00:00+00:00",
        entries=[ArtifactManifestEntry(filename="actions.json", sha256_hash="sha256:abc", size_bytes=2)],
    )
    reloaded = ArtifactManifest(**json.loads(manifest.model_dump_json()))
    assert reloaded == manifest
