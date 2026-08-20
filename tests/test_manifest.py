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


def test_build_artifact_manifest_skips_subdirectories(tmp_path):
    execution_dir = tmp_path / "exec_1"
    execution_dir.mkdir()
    (execution_dir / "actions.json").write_bytes(b"[]")
    (execution_dir / "a_subdir").mkdir()
    (execution_dir / "a_subdir" / "nested.json").write_bytes(b"{}")

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
