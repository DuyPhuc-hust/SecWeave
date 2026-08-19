import argparse
import json
import sys
from typing import List

from cli.common import CliError, _open_context_store


def _record_for_json(record: dict) -> dict:
    """Decodes `location` from its stored JSON-string form into a nested
    object, matching the un-double-encoded shape `hypothesize --format
    json` already outputs for the same logical field.
    """
    result = dict(record)
    if result.get("location") is not None:
        result["location"] = json.loads(result["location"])
    return result


def _print_hypothesis_record(record: dict) -> None:
    print(f"hypothesis_id       : {record['hypothesis_id']}")
    print(f"signal_id           : {record['signal_id']}")
    print(f"source_tool         : {record['source_tool']}")
    print(f"status              : {record['status']}")
    print(f"coverage            : {record['coverage']}")
    print(f"location            : {record['location']}")
    print(f"created_at          : {record['created_at']}")
    print(f"expected_behavior   : {record['expected_behavior']}")
    print(f"suspected_behavior  : {record['suspected_behavior']}")
    print(f"observation_criteria: {record['observation_criteria']}")
    print(f"reason              : {record['reason']}")


def _load_hypothesis_records(args: argparse.Namespace) -> List[dict]:
    context_store = _open_context_store(args.context_db)
    try:
        if args.hypothesis_id:
            record = context_store.get_hypothesis(args.hypothesis_id)
            records = [record] if record is not None else []
        else:
            # hypothesis_id only exists when status=hypothesis — a
            # NOT_VERIFIABLE record (no Hypothesis was ever created) can only
            # be looked up by signal_id, it has no hypothesis_id to query by.
            records = context_store.get_hypotheses_by_signal_id(args.signal_id)
    except RuntimeError as exc:
        raise CliError(str(exc)) from exc
    finally:
        context_store.close()

    if not records:
        key = f"hypothesis_id '{args.hypothesis_id}'" if args.hypothesis_id else f"signal_id '{args.signal_id}'"
        raise CliError(f"không tìm thấy bản ghi nào cho {key}")
    return records


def cmd_show_hypothesis(args: argparse.Namespace) -> int:
    try:
        records = _load_hypothesis_records(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        payload = [_record_for_json(r) for r in records] if args.signal_id else _record_for_json(records[0])
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for i, record in enumerate(records):
            if i > 0:
                print()
            _print_hypothesis_record(record)

    return 0
