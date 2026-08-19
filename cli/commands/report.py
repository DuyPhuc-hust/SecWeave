import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from cli.common import CliError
from shared.models.verification_package import VerificationPackage
from verification_package.report import render_markdown_report


def cmd_report(args: argparse.Namespace) -> int:
    """Render 1 VerificationPackage đã lắp (`assemble-package`/`review-package
    --format json`) thành 1 file Markdown đọc được trực tiếp — không tính gì
    mới, chỉ chọn cách trình bày cho SPEC §7's 19 trường (xem
    verification_package/report.py để biết chi tiết bố cục, gồm cả lý do
    Limitations được đặt lên đầu và vì sao action_record KHÔNG bị redact
    thêm ở bước này).
    """
    try:
        return _run_report(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_report(args: argparse.Namespace) -> int:
    package_path = Path(args.package_file)
    try:
        package_data = json.loads(package_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CliError(f"không tìm thấy package file '{package_path}'")
    except OSError as exc:
        raise CliError(f"không đọc được package file '{package_path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"'{package_path}' không phải JSON hợp lệ: {exc}") from exc
    if not isinstance(package_data, dict):
        raise CliError(f"'{package_path}' phải là 1 JSON object (VerificationPackage), nhận '{type(package_data).__name__}'.")
    try:
        package = VerificationPackage(**package_data)
    except ValidationError as exc:
        raise CliError(f"'{package_path}' không phải VerificationPackage hợp lệ: {exc}") from exc

    markdown = render_markdown_report(package)

    if args.out:
        out_path = Path(args.out)
        try:
            out_path.write_text(markdown, encoding="utf-8")
        except OSError as exc:
            raise CliError(f"không ghi được báo cáo vào '{out_path}': {type(exc).__name__}: {exc}") from exc
        print(f"-> Đã ghi báo cáo Markdown vào '{out_path}'.", file=sys.stderr)
    else:
        print(markdown)
    return 0
