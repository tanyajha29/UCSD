"""CLI entry point for independent APK validation and verification workflow."""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from ucsd.apk_loader import load_apk, normalize_container_path
from ucsd.validation.comparator import compare_metadata
from ucsd.validation.inspector import inspect_apk_independently
from ucsd.validation.reporter import write_reports


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the validation argument parser."""
    parser = argparse.ArgumentParser(
        prog="ucsd.validation",
        description="UCSD: Independent APK Validator & Verification Engine",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    val_parser = subparsers.add_parser(
        "validate",
        help="Run independent verification against an APK and compare with UCSD results",
    )
    val_parser.add_argument(
        "target",
        help="Path to the Android APK file to validate",
    )
    val_parser.add_argument(
        "--report",
        "-r",
        default=None,
        help="Path to an existing UCSD JSON analysis report (if omitted, UCSD analyzer runs dynamically)",
    )
    val_parser.add_argument(
        "--out",
        "-o",
        default="reports",
        help="Directory to write validation comparison reports (default: reports)",
    )
    val_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress human-readable summary output to stdout",
    )

    return parser


def run_validate(
    target_path: str,
    out_dir: str,
    report_path: Optional[str] = None,
    quiet: bool = False,
) -> int:
    """Execute independent validation and comparative analysis."""
    target_clean = normalize_container_path(target_path)
    out_clean = normalize_container_path(out_dir)
    target = Path(target_clean).resolve()
    out_path = Path(out_clean).resolve()

    if not target.is_file():
        print(f"Error: Target APK not found: {target}", file=sys.stderr)
        return 1

    # 1. Obtain UCSD analysis results
    if report_path:
        rep_clean = normalize_container_path(report_path)
        r_file = Path(rep_clean).resolve()
        if not r_file.is_file():
            print(f"Error: Specified UCSD report file not found: {r_file}", file=sys.stderr)
            return 1
        with open(r_file, "r", encoding="utf-8") as f:
            raw_report = json.load(f)
            ucsd_data = raw_report.get("metadata") or {}
    else:
        # Run UCSD analyzer dynamically (Phase 1 intake metadata only)
        ucsd_meta = load_apk(str(target), scan_ble=False)
        ucsd_data = ucsd_meta.model_dump()

    # 2. Run completely independent inspection (aapt + zipfile + hashlib)
    indep_data = inspect_apk_independently(str(target))

    # 3. Perform comparative evaluation
    val_report = compare_metadata(ucsd_data, indep_data)

    # 4. Generate JSON and Markdown reports
    json_path, md_path = write_reports(val_report, out_path, stem=target.stem)

    # 5. Output summary to console
    if not quiet:
        print("=================================================================")
        print("  UCSD Phase 1: Independent APK Validation & Verification")
        print("=================================================================")
        print(f"Target:       {target}")
        print(f"SHA-256:      {val_report.independent_metadata.sha256}")
        print(f"Tooling:      {val_report.independent_metadata.tool_metadata.get('aapt_tool')}")
        print(f"Evaluated:    {val_report.total_comparisons} properties")
        print(f"Matches:      {val_report.matches}")
        print(f"Mismatches:   {val_report.mismatches}")
        print(f"Unverifiable: {val_report.not_verifiable}")
        print(f"Verdict:      {val_report.verdict}")
        print("-----------------------------------------------------------------")
        print(f"JSON Report:  {json_path}")
        print(f"Markdown:     {md_path}")
        print("=================================================================")

    return 0 if val_report.verdict == "PASS" else 1


def main(argv: Optional[List[str]] = None) -> int:
    """Validation CLI main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "validate":
        return run_validate(
            args.target,
            args.out,
            report_path=args.report,
            quiet=args.quiet,
        )

    return 2


if __name__ == "__main__":
    sys.exit(main())
