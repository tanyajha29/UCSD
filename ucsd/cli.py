"""Command-line interface for UCSD static analysis."""

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import List, Optional

from ucsd.apk_loader import load_apk, normalize_container_path
from ucsd.errors import UCSDError
from ucsd.models import AnalysisReport


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="ucsd",
        description="UCSD: UUID Confusion Static Detection - APK Intake Engine",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze subcommand
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an APK archive and extract normalized static metadata",
    )
    analyze_parser.add_argument(
        "target",
        help="Path to the Android APK file to analyze",
    )
    analyze_parser.add_argument(
        "--out",
        "-o",
        default="reports",
        help="Output directory or file path for the JSON analysis report (default: reports)",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Output report format (default: json)",
    )
    analyze_parser.add_argument(
        "--skip-ble",
        action="store_true",
        help="Skip Phase 2 BLE indicators and UUID candidate extraction",
    )
    analyze_parser.add_argument(
        "--skip-registration",
        action="store_true",
        help="Skip Phase 3 GATT service registration detection",
    )
    analyze_parser.add_argument(
        "--skip-kb",
        action="store_true",
        help="Skip Phase 4 UUID knowledge base lookup",
    )
    analyze_parser.add_argument(
        "--no-html",
        action="store_true",
        help="Suppress standalone HTML report generation",
    )
    analyze_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress human-readable summary output to stdout",
    )

    # batch subcommand
    batch_parser = subparsers.add_parser(
        "batch",
        help="Batch analyze multiple APKs in a directory and perform cross-APK conflict assessment",
    )
    batch_parser.add_argument(
        "targets",
        nargs="+",
        help="Directory containing APK files or list of APK files to analyze in batch",
    )
    batch_parser.add_argument(
        "--out",
        "-o",
        default="reports",
        help="Output directory for individual and batch reports (default: reports)",
    )
    batch_parser.add_argument(
        "--no-html",
        action="store_true",
        help="Suppress standalone HTML report generation",
    )
    batch_parser.add_argument(
        "--skip-ble",
        action="store_true",
        help="Skip Phase 2 BLE indicators and UUID candidate extraction",
    )
    batch_parser.add_argument(
        "--skip-registration",
        action="store_true",
        help="Skip Phase 3 GATT service registration detection",
    )
    batch_parser.add_argument(
        "--skip-kb",
        action="store_true",
        help="Skip Phase 4 UUID knowledge base lookup",
    )
    batch_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress human-readable summary output to stdout",
    )

    # compare subcommand
    compare_parser = subparsers.add_parser(
        "compare",
        help="Perform cross-APK conflict assessment and knowledge base lookup across multiple APKs or reports",
    )
    compare_parser.add_argument(
        "targets",
        nargs="+",
        help="Paths to 2 or more APK files or existing JSON analysis reports",
    )
    compare_parser.add_argument(
        "--out",
        "-o",
        default="reports",
        help="Output directory or file path for the conflict report (default: reports)",
    )
    compare_parser.add_argument(
        "--no-html",
        action="store_true",
        help="Suppress standalone HTML report generation",
    )
    compare_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress human-readable summary output to stdout",
    )


    # validate subcommand
    val_parser = subparsers.add_parser(
        "validate",
        help="Run independent aapt/zip verification against an APK and compare with UCSD",
    )
    val_parser.add_argument(
        "target",
        help="Path to the Android APK file to validate",
    )
    val_parser.add_argument(
        "--report",
        "-r",
        default=None,
        help="Path to an existing UCSD JSON analysis report",
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


def run_analyze(
    target_path: str,
    out_path: str,
    skip_ble: bool = False,
    skip_registration: bool = False,
    skip_kb: bool = False,
    no_html: bool = False,
    quiet: bool = False,
) -> int:
    """Run intake analysis on target APK, write JSON & HTML reports, and return exit code."""
    from ucsd.orchestrator import analyze_single_apk

    report, json_file, html_file = analyze_single_apk(
        target_path=target_path,
        out_path=out_path,
        skip_ble=skip_ble,
        skip_registration=skip_registration,
        skip_kb=skip_kb,
        generate_html=not no_html,
    )

    exit_code = 0 if report.status in ("success", "partial") else 1

    if not quiet:
        if report.status in ("success", "partial") and report.metadata:
            manifest = report.metadata.manifest
            print(f"=== UCSD APK Analysis: {report.status.upper()} ===")
            print(f"Target:       {target_path}")
            print(f"SHA-256:      {report.metadata.sha256}")
            print(f"File Size:    {report.metadata.file_size_bytes} bytes")
            print(f"DEX Count:    {report.metadata.dex_count} (Multi-DEX: {report.metadata.is_multidex})")
            if manifest:
                print(f"Package:      {manifest.package_name}")
                print(f"Version Code: {manifest.version_code}")
                print(f"Version Name: {manifest.version_name}")
                print(f"Permissions:  {len(manifest.requested_permissions)} requested, {len(manifest.declared_permissions)} declared")

            # Phase 2 BLE Summary
            ble = report.ble_analysis
            if ble and ble.has_ble_indicators:
                print("\n--- Bluetooth & BLE Indicators ---")
                if ble.permissions.requested:
                    print("Bluetooth Permissions (Manifest):")
                    for p in ble.permissions.requested:
                        tag = "[BLE]" if "scan" in p.lower() or "connect" in p.lower() or "advertise" in p.lower() else "[Classic]"
                        print(f"  * {p} {tag}")
                else:
                    print("Bluetooth Permissions (Manifest): None requested")

                print("API Indicators:")
                print(f"  * Framework Classes Referenced: {len(ble.api_indicators.framework_classes)}")
                for fc in ble.api_indicators.framework_classes[:5]:
                    print(f"      - {fc}")
                if len(ble.api_indicators.framework_classes) > 5:
                    print(f"      ... and {len(ble.api_indicators.framework_classes) - 5} more")

                if ble.api_indicators.app_classes:
                    print(f"  * App/Library Bluetooth Classes: {len(ble.api_indicators.app_classes)}")
                    for ac in ble.api_indicators.app_classes[:5]:
                        print(f"      - {ac}")

                print(f"  * Bluetooth Method References: {len(ble.api_indicators.referenced_methods)}")
                print(f"  * GATT Client: {ble.api_indicators.has_gatt_client} | GATT Server: {ble.api_indicators.has_gatt_server}")
                print(f"  * LE Scanner: {ble.api_indicators.has_le_scanner} | LE Advertiser: {ble.api_indicators.has_le_advertiser}")

                print(f"\nUUID Candidates ({len(ble.uuid_candidates)} unique):")
                for i, cand in enumerate(ble.uuid_candidates[:10], 1):
                    type_str = f"Bluetooth SIG ({cand.sig_name})" if cand.is_bluetooth_sig_range and cand.sig_name else ("Bluetooth SIG" if cand.is_bluetooth_sig_range else "Custom 128-bit")
                    print(f"  [{i}] {cand.normalized_uuid} ({type_str})")
                    print(f"      Occurrences: {cand.occurrence_count}")
                    for ev in cand.evidence[:3]:
                        if ev.extraction_method == "bytecode_instruction":
                            print(f"        * [{ev.dex_file}] {ev.class_name}::{ev.method_name} (bytecode)")
                        else:
                            ctx = f" (context: '{ev.context_string}')" if ev.context_string else ""
                            print(f"        * [{ev.dex_file}] string_pool{ctx}")
                    if len(cand.evidence) > 3:
                        print(f"        ... and {len(cand.evidence) - 3} more evidence locations")
                if len(ble.uuid_candidates) > 10:
                    print(f"  ... and {len(ble.uuid_candidates) - 10} more candidate UUIDs (see full report)")

            elif ble:
                print("\n--- Bluetooth & BLE Analysis ---")
                print("No Bluetooth permissions, API indicators, or UUID candidates detected.")

            # Phase 3 GATT Service Registration Summary
            reg = report.registration_analysis
            if reg:
                print("\n--- GATT Service Registration Analysis ---")
                print(f"Call Sites: {reg.total_add_service_calls} addService, {reg.total_service_constructions} service constructors")
                print("Evidence Breakdown:")
                print(f"  * Strong Static Associations:        {reg.strong_associations_count}")
                print(f"  * Unresolved Registration Patterns: {reg.unresolved_patterns_count}")
                print(f"  * UUID Candidate Only:              {reg.candidate_only_count}")

                strong_findings = [f for f in reg.findings if f.evidence_level == "STRONG_STATIC_ASSOCIATION"]
                if strong_findings:
                    print("\nStrong Static Registrations:")
                    for sf in strong_findings:
                        print(f"  * UUID: {sf.normalized_uuid} (verified in {sf.class_name}::{sf.method_name})")

                unres_findings = [f for f in reg.findings if f.evidence_level == "REGISTRATION_PATTERN_UUID_UNRESOLVED"]
                if unres_findings:
                    print("\nUnresolved Registration Patterns:")
                    for uf in unres_findings[:3]:
                        print(f"  * [{uf.unresolved_reason}] {uf.class_name}::{uf.method_name}")

            # Phase 4 UUID Knowledge Base Summary
            kb_res = report.knowledge_base_assessment
            if kb_res:
                print("\n--- UUID Knowledge Base Assessment ---")
                print(f"Candidates Evaluated: {kb_res.total_candidates_checked}")
                print(f"  * Curated Standard Matches (SIG): {kb_res.known_standard_matches_count}")
                print(f"  * Sourced System/Vendor Matches:   {kb_res.known_system_vendor_matches_count}")
                print(f"  * Unknown Candidates:              {kb_res.unknown_candidates_count}")

                known_matches = [m for m in kb_res.findings if m.knowledge_base_match]
                if known_matches:
                    print("Identified Sourced UUIDs:")
                    for km in known_matches[:5]:
                        match_info = km.knowledge_base_match
                        src_type = f"[{match_info.source_type.value}]" if match_info else ""
                        m_name = match_info.name if match_info else "Unknown"
                        print(f"  * {km.normalized_uuid} -> {m_name} {src_type}")

            print(f"\nReport (JSON) saved: {json_file}")
            if html_file:
                print(f"Report (HTML) saved: {html_file}")
        else:
            err_info = report.error or {}
            print("=== UCSD APK Analysis: FAILED ===", file=sys.stderr)
            print(f"Target:       {target_path}", file=sys.stderr)
            print(f"Error Type:   {err_info.get('error_type', 'Unknown')}", file=sys.stderr)
            print(f"Message:      {err_info.get('message', 'No details')}", file=sys.stderr)
            print(f"Report (JSON) saved: {json_file}", file=sys.stderr)
            if html_file:
                print(f"Report (HTML) saved: {html_file}", file=sys.stderr)

    return exit_code


def run_batch(
    targets: List[str],
    out_dir: str,
    skip_ble: bool = False,
    skip_registration: bool = False,
    skip_kb: bool = False,
    no_html: bool = False,
    quiet: bool = False,
) -> int:
    """Run batch analysis across multiple APKs in a directory or list of targets."""
    from ucsd.orchestrator import batch_analyze

    target_input: Any = targets[0] if len(targets) == 1 else targets

    batch_report, json_path, html_path = batch_analyze(
        targets_or_dir=target_input,
        out_dir=out_dir,
        skip_ble=skip_ble,
        skip_registration=skip_registration,
        skip_kb=skip_kb,
        generate_html=not no_html,
    )

    if not quiet:
        print("\n=================================================================")
        print("  UCSD Phase 5: Multi-APK Batch Analysis & Conflict Report")
        print("=================================================================")
        print(f"Target Scope:              {batch_report.target_directory}")
        print(f"Total Targets Considered:  {batch_report.total_targets}")
        print(f"Successfully Analyzed:     {batch_report.successful_count}")
        print(f"Failed Intake:             {batch_report.failed_count}")

        conf = batch_report.cross_apk_conflicts
        if conf:
            print("\nCross-APK Conflict Summary:")
            print(f"  * Strong Duplicate Static Registrations: {conf.strong_duplicate_static_registrations_count}")
            print(f"  * Duplicate Unregistered UUIDs:          {conf.duplicate_candidates_unregistered_count}")
            print(f"  * Standard Matches (SIG):                {conf.known_standard_matches_count}")
            print(f"  * Sourced System/Vendor Matches:         {conf.known_system_vendor_matches_count}")
            print(f"  * Unknown / Unconflicted UUIDs:          {conf.unknown_uuids_count}")
            print("-----------------------------------------------------------------")
            if conf.strong_duplicate_static_registrations_count > 0:
                print("\nSTRONG DUPLICATE STATIC REGISTRATIONS:")
                for c in conf.assessments:
                    if c.condition == "STRONG_DUPLICATE_STATIC_REGISTRATION":
                        print(f"  [STATIC OVERLAP] UUID: {c.normalized_uuid}")
                        for app in c.participating_apks:
                            loc = f"{app.class_name}::{app.method_name}" if app.class_name and app.method_name else (f"[{app.dex_file}] string pool" if app.dex_file else "string pool")
                            ev_tag = f" ({app.evidence_level})" if app.evidence_level else ""
                            print(f"      - App: {app.package_name or app.file_name} in {loc}{ev_tag}")
            else:
                print("No duplicate static GATT service registrations detected across analyzed APKs.")

            if conf.duplicate_candidates_unregistered_count > 0:
                print(f"\nDuplicate Candidate Identifiers ({conf.duplicate_candidates_unregistered_count} UUIDs across APKs):")
                print("  (Note: Candidate strings without dual static registration are NOT proven conflicts)")
                dup_candidates = [c for c in conf.assessments if c.condition == "DUPLICATE_CANDIDATE_NO_REGISTRATION"]
                for dc in dup_candidates[:5]:
                    print(f"  * {dc.normalized_uuid}: present in {len(dc.participating_apks)} APKs")

        if batch_report.failed_targets:
            print("\nFailed Targets:")
            for f in batch_report.failed_targets:
                print(f"  * {f['target']}: [{f['error_type']}] {f['message']}")

        print("-----------------------------------------------------------------")
        print(f"Batch JSON Report: {json_path}")
        if html_path:
            print(f"Batch HTML Report: {html_path}")
        print("=================================================================\n")

    return 0 if batch_report.status in ("success", "partial") else 1


def run_compare(
    targets: List[str],
    out_path: str,
    no_html: bool = False,
    quiet: bool = False,
) -> int:
    """Run cross-APK conflict evaluation across 2 or more targets and output report."""
    if len(targets) < 2:
        print("Error: 'compare' requires at least 2 APK targets or report files.", file=sys.stderr)
        return 2

    out_path = normalize_container_path(out_path)
    out_target = Path(out_path)

    apk_metadata_list = []

    for t in targets:
        t_norm = normalize_container_path(t)
        p = Path(t_norm)
        if not p.exists():
            print(f"Error: Target path not found: {t_norm}", file=sys.stderr)
            return 1

        if p.suffix.lower() == ".json":
            try:
                with open(p, "r", encoding="utf-8") as f:
                    rep_data = json.load(f)
                rep = AnalysisReport.model_validate(rep_data)
                if not rep.metadata:
                    print(f"Error: Report at {p} contains no successful APK metadata", file=sys.stderr)
                    return 1
                apk_metadata_list.append(rep.metadata)
            except Exception as exc:
                print(f"Error: Failed to load report from {p}: {exc}", file=sys.stderr)
                return 1
        else:
            try:
                meta = load_apk(p)
                apk_metadata_list.append(meta)
            except Exception as exc:
                print(f"Error: Failed to analyze target {p}: {exc}", file=sys.stderr)
                return 1

    from ucsd.conflict.assessor import compare_apks
    report = compare_apks(apk_metadata_list)

    if out_target.suffix.lower() == ".json":
        report_file = out_target
    else:
        out_target.mkdir(parents=True, exist_ok=True)
        report_file = out_target / "conflict_report.json"

    report_file.parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

    html_file = None
    if not no_html:
        from ucsd.reporting.html_generator import generate_conflict_html_report
        html_file = report_file.with_suffix(".html")
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(generate_conflict_html_report(report))

    if not quiet:
        print("\n=================================================================")
        print("  UCSD Phase 4: Cross-APK UUID Conflict Assessment Report")
        print("=================================================================")
        print(f"APKs Evaluated:            {report.total_apks_analyzed}")
        print(f"Unique UUIDs Evaluated:    {report.total_unique_uuids_evaluated}")
        print("Conflict Summary:")
        print(f"  * Strong Duplicate Static Registrations: {report.strong_duplicate_static_registrations_count}")
        print(f"  * Duplicate Unregistered UUIDs:          {report.duplicate_candidates_unregistered_count}")
        print(f"  * Standard Matches (SIG):                {report.known_standard_matches_count}")
        print(f"  * Sourced System/Vendor Matches:         {report.known_system_vendor_matches_count}")
        print(f"  * Unknown / Unconflicted UUIDs:          {report.unknown_uuids_count}")
        print("-----------------------------------------------------------------")
        if report.strong_duplicate_static_registrations_count > 0:
            print("\nSTRONG DUPLICATE STATIC REGISTRATIONS:")
            for c in report.assessments:
                if c.condition == "STRONG_DUPLICATE_STATIC_REGISTRATION":
                    print(f"  [STATIC OVERLAP] UUID: {c.normalized_uuid}")
                    print(f"    Diagnosis: {c.explanation}")
                    for app in c.participating_apks:
                        loc = f"{app.class_name}::{app.method_name}" if app.class_name and app.method_name else (f"[{app.dex_file}] string pool" if app.dex_file else "string pool")
                        ev_tag = f" ({app.evidence_level})" if app.evidence_level else ""
                        print(f"      - App: {app.package_name or app.file_name} in {loc}{ev_tag}")
        else:
            print("No duplicate static GATT service registrations detected across analyzed APKs.")

        if report.duplicate_candidates_unregistered_count > 0:
            print(f"\nDuplicate Candidate Identifiers ({report.duplicate_candidates_unregistered_count} UUIDs across APKs):")
            print("  (Note: Candidate strings without dual static registration are NOT proven conflicts)")
            dup_candidates = [c for c in report.assessments if c.condition == "DUPLICATE_CANDIDATE_NO_REGISTRATION"]
            for dc in dup_candidates[:5]:
                print(f"  * {dc.normalized_uuid}: present in {len(dc.participating_apks)} APKs")

        print("-----------------------------------------------------------------")
        print(f"Conflict Report (JSON) saved: {report_file}")
        if html_file:
            print(f"Conflict Report (HTML) saved: {html_file}")
        print("=================================================================\n")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "analyze":
        return run_analyze(
            args.target,
            args.out,
            skip_ble=getattr(args, "skip_ble", False),
            skip_registration=getattr(args, "skip_registration", False),
            skip_kb=getattr(args, "skip_kb", False),
            no_html=getattr(args, "no_html", False),
            quiet=args.quiet,
        )

    if args.command == "batch":
        return run_batch(
            args.targets,
            args.out,
            skip_ble=getattr(args, "skip_ble", False),
            skip_registration=getattr(args, "skip_registration", False),
            skip_kb=getattr(args, "skip_kb", False),
            no_html=getattr(args, "no_html", False),
            quiet=args.quiet,
        )

    if args.command == "compare":
        return run_compare(
            args.targets,
            args.out,
            no_html=getattr(args, "no_html", False),
            quiet=args.quiet,
        )

    if args.command == "validate":
        from ucsd.validation.cli import run_validate
        return run_validate(
            args.target,
            args.out,
            report_path=args.report,
            quiet=args.quiet,
        )

    return 2


if __name__ == "__main__":
    sys.exit(main())


