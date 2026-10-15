"""Comparison logic between UCSD analysis results and independent aapt/zip inspection."""

import datetime
from typing import Any, Dict, List, Union

from ucsd.models import APKMetadata
from ucsd.validation.models import (
    ComparisonField,
    ComparisonStatus,
    IndependentAPKMetadata,
    ValidationReport,
)


def _compare_scalar(
    field_name: str,
    ucsd_val: Any,
    indep_val: Any,
    description: str,
) -> ComparisonField:
    """Compare two scalar values."""
    if ucsd_val is None or indep_val is None:
        if ucsd_val == indep_val:
            return ComparisonField(
                field=field_name,
                ucsd=ucsd_val,
                independent=indep_val,
                status=ComparisonStatus.MATCH,
                explanation=f"{description}: both sources report null/absent.",
            )
        else:
            return ComparisonField(
                field=field_name,
                ucsd=ucsd_val,
                independent=indep_val,
                status=ComparisonStatus.NOT_VERIFIABLE,
                explanation=f"{description}: value available in one source but absent or unmodeled in the other.",
            )

    if ucsd_val == indep_val:
        return ComparisonField(
            field=field_name,
            ucsd=ucsd_val,
            independent=indep_val,
            status=ComparisonStatus.MATCH,
            explanation=f"{description}: both sources independently report exact match '{ucsd_val}'.",
        )
    else:
        return ComparisonField(
            field=field_name,
            ucsd=ucsd_val,
            independent=indep_val,
            status=ComparisonStatus.MISMATCH,
            explanation=f"{description}: mismatch! UCSD reports '{ucsd_val}' while independent tool reports '{indep_val}'.",
        )


def compare_metadata(
    ucsd_data: Union[APKMetadata, Dict[str, Any]],
    indep_data: IndependentAPKMetadata,
) -> ValidationReport:
    """Compare UCSD analysis data against independent tool ground truth.

    Args:
        ucsd_data: APKMetadata model or dict from UCSD JSON report.
        indep_data: IndependentAPKMetadata extracted without Androguard.

    Returns:
        ValidationReport with field-by-field verdicts and summary statistics.
    """
    if isinstance(ucsd_data, APKMetadata):
        u_dict = ucsd_data.model_dump()
    else:
        u_dict = ucsd_data

    u_manifest = u_dict.get("manifest") or {}
    comparisons: List[ComparisonField] = []

    # 1. SHA-256
    comparisons.append(
        _compare_scalar(
            "sha256",
            u_dict.get("sha256"),
            indep_data.sha256,
            "File SHA-256 checksum",
        )
    )

    # 2. File size
    comparisons.append(
        _compare_scalar(
            "file_size_bytes",
            u_dict.get("file_size_bytes"),
            indep_data.file_size_bytes,
            "Total file size in bytes",
        )
    )

    # 3. ZIP integrity check
    comparisons.append(
        _compare_scalar(
            "is_valid_zip",
            u_dict.get("is_valid_zip"),
            indep_data.is_valid_zip,
            "ZIP CRC32 archive integrity",
        )
    )

    # 4. Package Name
    comparisons.append(
        _compare_scalar(
            "package_name",
            u_manifest.get("package_name"),
            indep_data.package_name,
            "Android application package identifier",
        )
    )

    # 5. Version Code
    comparisons.append(
        _compare_scalar(
            "version_code",
            u_manifest.get("version_code"),
            indep_data.version_code,
            "Internal integer version code",
        )
    )

    # 6. Version Name
    comparisons.append(
        _compare_scalar(
            "version_name",
            u_manifest.get("version_name"),
            indep_data.version_name,
            "Display version string",
        )
    )

    # 7. minSdk
    comparisons.append(
        _compare_scalar(
            "min_sdk_version",
            u_manifest.get("min_sdk_version"),
            indep_data.min_sdk_version,
            "Minimum supported Android API level",
        )
    )

    # 8. targetSdk
    comparisons.append(
        _compare_scalar(
            "target_sdk_version",
            u_manifest.get("target_sdk_version"),
            indep_data.target_sdk_version,
            "Target Android API level",
        )
    )

    # 9. compileSdk
    compile_sdk_ucsd = u_manifest.get("compile_sdk_version")
    if compile_sdk_ucsd is None and indep_data.compile_sdk_version is not None:
        comparisons.append(
            ComparisonField(
                field="compile_sdk_version",
                ucsd=None,
                independent=indep_data.compile_sdk_version,
                status=ComparisonStatus.NOT_VERIFIABLE,
                explanation=(
                    f"UCSD Phase 1 schema does not extract compileSdkVersion; "
                    f"independent aapt tool reports compileSdkVersion='{indep_data.compile_sdk_version}'."
                ),
            )
        )
    else:
        comparisons.append(
            _compare_scalar(
                "compile_sdk_version",
                compile_sdk_ucsd,
                indep_data.compile_sdk_version,
                "Compile SDK version",
            )
        )

    # 10. Requested Permissions Count (equivalent concept: <uses-permission>)
    u_req_perms = sorted(u_manifest.get("requested_permissions") or [])
    i_std_perms = sorted(indep_data.uses_permissions)
    comparisons.append(
        _compare_scalar(
            "requested_permissions_count",
            len(u_req_perms),
            len(i_std_perms),
            "Count of standard <uses-permission> items",
        )
    )

    # 11. Requested Permission Names
    if u_req_perms == i_std_perms:
        sdk23_note = ""
        if indep_data.uses_permissions_sdk_23:
            sdk23_note = (
                f" Note: aapt also identified conditional permission tag(s) "
                f"<uses-permission-sdk-23>: {indep_data.uses_permissions_sdk_23}."
            )
        comparisons.append(
            ComparisonField(
                field="requested_permissions",
                ucsd=u_req_perms,
                independent=i_std_perms,
                status=ComparisonStatus.MATCH,
                explanation=(
                    f"Exact set match for all {len(u_req_perms)} standard <uses-permission> entries.{sdk23_note}"
                ),
            )
        )
    else:
        diff_u = sorted(set(u_req_perms) - set(i_std_perms))
        diff_i = sorted(set(i_std_perms) - set(u_req_perms))
        comparisons.append(
            ComparisonField(
                field="requested_permissions",
                ucsd=u_req_perms,
                independent=i_std_perms,
                status=ComparisonStatus.MISMATCH,
                explanation=f"Permission list mismatch! Only in UCSD: {diff_u}. Only in aapt: {diff_i}.",
            )
        )

    # 12. Declared Permissions Count (<permission> definitions)
    u_decl_perms = sorted(u_manifest.get("declared_permissions") or [])
    i_decl_perms = sorted(indep_data.declared_permissions)
    comparisons.append(
        _compare_scalar(
            "declared_permissions_count",
            len(u_decl_perms),
            len(i_decl_perms),
            "Count of custom declared <permission> definitions",
        )
    )

    # 13. Declared Permission Names
    if u_decl_perms == i_decl_perms:
        comparisons.append(
            ComparisonField(
                field="declared_permissions",
                ucsd=u_decl_perms,
                independent=i_decl_perms,
                status=ComparisonStatus.MATCH,
                explanation=f"Exact match on custom declared permissions: {u_decl_perms}.",
            )
        )
    else:
        comparisons.append(
            ComparisonField(
                field="declared_permissions",
                ucsd=u_decl_perms,
                independent=i_decl_perms,
                status=ComparisonStatus.MISMATCH,
                explanation=f"Declared permissions mismatch! UCSD: {u_decl_perms} vs aapt: {i_decl_perms}.",
            )
        )

    # 14. DEX Count
    comparisons.append(
        _compare_scalar(
            "dex_count",
            u_dict.get("dex_count"),
            indep_data.dex_count,
            "Count of classes*.dex archive entries",
        )
    )

    # 15. Multi-DEX Flag
    comparisons.append(
        _compare_scalar(
            "is_multidex",
            u_dict.get("is_multidex"),
            indep_data.is_multidex,
            "Multi-DEX indicator (dex_count > 1)",
        )
    )

    # 16. DEX Member Names
    u_dex_names = sorted([d.get("name") for d in u_dict.get("dex_files") or [] if isinstance(d, dict)])
    i_dex_names = sorted([d.name for d in indep_data.dex_files])
    if u_dex_names == i_dex_names:
        comparisons.append(
            ComparisonField(
                field="dex_names",
                ucsd=u_dex_names,
                independent=i_dex_names,
                status=ComparisonStatus.MATCH,
                explanation=f"Exact match for DEX members: {u_dex_names}.",
            )
        )
    else:
        comparisons.append(
            ComparisonField(
                field="dex_names",
                ucsd=u_dex_names,
                independent=i_dex_names,
                status=ComparisonStatus.MISMATCH,
                explanation=f"DEX names mismatch! UCSD: {u_dex_names} vs independent: {i_dex_names}.",
            )
        )

    # 17. Individual DEX Checksums and Sizes
    u_dex_map = {d.get("name"): d for d in u_dict.get("dex_files") or [] if isinstance(d, dict)}
    i_dex_map = {d.name: d for d in indep_data.dex_files}

    dex_hashes_match = True
    mismatched_details = []
    for d_name in i_dex_names:
        u_item = u_dex_map.get(d_name)
        i_item = i_dex_map.get(d_name)
        if not u_item:
            dex_hashes_match = False
            mismatched_details.append(f"Missing {d_name} in UCSD")
            continue
        if u_item.get("sha256") != i_item.sha256 or u_item.get("size_bytes") != i_item.size_bytes:
            dex_hashes_match = False
            mismatched_details.append(
                f"{d_name}: UCSD(size={u_item.get('size_bytes')}, sha={u_item.get('sha256')[:8]}) vs "
                f"Indep(size={i_item.size_bytes}, sha={i_item.sha256[:8]})"
            )

    if dex_hashes_match:
        comparisons.append(
            ComparisonField(
                field="dex_checksums_and_sizes",
                ucsd={k: {"size": v.get("size_bytes"), "sha256": v.get("sha256")[:12] + "..."} for k, v in u_dex_map.items()},
                independent={k: {"size": v.size_bytes, "sha256": v.sha256[:12] + "..."} for k, v in i_dex_map.items()},
                status=ComparisonStatus.MATCH,
                explanation="All individual DEX members have identical uncompressed byte sizes and SHA-256 checksums.",
            )
        )
    else:
        comparisons.append(
            ComparisonField(
                field="dex_checksums_and_sizes",
                ucsd={k: v.get("sha256") for k, v in u_dex_map.items()},
                independent={k: v.sha256 for k, v in i_dex_map.items()},
                status=ComparisonStatus.MISMATCH,
                explanation=f"DEX checksum or size mismatch: {mismatched_details}",
            )
        )

    # Calculate summary statistics
    matches = sum(1 for c in comparisons if c.status == ComparisonStatus.MATCH)
    mismatches = sum(1 for c in comparisons if c.status == ComparisonStatus.MISMATCH)
    not_verifiable = sum(1 for c in comparisons if c.status == ComparisonStatus.NOT_VERIFIABLE)

    verdict = "PASS" if mismatches == 0 else "FAIL"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return ValidationReport(
        target=indep_data.file_path,
        timestamp=now_iso,
        verdict=verdict,
        total_comparisons=len(comparisons),
        matches=matches,
        mismatches=mismatches,
        not_verifiable=not_verifiable,
        comparisons=comparisons,
        independent_metadata=indep_data,
    )
