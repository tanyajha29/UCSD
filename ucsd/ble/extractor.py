"""BLE indicator detection and UUID candidate extraction engine."""

import re
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

try:
    from loguru import logger
    logger.disable("androguard")
except ImportError:
    pass

try:
    from androguard.core.dex import DEX
except ImportError:
    from androguard.core.bytecodes.dvm import DalvikVMFormat as DEX

from ucsd.ble.models import (
    BLEAnalysisResult,
    BLEApiIndicators,
    BLEMethodReference,
    BLEPermissions,
    UUIDCandidate,
    UUIDEvidence,
)
from ucsd.ble.normalizer import (
    CANONICAL_UUID_SEARCH_RE,
    HEX16_PREFIXED_SEARCH_RE,
    HEX16_RAW_EXACT_RE,
    extract_short_hex,
    is_bluetooth_sig_range,
    lookup_sig_name,
    normalize_uuid,
)
from ucsd.errors import InvalidUUIDError
from ucsd.models import ManifestMetadata

_DEX_PATTERN = re.compile(r"^classes(\d+)?\.dex$")

_BLE_PERMISSIONS = {
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
}

_CLASSIC_PERMISSIONS = {
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_PRIVILEGED",
}


def _natural_dex_sort_key(name: str) -> Tuple[int, str]:
    """Sort key for DEX files to ensure deterministic ordering (classes.dex, classes2.dex, ...)."""
    match = _DEX_PATTERN.match(name)
    if not match:
        return (9999, name)
    suffix = match.group(1)
    if suffix is None:
        return (1, name)
    return (int(suffix), name)


def _clean_smali_class_name(raw: str) -> str:
    """Convert Smali class descriptor (e.g. 'Landroid/bluetooth/BluetoothGatt;') to Java notation."""
    s = raw.strip()
    if s.startswith("L") and s.endswith(";"):
        s = s[1:-1]
    return s.replace("/", ".")


def extract_bluetooth_permissions(manifest_meta: Optional[ManifestMetadata]) -> BLEPermissions:
    """Filter and classify Bluetooth and BLE permissions from manifest metadata."""
    if not manifest_meta:
        return BLEPermissions(
            requested=[],
            declared=[],
            has_ble_permission=False,
            has_classic_permission=False,
        )

    requested_bt: List[str] = sorted(
        [p for p in manifest_meta.requested_permissions if "bluetooth" in p.lower()]
    )
    declared_bt: List[str] = sorted(
        [p for p in manifest_meta.declared_permissions if "bluetooth" in p.lower()]
    )

    has_ble = any(p in _BLE_PERMISSIONS for p in requested_bt)
    has_classic = any(p in _CLASSIC_PERMISSIONS for p in requested_bt)

    return BLEPermissions(
        requested=requested_bt,
        declared=declared_bt,
        has_ble_permission=has_ble,
        has_classic_permission=has_classic,
    )


def scan_ble_indicators(
    apk_path: Union[str, Path],
    manifest_meta: Optional[ManifestMetadata] = None,
) -> BLEAnalysisResult:
    """Scan an APK for Bluetooth Low Energy indicators, APIs, and UUID candidates.

    Performs:
    1. Permission extraction and BLE vs. Classic categorization.
    2. DEX method reference table inspection for Bluetooth framework and application classes.
    3. Targeted bytecode instruction and DEX string pool inspection for candidate UUIDs.
    4. Deterministic normalization and Base UUID expansion.
    5. Deduplication of candidates while preserving distinct evidence locations.
    6. Reporting of standard analytical caveats and false-positive notices.

    Args:
        apk_path: Path to the APK archive on disk.
        manifest_meta: Optional pre-parsed ManifestMetadata.

    Returns:
        BLEAnalysisResult containing structured findings.
    """
    path = Path(apk_path).resolve()
    summary_notes: List[str] = []

    # 1. Permissions
    permissions = extract_bluetooth_permissions(manifest_meta)

    # 2. Inspect DEX files
    raw_evidences: List[UUIDEvidence] = []
    framework_classes: Set[str] = set()
    app_classes: Set[str] = set()
    referenced_methods: List[BLEMethodReference] = []

    dex_files_analyzed: List[str] = []

    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            dex_names = [n for n in zf.namelist() if _DEX_PATTERN.match(n)]
            dex_names.sort(key=_natural_dex_sort_key)

            for dex_name in dex_names:
                dex_files_analyzed.append(dex_name)
                try:
                    dex_bytes = zf.read(dex_name)
                    dex_obj = DEX(dex_bytes)
                except Exception as exc:
                    summary_notes.append(
                        f"DEX parsing failure in '{dex_name}': {exc}. Skipped internal bytecode analysis for this file."
                    )
                    continue

                # A. Inspect method references
                try:
                    for m in dex_obj.get_methods():
                        raw_cname = m.get_class_name()
                        cname_lower = raw_cname.lower()
                        if "bluetooth" not in cname_lower:
                            continue

                        clean_name = _clean_smali_class_name(raw_cname)
                        if clean_name.startswith("android.bluetooth"):
                            framework_classes.add(clean_name)
                            referenced_methods.append(
                                BLEMethodReference(
                                    dex_file=dex_name,
                                    class_name=clean_name,
                                    method_name=m.get_name(),
                                    descriptor=m.get_descriptor(),
                                )
                            )
                        else:
                            app_classes.add(clean_name)
                except Exception as exc:
                    summary_notes.append(
                        f"Warning: Failed to inspect method reference table in '{dex_name}': {exc}."
                    )

                # B. Inspect string pool for candidate UUIDs
                try:
                    dex_strings = dex_obj.get_strings()
                except Exception as exc:
                    summary_notes.append(
                        f"Warning: Failed to read string pool in '{dex_name}': {exc}."
                    )
                    dex_strings = []

                # Find candidate matches in string pool
                # candidate_matches: dict mapping matched_candidate_string -> list of (full_string, format_type)
                candidate_matches: Dict[str, List[Tuple[str, str]]] = {}

                for s in dex_strings:
                    # 1) Canonical 128-bit search
                    for m128 in CANONICAL_UUID_SEARCH_RE.finditer(s):
                        c_str = m128.group(1)
                        candidate_matches.setdefault(c_str, []).append((s, "canonical-128"))

                    # 2) Prefixed 16-bit search (0xXXXX)
                    for m16 in HEX16_PREFIXED_SEARCH_RE.finditer(s):
                        c_str = m16.group(0)
                        candidate_matches.setdefault(c_str, []).append((s, "bluetooth-16-prefixed"))

                    # 3) Standalone 16-bit raw (XXXX)
                    if HEX16_RAW_EXACT_RE.match(s):
                        candidate_matches.setdefault(s, []).append((s, "bluetooth-16-raw"))

                # If candidates exist in this DEX, search bytecode instructions for exact method context
                target_candidates = set(candidate_matches.keys())
                instruction_found_targets: Set[str] = set()

                if target_candidates:
                    try:
                        classes_list = dex_obj.get_classes()
                        for cls in classes_list:
                            cls_name = _clean_smali_class_name(cls.get_name())
                            for method in cls.get_methods():
                                code = method.get_code()
                                if not code:
                                    continue
                                try:
                                    for ins in code.get_bc().get_instructions():
                                        if "const-string" in ins.get_name():
                                            val = ins.get_string()
                                            if not val:
                                                continue

                                            # Check canonical UUIDs in val
                                            for m128 in CANONICAL_UUID_SEARCH_RE.finditer(val):
                                                matched_str = m128.group(1)
                                                try:
                                                    norm = normalize_uuid(matched_str)
                                                    raw_evidences.append(
                                                        UUIDEvidence(
                                                            original_text=matched_str,
                                                            normalized_uuid=norm,
                                                            format_type="canonical-128",
                                                            dex_file=dex_name,
                                                            class_name=cls_name,
                                                            method_name=method.get_name(),
                                                            extraction_method="bytecode_instruction",
                                                            context_string=val if val != matched_str else None,
                                                        )
                                                    )
                                                    instruction_found_targets.add(matched_str)
                                                except InvalidUUIDError:
                                                    pass

                                            # Check prefixed 16-bit in val
                                            for m16 in HEX16_PREFIXED_SEARCH_RE.finditer(val):
                                                matched_str = m16.group(0)
                                                try:
                                                    norm = normalize_uuid(matched_str)
                                                    raw_evidences.append(
                                                        UUIDEvidence(
                                                            original_text=matched_str,
                                                            normalized_uuid=norm,
                                                            format_type="bluetooth-16-prefixed",
                                                            dex_file=dex_name,
                                                            class_name=cls_name,
                                                            method_name=method.get_name(),
                                                            extraction_method="bytecode_instruction",
                                                            context_string=val if val != matched_str else None,
                                                        )
                                                    )
                                                    instruction_found_targets.add(matched_str)
                                                except InvalidUUIDError:
                                                    pass

                                            # Check standalone 16-bit raw in val
                                            if HEX16_RAW_EXACT_RE.match(val):
                                                try:
                                                    norm = normalize_uuid(val)
                                                    raw_evidences.append(
                                                        UUIDEvidence(
                                                            original_text=val,
                                                            normalized_uuid=norm,
                                                            format_type="bluetooth-16-raw",
                                                            dex_file=dex_name,
                                                            class_name=cls_name,
                                                            method_name=method.get_name(),
                                                            extraction_method="bytecode_instruction",
                                                            context_string=None,
                                                        )
                                                    )
                                                    instruction_found_targets.add(val)
                                                except InvalidUUIDError:
                                                    pass
                                except Exception:
                                    # Gracefully continue if an instruction in a specific method fails
                                    continue
                    except Exception as exc:
                        summary_notes.append(
                            f"Warning: Partial failure while inspecting bytecode in '{dex_name}': {exc}."
                        )

                # Record string_pool evidence for all candidates found in string pool
                for cand_str, contexts in candidate_matches.items():
                    try:
                        norm = normalize_uuid(cand_str)
                    except InvalidUUIDError:
                        continue

                    for full_s, fmt in contexts:
                        raw_evidences.append(
                            UUIDEvidence(
                                original_text=cand_str,
                                normalized_uuid=norm,
                                format_type=fmt,
                                dex_file=dex_name,
                                class_name=None,
                                method_name=None,
                                extraction_method="string_pool",
                                context_string=full_s if full_s != cand_str else None,
                            )
                        )
    except Exception as exc:
        summary_notes.append(f"Failed to read APK archive members: {exc}.")

    # 3. Deduplicate candidate UUIDs and aggregate evidence
    grouped_evidence: Dict[str, List[UUIDEvidence]] = {}
    for ev in raw_evidences:
        grouped_evidence.setdefault(ev.normalized_uuid, []).append(ev)

    candidates: List[UUIDCandidate] = []
    total_custom_count = 0
    total_sig_count = 0

    for norm_uuid, ev_list in grouped_evidence.items():
        # Deduplicate evidence locations: keep distinct (dex_file, class_name, method_name, extraction_method, original_text)
        seen_keys: Set[Tuple[str, Optional[str], Optional[str], str, str]] = set()
        distinct_evidence: List[UUIDEvidence] = []
        for ev in ev_list:
            key = (ev.dex_file, ev.class_name, ev.method_name, ev.extraction_method, ev.original_text)
            if key not in seen_keys:
                seen_keys.add(key)
                distinct_evidence.append(ev)

        # Sort distinct evidence deterministically
        distinct_evidence.sort(
            key=lambda e: (
                e.dex_file,
                e.extraction_method,
                e.class_name or "",
                e.method_name or "",
                e.original_text,
            )
        )

        is_sig = is_bluetooth_sig_range(norm_uuid)
        short_hex = extract_short_hex(norm_uuid)
        sig_name = lookup_sig_name(short_hex)

        if is_sig:
            total_sig_count += 1
        else:
            total_custom_count += 1

        candidates.append(
            UUIDCandidate(
                normalized_uuid=norm_uuid,
                is_bluetooth_sig_range=is_sig,
                short_hex=short_hex,
                sig_name=sig_name,
                occurrence_count=len(ev_list),
                evidence=distinct_evidence,
            )
        )

    # Sort candidates deterministically by normalized UUID
    candidates.sort(key=lambda c: c.normalized_uuid)

    # 4. Synthesize API indicator flags
    framework_sorted = sorted(framework_classes)
    app_sorted = sorted(app_classes)
    referenced_methods.sort(
        key=lambda m: (m.dex_file, m.class_name, m.method_name, m.descriptor)
    )

    all_method_names = {m.method_name for m in referenced_methods}
    all_class_names = set(framework_sorted)

    has_gatt_client = (
        "android.bluetooth.BluetoothGatt" in all_class_names
        or "android.bluetooth.BluetoothGattCallback" in all_class_names
        or bool({"connectGatt", "discoverServices", "readCharacteristic", "writeCharacteristic"}.intersection(all_method_names))
    )
    has_gatt_server = (
        "android.bluetooth.BluetoothGattServer" in all_class_names
        or "android.bluetooth.BluetoothGattServerCallback" in all_class_names
        or bool({"openGattServer", "addService", "sendResponse"}.intersection(all_method_names))
    )
    has_le_scanner = (
        "android.bluetooth.le.BluetoothLeScanner" in all_class_names
        or "android.bluetooth.le.ScanCallback" in all_class_names
        or bool({"startScan", "stopScan"}.intersection(all_method_names))
    )
    has_le_advertiser = (
        "android.bluetooth.le.BluetoothLeAdvertiser" in all_class_names
        or "android.bluetooth.le.AdvertiseCallback" in all_class_names
        or bool({"startAdvertising", "stopAdvertising"}.intersection(all_method_names))
    )
    has_classic_bluetooth = (
        "android.bluetooth.BluetoothAdapter" in all_class_names
        or "android.bluetooth.BluetoothDevice" in all_class_names
        or "android.bluetooth.BluetoothSocket" in all_class_names
        or "android.bluetooth.BluetoothServerSocket" in all_class_names
    )

    api_indicators = BLEApiIndicators(
        framework_classes=framework_sorted,
        app_classes=app_sorted,
        referenced_methods=referenced_methods,
        has_gatt_client=has_gatt_client,
        has_gatt_server=has_gatt_server,
        has_le_scanner=has_le_scanner,
        has_le_advertiser=has_le_advertiser,
        has_classic_bluetooth=has_classic_bluetooth,
    )

    has_indicators = (
        permissions.has_ble_permission
        or permissions.has_classic_permission
        or bool(framework_sorted)
        or bool(app_sorted)
        or bool(referenced_methods)
        or bool(candidates)
    )

    # 5. Mandatory analytical summary notes
    summary_notes.append(
        "Static analysis note: UUID candidates extracted from string pools or bytecode instructions are potential identifiers. Presence in a string pool or instruction is not proof of runtime use or active transmission."
    )

    summary_notes.append(
        "Service registration note: A BLE API reference is not proof of server-side service registration or active GATT server establishment."
    )

    summary_notes.append(
        "No UUID is marked as registered in Phase 2; all extracted UUIDs represent static candidates without registration verdicts."
    )
    summary_notes.append(
        "Scope limitation: Analysis relies on DEX string pools, method reference tables, and const-string instruction inspection. Full program slicing and inter-procedural data-flow analysis are not performed."
    )
    summary_notes.append(
        "Known false-positive sources: Standalone 4-character hex strings in DEX string pools (e.g. '0000', 'dead', 'fade') match 16-bit Bluetooth UUID syntax but may represent arbitrary string constants, dates, or hash fragments unless matched with known Bluetooth SIG assigned numbers or BLE API call sites."
    )

    return BLEAnalysisResult(
        has_ble_indicators=has_indicators,
        permissions=permissions,
        api_indicators=api_indicators,
        uuid_candidates=candidates,
        candidate_summary={
            "total_candidates": len(candidates),
            "bluetooth_sig_range_count": total_sig_count,
            "custom_uuid_count": total_custom_count,
            "total_evidence_locations": len(raw_evidences),
            "dex_files_analyzed": len(dex_files_analyzed),
        },
        summary_notes=summary_notes,
    )
