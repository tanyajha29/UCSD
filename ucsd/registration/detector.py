"""Conservative, evidence-grounded GATT service registration detection engine."""

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    from loguru import logger
    logger.disable("androguard")
except ImportError:
    pass

try:
    from androguard.core.dex import DEX
except ImportError:
    from androguard.core.bytecodes.dvm import DalvikVMFormat as DEX

from ucsd.registration.models import (
    AddServiceCallSite,
    EvidenceLevel,
    RegistrationAnalysisResult,
    RegistrationFinding,
    ServiceConstructionSite,
    UnresolvedReason,
)
from ucsd.registration.tracer import trace_method_registrations

_DEX_PATTERN = re.compile(r"^classes(\d+)?\.dex$")

_GATT_SERVICE_INIT_SIG = "Landroid/bluetooth/BluetoothGattService;-><init>"
_GATT_SERVER_ADD_SIG = "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z"

KNOWN_BLIND_SPOTS = [
    "Cross-Method Data Flow: BluetoothGattService objects constructed in helper/factory methods and passed across method boundaries to addService() are classified as REGISTRATION_PATTERN_UUID_UNRESOLVED because inter-procedural data-flow slicing is not performed.",
    "Field-Based Storage: Services or UUIDs stored in instance/static fields (e.g. this.mService) and subsequently registered in separate lifecycle methods are classified as REGISTRATION_PATTERN_UUID_UNRESOLVED (FIELD_BASED_SERVICE_OBJECT).",
    "Dynamic and Obfuscated UUIDs: UUID values generated at runtime via string concatenation, byte arrays, reflection, or UUID.randomUUID() cannot be resolved to static string literals.",
    "Control-Flow Sensitivity: Intra-method tracing models forward register simulation; complex branching where registers are redefined on alternative paths falls back safely to REGISTRATION_PATTERN_UUID_UNRESOLVED.",
    "Non-Standard Wrapper Frameworks: Third-party reactive or proprietary BLE vendor SDKs that encapsulate BluetoothGattServer internally without calling standard Android framework APIs directly are not tracked.",
]


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
    """Convert Smali class descriptor (e.g. 'Lcom/example/MyClass;') to Java notation."""
    s = raw.strip()
    if s.startswith("L") and s.endswith(";"):
        s = s[1:-1]
    return s.replace("/", ".")


def detect_gatt_registrations(
    apk_path: Union[str, Path],
    candidate_uuids: Optional[List[str]] = None,
) -> RegistrationAnalysisResult:
    """Scan all DEX files in an APK for GATT service registration call sites and data-flow links.

    Strictly conservative:
    - Never uses proximity of strings in DEX as proof of data flow.
    - Never represents heuristic evidence levels as calibrated probabilities.
    - Classifies findings strictly into STRONG_STATIC_ASSOCIATION, REGISTRATION_PATTERN_UUID_UNRESOLVED,
      or UUID_CANDIDATE_ONLY.

    Args:
        apk_path: Path to the Android APK file.
        candidate_uuids: Optional list of normalized candidate UUIDs from Phase 2.

    Returns:
        RegistrationAnalysisResult model with findings and summary statistics.
    """
    path = Path(apk_path).resolve()
    all_findings: List[RegistrationFinding] = []
    all_constructions: List[ServiceConstructionSite] = []
    all_add_services: List[AddServiceCallSite] = []

    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            dex_names = [n for n in zf.namelist() if _DEX_PATTERN.match(n)]
            dex_names.sort(key=_natural_dex_sort_key)

            for dex_name in dex_names:
                try:
                    dex_bytes = zf.read(dex_name)
                    dex_obj = DEX(dex_bytes)
                except Exception:
                    continue

                # Fast check: does this DEX reference BluetoothGattService.<init> or BluetoothGattServer.addService?
                dex_method_sigs = set()
                try:
                    for m in dex_obj.get_methods():
                        cname = m.get_class_name()
                        if "bluetooth" in cname.lower():
                            dex_method_sigs.add(f"{cname}->{m.get_name()}{m.get_descriptor()}")
                except Exception:
                    pass

                has_service_init_in_dex = any(_GATT_SERVICE_INIT_SIG in s for s in dex_method_sigs)
                has_add_service_in_dex = any(_GATT_SERVER_ADD_SIG in s for s in dex_method_sigs)

                if not (has_service_init_in_dex or has_add_service_in_dex):
                    continue

                # Inspect classes and methods in this DEX
                try:
                    for cls in dex_obj.get_classes():
                        clean_cls = _clean_smali_class_name(cls.get_name())
                        for m in cls.get_methods():
                            code = m.get_code()
                            if not code:
                                continue

                            inss = list(code.get_bc().get_instructions())
                            # Quick pre-filter on method instructions
                            method_has_target = False
                            for ins in inss:
                                if ins.get_name().startswith("invoke-"):
                                    out_str = getattr(ins, "get_output", lambda: "")()
                                    if "BluetoothGattService;-><init>" in out_str or "BluetoothGattServer;->addService" in out_str:
                                        method_has_target = True
                                        break

                            if not method_has_target:
                                continue

                            # Run full intra-method register data-flow tracer
                            f_list, c_list, a_list = trace_method_registrations(
                                dex_file=dex_name,
                                class_name=clean_cls,
                                method_name=m.get_name(),
                                descriptor=m.get_descriptor(),
                                instructions=inss,
                            )
                            all_findings.extend(f_list)
                            all_constructions.extend(c_list)
                            all_add_services.extend(a_list)
                except Exception:
                    continue
    except Exception:
        pass

    # Correlate Phase 2 UUID candidates that were not associated with any registration site
    strongly_associated_uuids: Set[str] = {
        f.normalized_uuid for f in all_findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION and f.normalized_uuid
    }
    unresolved_finding_uuids: Set[str] = {
        f.normalized_uuid for f in all_findings if f.normalized_uuid and f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED
    }

    if candidate_uuids:
        for cand_uuid in sorted(candidate_uuids):
            if cand_uuid not in strongly_associated_uuids and cand_uuid not in unresolved_finding_uuids:
                all_findings.append(
                    RegistrationFinding(
                        evidence_level=EvidenceLevel.UUID_CANDIDATE_ONLY,
                        normalized_uuid=cand_uuid,
                        dex_file="",
                        class_name="",
                        method_name="",
                        descriptor="",
                        diagnosis=(
                            f"UUID candidate '{cand_uuid}' discovered in DEX constants/strings, "
                            f"but has no static data-flow link to BluetoothGattService constructor "
                            f"or BluetoothGattServer.addService() registration call sites."
                        ),
                        construction_site=None,
                        registration_site=None,
                        trace_steps=[],
                        unresolved_reason=UnresolvedReason.NO_REGISTRATION_CALL_SITE,
                    )
                )

    strong_count = sum(1 for f in all_findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION)
    unresolved_count = sum(1 for f in all_findings if f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED)
    candidate_only_count = sum(1 for f in all_findings if f.evidence_level == EvidenceLevel.UUID_CANDIDATE_ONLY)

    return RegistrationAnalysisResult(
        has_gatt_registrations=(strong_count > 0 or unresolved_count > 0),
        total_add_service_calls=len(all_add_services),
        total_service_constructions=len(all_constructions),
        strong_associations_count=strong_count,
        unresolved_patterns_count=unresolved_count,
        candidate_only_count=candidate_only_count,
        findings=all_findings,
        blind_spots_and_limitations=KNOWN_BLIND_SPOTS,
    )
