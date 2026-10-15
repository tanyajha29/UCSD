"""Assessment engine for UUID knowledge base lookup and cross-APK conflict evaluation."""

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ucsd.conflict.models import (
    ConflictCondition,
    CrossAPKEvidence,
    CrossAPKConflictReport,
    SingleAPKKnowledgeAssessment,
    UUIDConflictAssessment,
)
from ucsd.knowledge.models import KnowledgeBaseEntry
from ucsd.knowledge.repository import UUIDKnowledgeBase
from ucsd.models import APKMetadata

METHODOLOGY_NOTES = [
    "Definition of Strong Duplicate Static Registration: An assessment is classified as STRONG_DUPLICATE_STATIC_REGISTRATION (with is_proven = true strictly according to UCSD's static-analysis evidence criteria) if and only if two or more distinct APK packages both demonstrate verified intra-method Dalvik register data-flow (STRONG_STATIC_ASSOCIATION) associating the identical GATT service UUID with BluetoothGattServer.addService(). Static analysis establishes high-confidence static overlap; it does NOT constitute proof of runtime vulnerability, confirmed host collision, or confirmed service squatting.",
    "Duplicate Candidates are NOT Proven Conflicts: Identical UUID candidate strings appearing across multiple APKs (e.g. from shared third-party SDKs, utility libraries, or string pools) without verified dual static GATT registration are classified as DUPLICATE_CANDIDATE_NO_REGISTRATION. They are explicitly NOT presented as runtime service conflicts.",
    "Non-Malicious Nature of Assigned Standards: Matching a Bluetooth SIG assigned UUID (e.g. Heart Rate, Battery Service) or known vendor identifier is a standard protocol implementation pattern. It does NOT indicate malicious intent or spoofing without operational device evidence.",
    "No Unverifiable System/Vendor Claims: An identifier is classified as system-level or vendor-specific (KNOWN_SYSTEM_OR_VENDOR_MATCH) only when supported by verifiable source documentation in the versioned knowledge base.",
    "Strict Absence of Calibrated Probabilities: Conflict determinations are discrete qualitative classifications based on verified static Dalvik bytecode evidence, not numeric risk scores or calibrated percentages.",
    "Knowledge Base Scope and Currency: The UUID knowledge base contains curated identifiers with verifiable provenance. Unknown UUIDs remain strictly unknown (UNKNOWN_UNCONFLICTED).",
]


def assess_single_apk(
    metadata: APKMetadata,
    kb: Optional[UUIDKnowledgeBase] = None,
) -> SingleAPKKnowledgeAssessment:
    """Assess all UUIDs within a single APK against the knowledge base.

    Args:
        metadata: Analyzed APK metadata with BLE and/or registration results.
        kb: Optional UUIDKnowledgeBase repository. If None, default instance is loaded.

    Returns:
        SingleAPKKnowledgeAssessment model with evaluated findings.
    """
    if kb is None:
        kb = UUIDKnowledgeBase()

    # Collect all unique UUIDs and their strongest evidence in this APK
    uuid_evidence_map: Dict[str, CrossAPKEvidence] = {}

    pkg_name = metadata.manifest.package_name if metadata.manifest else None
    v_code = metadata.manifest.version_code if metadata.manifest else None
    v_name = metadata.manifest.version_name if metadata.manifest else None

    # 1. From registration analysis findings (highest fidelity)
    if metadata.registration_analysis:
        for finding in metadata.registration_analysis.findings:
            if finding.normalized_uuid:
                u = finding.normalized_uuid
                offset = (
                    finding.trace_steps[-1].instruction_offset
                    if finding.trace_steps
                    else None
                )
                ev = CrossAPKEvidence(
                    package_name=pkg_name,
                    version_code=v_code,
                    version_name=v_name,
                    file_name=metadata.file_name,
                    sha256=metadata.sha256,
                    evidence_level=finding.evidence_level.value,
                    class_name=finding.class_name or None,
                    method_name=finding.method_name or None,
                    descriptor=finding.descriptor or None,
                    dex_file=finding.dex_file or None,
                    instruction_offset=offset,
                    diagnosis=finding.diagnosis,
                )
                # Keep strongest evidence
                if u not in uuid_evidence_map or finding.evidence_level.value == "STRONG_STATIC_ASSOCIATION":
                    uuid_evidence_map[u] = ev

    # 2. From BLE candidate analysis
    if metadata.ble_analysis:
        for cand in metadata.ble_analysis.uuid_candidates:
            u = cand.normalized_uuid
            if u not in uuid_evidence_map:
                first_ev = cand.evidence[0] if cand.evidence else None
                diag = (
                    f"Candidate UUID '{u}' detected across {cand.occurrence_count} location(s) "
                    f"in DEX files without verified GATT service registration."
                )
                ev = CrossAPKEvidence(
                    package_name=pkg_name,
                    version_code=v_code,
                    version_name=v_name,
                    file_name=metadata.file_name,
                    sha256=metadata.sha256,
                    evidence_level="UUID_CANDIDATE_ONLY",
                    class_name=first_ev.class_name if first_ev else None,
                    method_name=first_ev.method_name if first_ev else None,
                    descriptor=None,
                    dex_file=first_ev.dex_file if first_ev else None,
                    instruction_offset=None,
                    diagnosis=diag,
                )
                uuid_evidence_map[u] = ev

    # Evaluate each UUID against knowledge base
    assessments: List[UUIDConflictAssessment] = []
    standard_count = 0
    vendor_count = 0
    unknown_count = 0

    for u in sorted(uuid_evidence_map.keys()):
        ev = uuid_evidence_map[u]
        kb_res = kb.lookup(u)

        if kb_res.is_known and kb_res.entry:
            entry = kb_res.entry
            if entry.is_system_or_vendor:
                condition = ConflictCondition.KNOWN_SYSTEM_OR_VENDOR_MATCH
                vendor_count += 1
                explanation = (
                    f"Matches verified system/vendor specification '{entry.name}' "
                    f"published by {entry.source_name} ({entry.source_url}). "
                    f"Analyst note: {entry.analyst_notes}"
                )
            else:
                condition = ConflictCondition.KNOWN_ASSIGNED_STANDARD_MATCH
                standard_count += 1
                explanation = (
                    f"Matches official Bluetooth SIG assigned specification '{entry.name}' "
                    f"({entry.source_url}). Standard protocol identifier; not indicative of conflict "
                    f"or malicious intent. Analyst note: {entry.analyst_notes}"
                )
            assessments.append(
                UUIDConflictAssessment(
                    normalized_uuid=u,
                    condition=condition,
                    is_proven=False,
                    is_proven_service_conflict=False,
                    explanation=explanation,
                    knowledge_base_match=entry,
                    participating_apks=[ev],
                )
            )
        else:
            condition = ConflictCondition.UNKNOWN_UNCONFLICTED
            unknown_count += 1
            explanation = (
                f"Identifier '{u}' is not present in the curated knowledge base and is confined "
                f"to this single APK without multi-app collision analysis."
            )
            assessments.append(
                UUIDConflictAssessment(
                    normalized_uuid=u,
                    condition=condition,
                    is_proven=False,
                    is_proven_service_conflict=False,
                    explanation=explanation,
                    knowledge_base_match=None,
                    participating_apks=[ev],
                )
            )

    return SingleAPKKnowledgeAssessment(
        total_candidates_checked=len(assessments),
        known_standard_matches_count=standard_count,
        known_system_vendor_matches_count=vendor_count,
        unknown_candidates_count=unknown_count,
        findings=assessments,
    )


def compare_apks(
    apk_list: List[APKMetadata],
    kb: Optional[UUIDKnowledgeBase] = None,
) -> CrossAPKConflictReport:
    """Perform cross-APK comparison for UUID conflicts and knowledge base matching.

    Args:
        apk_list: List of analyzed APKMetadata objects to cross-evaluate.
        kb: Optional UUIDKnowledgeBase repository.

    Returns:
        CrossAPKConflictReport containing categorized conflict determinations.
    """
    if kb is None:
        kb = UUIDKnowledgeBase()

    # Map normalized_uuid -> list of CrossAPKEvidence from all APKs
    uuid_cross_evidence: Dict[str, List[CrossAPKEvidence]] = defaultdict(list)

    for metadata in apk_list:
        pkg_name = metadata.manifest.package_name if metadata.manifest else None
        v_code = metadata.manifest.version_code if metadata.manifest else None
        v_name = metadata.manifest.version_name if metadata.manifest else None

        apk_uuids_seen: Set[str] = set()

        # 1. Registration findings
        if metadata.registration_analysis:
            for finding in metadata.registration_analysis.findings:
                if finding.normalized_uuid:
                    u = finding.normalized_uuid
                    offset = (
                        finding.trace_steps[-1].instruction_offset
                        if finding.trace_steps
                        else None
                    )
                    ev = CrossAPKEvidence(
                        package_name=pkg_name,
                        version_code=v_code,
                        version_name=v_name,
                        file_name=metadata.file_name,
                        sha256=metadata.sha256,
                        evidence_level=finding.evidence_level.value,
                        class_name=finding.class_name or None,
                        method_name=finding.method_name or None,
                        descriptor=finding.descriptor or None,
                        dex_file=finding.dex_file or None,
                        instruction_offset=offset,
                        diagnosis=finding.diagnosis,
                    )
                    uuid_cross_evidence[u].append(ev)
                    apk_uuids_seen.add(u)

        # 2. BLE candidate findings
        if metadata.ble_analysis:
            for cand in metadata.ble_analysis.uuid_candidates:
                u = cand.normalized_uuid
                if u not in apk_uuids_seen:
                    first_ev = cand.evidence[0] if cand.evidence else None
                    diag = (
                        f"Candidate UUID '{u}' detected across {cand.occurrence_count} location(s) "
                        f"in DEX files without verified GATT service registration."
                    )
                    ev = CrossAPKEvidence(
                        package_name=pkg_name,
                        version_code=v_code,
                        version_name=v_name,
                        file_name=metadata.file_name,
                        sha256=metadata.sha256,
                        evidence_level="UUID_CANDIDATE_ONLY",
                        class_name=first_ev.class_name if first_ev else None,
                        method_name=first_ev.method_name if first_ev else None,
                        descriptor=None,
                        dex_file=first_ev.dex_file if first_ev else None,
                        instruction_offset=None,
                        diagnosis=diag,
                    )
                    uuid_cross_evidence[u].append(ev)
                    apk_uuids_seen.add(u)

    assessments: List[UUIDConflictAssessment] = []
    strong_static_conflicts_count = 0
    duplicate_unregistered_count = 0
    standard_matches_count = 0
    system_vendor_matches_count = 0
    unknown_count = 0

    for u in sorted(uuid_cross_evidence.keys()):
        ev_list = uuid_cross_evidence[u]
        kb_res = kb.lookup(u)
        kb_entry = kb_res.entry if kb_res.is_known else None

        # Distinct packages (fallback to file_name or sha256 if package_name missing)
        distinct_packages: Set[str] = {
            ev.package_name or ev.file_name for ev in ev_list
        }
        distinct_count = len(distinct_packages)

        # Count strong static registration packages
        strong_packages: Set[str] = {
            ev.package_name or ev.file_name
            for ev in ev_list
            if ev.evidence_level == "STRONG_STATIC_ASSOCIATION"
        }
        unresolved_packages: Set[str] = {
            ev.package_name or ev.file_name
            for ev in ev_list
            if ev.evidence_level == "REGISTRATION_PATTERN_UUID_UNRESOLVED"
        }

        # Track KB categorization
        if kb_entry:
            if kb_entry.is_system_or_vendor:
                system_vendor_matches_count += 1
            else:
                standard_matches_count += 1
        else:
            unknown_count += 1

        kb_note = ""
        if kb_entry:
            kb_note = (
                f" [Knowledge Base Provenance: '{kb_entry.name}' sourced from "
                f"{kb_entry.source_name} ({kb_entry.source_url})]"
            )

        # Condition Evaluation
        if distinct_count >= 2 and len(strong_packages) >= 2:
            # STRONG_DUPLICATE_STATIC_REGISTRATION: Two distinct APKs contain strong static evidence associating the same UUID with GATT service registration
            condition = ConflictCondition.STRONG_DUPLICATE_STATIC_REGISTRATION
            is_proven = True
            strong_static_conflicts_count += 1
            pkgs_str = ", ".join(sorted(strong_packages))
            explanation = (
                f"Two distinct APKs ({pkgs_str}) contain strong static evidence (STRONG_STATIC_ASSOCIATION) "
                f"associating the same UUID '{u}' with GATT service registration via "
                f"BluetoothGattServer.addService(). This is a high-confidence static overlap "
                f"and may warrant runtime/host-context validation.{kb_note}"
            )

        elif distinct_count >= 2 and (len(strong_packages) == 1 and len(unresolved_packages) >= 1):
            condition = ConflictCondition.UNRESOLVED_REGISTRATION_OVERLAP
            is_proven = False
            explanation = (
                f"UNRESOLVED REGISTRATION OVERLAP: Multiple applications reference UUID '{u}', "
                f"where one package has strong registration evidence and another has an unresolved "
                f"cross-method/field registration pattern. This is NOT classified as a proven service conflict "
                f"without verified dual registration.{kb_note}"
            )

        elif distinct_count >= 2 and len(unresolved_packages) >= 2:
            condition = ConflictCondition.UNRESOLVED_REGISTRATION_OVERLAP
            is_proven = False
            explanation = (
                f"UNRESOLVED REGISTRATION OVERLAP: Multiple applications attempt service registrations "
                f"associated with UUID '{u}', but registration patterns in both applications remain unresolved "
                f"(cross-method parameter, field read, or dynamic expression). Not proven.{kb_note}"
            )

        elif distinct_count >= 2:
            # DUPLICATE_CANDIDATE_NO_REGISTRATION: Candidate strings present across multiple APKs without dual registration
            condition = ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION
            is_proven = False
            duplicate_unregistered_count += 1
            pkgs_str = ", ".join(sorted(distinct_packages))
            explanation = (
                f"DUPLICATE CANDIDATE STRINGS (NO DUAL REGISTRATION): Identical UUID candidate string '{u}' "
                f"appears across {distinct_count} distinct APK packages ({pkgs_str}), but the applications "
                f"LACK verified dual static GATT service registrations. This is commonly caused by shared "
                f"third-party utility libraries or constant pools and is NOT a proven service conflict.{kb_note}"
            )

        else:
            # Single APK occurrence
            is_proven = False
            if kb_entry and kb_entry.is_system_or_vendor:
                condition = ConflictCondition.KNOWN_SYSTEM_OR_VENDOR_MATCH
                explanation = (
                    f"Matches verified system/vendor specification '{kb_entry.name}' "
                    f"({kb_entry.source_name}). Confined to single analyzed APK."
                )
            elif kb_entry:
                condition = ConflictCondition.KNOWN_ASSIGNED_STANDARD_MATCH
                explanation = (
                    f"Matches official Bluetooth SIG assigned specification '{kb_entry.name}'. "
                    f"Standard protocol identifier; not indicative of conflict or malicious intent."
                )
            else:
                condition = ConflictCondition.UNKNOWN_UNCONFLICTED
                explanation = (
                    f"Identifier '{u}' is unknown in the knowledge base and is referenced by a single analyzed APK."
                )

        assessments.append(
            UUIDConflictAssessment(
                normalized_uuid=u,
                condition=condition,
                is_proven=is_proven,
                is_proven_service_conflict=is_proven,
                explanation=explanation,
                knowledge_base_match=kb_entry,
                participating_apks=ev_list,
            )
        )

    return CrossAPKConflictReport(
        total_apks_analyzed=len(apk_list),
        total_unique_uuids_evaluated=len(assessments),
        strong_duplicate_static_registrations_count=strong_static_conflicts_count,
        proven_registration_conflicts_count=strong_static_conflicts_count,
        duplicate_candidates_unregistered_count=duplicate_unregistered_count,
        known_standard_matches_count=standard_matches_count,
        known_system_vendor_matches_count=system_vendor_matches_count,
        unknown_uuids_count=unknown_count,
        assessments=assessments,
        knowledge_base_metadata=kb.get_metadata(),
        methodology_and_limitations=METHODOLOGY_NOTES,
    )
