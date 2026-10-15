# UCSD Report Schema Specification

This document defines the stable machine-readable JSON report schema and human-readable standalone HTML reporting formats produced by UCSD (UUID Confusion Static Detection).

---

## 1. Overview

UCSD generates two structured reporting artifacts:
1. **Single-APK Analysis Report (`AnalysisReport`)**: Comprehensive static evaluation of an individual Android application package covering intake metadata, Bluetooth permissions and API indicators, candidate UUID extraction, conservative GATT service registration tracing, and knowledge-base provenance lookup.
2. **Multi-APK Batch Report (`BatchAnalysisReport`)**: Aggregated multi-package evaluation capturing per-APK metrics, cross-APK static registration overlaps (`STRONG_DUPLICATE_STATIC_REGISTRATION`), duplicate candidate strings without dual registration (`DUPLICATE_CANDIDATE_NO_REGISTRATION`), and intake failure diagnostics.

Every run generates both **JSON** and **standalone, offline HTML** reports simultaneously by default.

---

## 2. Single-APK Analysis Report Schema (`AnalysisReport`)

Root object written to `<stem>_<sha256[:12]>_report.json` and `<stem>_<sha256[:12]>_report.html`.

### Top-Level Fields

| Field Name | Type | Nullable | Description |
|------------|------|----------|-------------|
| `status` | string | No | `'success'`, `'partial'`, or `'error'`. |
| `timestamp` | string | No | ISO 8601 UTC timestamp of the analysis run. |
| `target` | string | No | Path to the target APK provided to the CLI. |
| `analyzer_version` | string | No | Semantic version of the UCSD analysis engine (e.g. `"0.1.0"`). |
| `knowledge_base_version` | string | Yes | Semantic version of the curated UUID knowledge base (e.g. `"1.0.0"`), or null if disabled/unavailable. |
| `metadata` | object | Yes | Normalized APK intake metadata (`APKMetadata`), or null if intake failed. |
| `ble_analysis` | object | Yes | Static Bluetooth permissions, API indicators, and UUID candidates (`BLEAnalysisResult`). |
| `registration_analysis` | object | Yes | GATT service registration findings and intra-method register traces (`RegistrationAnalysisResult`). |
| `knowledge_base_assessment` | object | Yes | Single-APK UUID evaluation against curated knowledge base (`SingleAPKKnowledgeAssessment`). |
| `limitations` | array[string] | No | Explicit analytical boundaries and methodology caveats. |
| `html_report_path` | string | Yes | Local path to the standalone HTML report. |
| `error` | object | Yes | Structured error details if `status` is `'error'` or `'partial'`. |

---

### `metadata` Object (`APKMetadata`)

| Field Name | Type | Description |
|------------|------|-------------|
| `file_path` | string | Normalized file path of the analyzed APK. |
| `file_name` | string | Base filename of the APK archive. |
| `file_size_bytes` | integer | Total file size in bytes. |
| `sha256` | string | Streaming SHA-256 cryptographic digest of the entire APK file. |
| `is_valid_zip` | boolean | True if archive passed ZIP CRC32 and central directory validation. |
| `is_multidex` | boolean | True if more than one DEX file exists (`classes*.dex`). |
| `dex_count` | integer | Total count of DEX files in the archive. |
| `dex_files` | array[object] | Array of `DEXInfo` objects (`name`, `sha256`, `size_bytes`). |
| `manifest` | object | Manifest metadata (`package_name`, `version_code`, `version_name`, `min_sdk_version`, `target_sdk_version`, `requested_permissions`, `declared_permissions`, `activities`, `services`, `receivers`, `providers`, `main_activity`). |

---

### `ble_analysis` Object (`BLEAnalysisResult`)

| Field Name | Type | Description |
|------------|------|-------------|
| `has_ble_indicators` | boolean | True if any BLE permissions, framework classes, or candidate UUIDs were detected. |
| `permissions` | object | Categorized requested/declared Bluetooth permissions (`is_modern_ble`, `has_admin_permission`, `has_connect_permission`, `has_scan_permission`, `has_advertise_permission`). |
| `api_indicators` | object | Method reference and class inspection (`has_gatt_client`, `has_gatt_server`, `has_le_scanner`, `has_le_advertiser`, `framework_classes`, `app_classes`, `referenced_methods`). |
| `uuid_candidates` | array[object] | Deduplicated array of `UUIDCandidate` models sorted by normalized UUID. |

Each `UUIDCandidate` contains:
- `normalized_uuid`: 128-bit lowercase hyphenated UUID (`0000180d-0000-1000-8000-00805f9b34fb`).
- `is_bluetooth_sig_range`: True if expanded from 16-bit or in the standard Bluetooth Base UUID range.
- `sig_name`: Standard service/characteristic name if in Bluetooth SIG range, else null.
- `occurrence_count`: Total occurrences across all DEX files.
- `evidence`: Array of `UUIDEvidence` objects detailing extraction method (`bytecode_instruction` or `string_pool`), `dex_file`, `class_name`, `method_name`, and context.

---

### `registration_analysis` Object (`RegistrationAnalysisResult`)

| Field Name | Type | Description |
|------------|------|-------------|
| `has_gatt_registrations` | boolean | True if any `STRONG_STATIC_ASSOCIATION` findings exist. |
| `total_add_service_calls` | integer | Total call sites of `BluetoothGattServer.addService()`. |
| `total_service_constructions` | integer | Total call sites of `BluetoothGattService.<init>()`. |
| `strong_associations_count` | integer | Count of verified static register data-flow registrations. |
| `unresolved_patterns_count` | integer | Count of unresolved registration patterns. |
| `candidate_only_count` | integer | Count of UUID candidates without service registration call sites. |
| `findings` | array[object] | Array of `RegistrationFinding` objects. |

Each `RegistrationFinding` specifies:
- `evidence_level`: Strictly categorical enum:
  - `STRONG_STATIC_ASSOCIATION`: Verified intra-method Dalvik register data-flow linking a UUID literal to service construction and `addService()`.
  - `REGISTRATION_PATTERN_UUID_UNRESOLVED`: Registration call site where service or UUID resolution crosses method/field boundaries.
  - `UUID_CANDIDATE_ONLY`: UUID candidate with no associated service registration call site.
- `normalized_uuid`: Normalized 128-bit UUID if resolved.
- `dex_file`, `class_name`, `method_name`, `descriptor`: Exact code location.
- `trace_steps`: Array of `TraceStep` records capturing opcode, step type, instruction offset, and Dalvik registers.

---

### `knowledge_base_assessment` Object (`SingleAPKKnowledgeAssessment`)

| Field Name | Type | Description |
|------------|------|-------------|
| `total_candidates_checked` | integer | Total unique UUID candidates evaluated against the knowledge base. |
| `known_standard_matches_count` | integer | Count of verified Bluetooth SIG standard specification matches. |
| `known_system_vendor_matches_count` | integer | Count of sourced OS or hardware vendor specification matches. |
| `unknown_candidates_count` | integer | Count of candidate UUIDs with no matching knowledge-base entry. |
| `findings` | array[object] | Array of `UUIDConflictAssessment` records detailing provenance, category, and analyst notes. |

---

## 3. Multi-APK Batch Report Schema (`BatchAnalysisReport`)

Written to `batch_report.json` and `batch_report.html` when executing `ucsd batch`.

### Top-Level Fields

| Field Name | Type | Description |
|------------|------|-------------|
| `status` | string | `'success'` (all succeeded), `'partial'` (some succeeded, some failed), or `'error'`. |
| `timestamp` | string | ISO 8601 UTC timestamp of the batch run. |
| `analyzer_version` | string | UCSD static analyzer version. |
| `knowledge_base_version` | string | Active UUID knowledge base version. |
| `target_directory` | string | Input directory path or description of analyzed targets. |
| `total_targets` | integer | Total APK files discovered or provided. |
| `successful_count` | integer | Number of APKs successfully processed. |
| `failed_count` | integer | Number of APKs that failed intake or parsing. |
| `apk_summaries` | array[object] | Array of `SingleAPKSummary` records for each successful APK. |
| `cross_apk_conflicts` | object | Multi-APK conflict evaluation (`CrossAPKConflictReport`). |
| `failed_targets` | array[object] | Structured intake error records for failed targets (`target`, `error_type`, `message`). |
| `limitations` | array[string] | Explicit analytical boundaries and methodology caveats. |
| `html_report_path` | string | Local path to the batch HTML report. |

---

### Cross-APK Conflict Categories

UCSD strictly separates cross-package findings into mutually exclusive categories:

1. **`STRONG_DUPLICATE_STATIC_REGISTRATION` (`is_proven = true`)**:
   Two or more distinct APK packages both exhibit verified intra-method Dalvik register data-flow (`STRONG_STATIC_ASSOCIATION`) associating the identical GATT service UUID with `BluetoothGattServer.addService()`.
   *Interpretation:* High-confidence static overlap. May warrant runtime/host-context validation. Does NOT constitute proof of runtime vulnerability or confirmed service squatting.
2. **`DUPLICATE_CANDIDATE_NO_REGISTRATION` (`is_proven = false`)**:
   Identical candidate UUID string appears across multiple APKs without dual verified static GATT registration (e.g. from shared third-party SDKs or constant pools).
   *Interpretation:* Strictly NOT presented as a runtime service conflict.
3. **`KNOWN_ASSIGNED_STANDARD_MATCH` (`is_proven = false`)**:
   Candidate matches an official Bluetooth SIG assigned specification (e.g. Heart Rate `0x180D`, Battery `0x180F`).
   *Interpretation:* Standard protocol identifier; not indicative of conflict or malicious intent.
4. **`KNOWN_SYSTEM_OR_VENDOR_MATCH` (`is_proven = false`)**:
   Matches an OS vendor or hardware vendor specification backed by verifiable provenance in the knowledge base.
5. **`UNKNOWN_UNCONFLICTED` (`is_proven = false`)**:
   Candidate UUID is not present in the curated knowledge base and is confined to a single analyzed APK.

---

## 4. Standalone HTML Reporting Design

1. **Zero External Runtime Dependencies**: All CSS stylesheets are embedded directly in the `<style>` block. No external CDNs, fonts, or external JavaScript files are loaded. Reports render fully offline in any modern browser.
2. **Strict Context Escaping**: All APK-controlled strings (package IDs, version strings, permissions, class names, method names, bytecode string pool contents, error strings) are escaped via `html.escape(val, quote=True)` to prevent HTML and cross-site script injection.
3. **Deterministic Output**: Arrays of DEX files, candidate UUIDs, permissions, and conflict findings are sorted alphabetically and deterministically.
