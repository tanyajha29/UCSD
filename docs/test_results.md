# UCSD Phase 6: Controlled Validation, Regression Tests & Test Matrix Results

## 1. Executive Summary

Phase 6 implements a rigorous, evidence-grounded validation and regression testing framework for the Universal Candidate Service Detector (UCSD). The objective is to validate the actual static capabilities and boundary failure modes of the pipeline without introducing speculative heuristics.

> [!IMPORTANT]
> **Validation Scope & Scientific Caveat**:
> Automated tests validate that UCSD's static data-flow engine behaves strictly in concordance with its documented rules against controlled fixtures with known ground truth. Passing unit and integration tests does **not** prove general runtime detection accuracy across all arbitrary, real-world Android applications. True runtime service squatting assessment requires host/runtime device instrumentation.

---

## 2. Test Matrix & Automated Test Results

The test matrix covers all required operational dimensions, spanning 17 specialized regression tests in [`tests/test_validation_matrix.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_validation_matrix.py) alongside 111 baseline and edge-case tests across the test suite (128 total automated tests).

| Test ID | Category | Target / Fixture | Expected Behavior | Observed Behavior | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-INV-01** | Invalid APK Input | `corrupt_zip_apk` | Fails ZIP CRC check; raises `CorruptZipAPKError`; generates JSON and HTML error reports. | `report.status == "error"`; `CorruptZipAPKError` captured; reports written to disk. | **PASS** |
| **TC-INV-02** | Invalid APK Input | `renamed_text_apk` | Fails ZIP header check; raises `CorruptZipAPKError`; error report written. | `CorruptZipAPKError` captured; graceful error reporting. | **PASS** |
| **TC-INV-03** | Invalid APK Input | `empty_apk` (0-byte) | Fails file size check; raises `EmptyFileAPKError`; error report written. | `EmptyFileAPKError` captured; status `error`. | **PASS** |
| **TC-INV-04** | Invalid APK Input | `non_existent_apk` | Fails file existence check; raises `FileNotFoundAPKError`. | `FileNotFoundAPKError` captured; status `error`. | **PASS** |
| **TC-INV-05** | Invalid APK Input | `zip_without_dex_apk` | Missing `classes*.dex`; raises `MissingDEXError`. | `MissingDEXError` captured; status `error`. | **PASS** |
| **TC-INV-06** | Invalid APK Input | `zip_without_manifest_apk` | Missing `AndroidManifest.xml`; raises `MissingManifestError`. | `MissingManifestError` captured; status `error`. | **PASS** |
| **TC-BLE-PERM-01** | Manifest BLE vs Bytecode | `ble_perm_no_service_api_apk` | Bluetooth permissions extracted; DEX has no BT APIs; candidate UUID marked `UUID_CANDIDATE_ONLY`. | Permissions extracted; `has_gatt_server: False`; 0 registrations; candidate marked `UUID_CANDIDATE_ONLY`. | **PASS** |
| **TC-BLE-CLIENT-01** | Client-Only BLE | `client_only_ble_apk` | `BluetoothGatt.discoverServices` detected; `has_gatt_client: True`; `has_gatt_server: False`; 0 registrations. | Client detected; server False; 0 registration call sites; candidate marked `UUID_CANDIDATE_ONLY`. | **PASS** |
| **TC-UNUSED-UUID-01** | Unused UUID Constant | `negative_candidate_apk` | Candidate UUID extracted from DEX string pool; no service registration data-flow; marked `UUID_CANDIDATE_ONLY`. | Candidate extracted; 0 registrations; marked `UUID_CANDIDATE_ONLY` (`NO_REGISTRATION_CALL_SITE`). | **PASS** |
| **TC-REG-STRONG-01** | Supported Local Registration | `conflict_apk_a` | Canonical intra-method literal UUID -> constructor -> `addService`; `STRONG_STATIC_ASSOCIATION`. | Exactly 1 strong association; all 4 trace steps matched with instruction offsets. | **PASS** |
| **TC-REG-UNRESOLVED-01** | Unresolved Call Site | `unresolved_registration_apk` | `BluetoothGattServer.addService` called with cross-method argument; `REGISTRATION_PATTERN_UUID_UNRESOLVED`. | Call site detected; `CROSS_METHOD_SERVICE_OBJECT`; `normalized_uuid: None`. | **PASS** |
| **TC-REG-UNRESOLVED-02** | Unresolved Call Site | `service_constructed_without_add_service_apk` | `BluetoothGattService.<init>` called with literal UUID, but `addService` never called; unresolved. | Construction site detected; `SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE`; UUID preserved. | **PASS** |
| **TC-REG-NEG-CLOBBER-01** | Negative Register Clobbering | `test_clobbered_uuid_register_before_service_constructor` | Register `v1` holding UUID clobbered by `const/4` before service constructor; rejects strong association. | `strong_associations: 0`; emits `REGISTRATION_PATTERN_UUID_UNRESOLVED` with `normalized_uuid: None`. | **PASS** |
| **TC-REG-NEG-CLOBBER-02** | Negative Register Clobbering | `test_clobbered_service_register_with_new_instance` | Register `v3` holding service clobbered by `new-instance Object` before `addService`; rejects strong association. | `strong_associations: 0`; emits `REGISTRATION_PATTERN_UUID_UNRESOLVED` (`CROSS_METHOD_SERVICE_OBJECT`). | **PASS** |
| **TC-REG-NEG-ORDER-01** | Negative Call Sequence | `test_out_of_order_add_service_before_constructor` | `addService` called prematurely before service constructor initializes register; rejects strong association. | `strong_associations: 0`; call site unassociated with UUID. | **PASS** |
| **TC-REG-REUSE-01** | Register Reuse Isolation | `test_register_reuse_associates_correct_uuid` | Register `v1` overwritten with UUID B after Service A created; registering Service A correctly associates UUID A. | Exactly 1 strong association linked exclusively to UUID A (no cross-talk). | **PASS** |
| **TC-CONFLICT-DUPLICATE-CAND-01** | Cross-APK Duplicate Candidate | `conflict_apk_a` vs `negative_candidate_apk` | Same candidate UUID in both APKs, but only APK A registers it; reported as `DUPLICATE_CANDIDATE_NO_REGISTRATION`. | `strong_duplicate_static_registrations: 0`; `duplicate_candidates_unregistered: 1`. | **PASS** |
| **TC-CONFLICT-DUPLICATE-STRONG-01** | Cross-APK Duplicate Strong Reg | `conflict_apk_a` vs `conflict_apk_b` | Two distinct packages each have verified `STRONG_STATIC_ASSOCIATION` for same UUID; `STRONG_DUPLICATE_STATIC_REGISTRATION`. | Exactly 1 strong duplicate registration; both participating packages recorded; `is_proven: True`. | **PASS** |
| **TC-CONFLICT-SAME-PKG-01** | Same Package Identity | `test_identical_package_name_across_apks_no_cross_conflict` | Two distinct APK files share same package name and UUID registration; rejects cross-app conflict. | `strong_duplicate_static_registrations: 0`; not flagged as inter-app collision. | **PASS** |
| **TC-CONFLICT-ASYMMETRIC-01** | Asymmetric Evidence Overlap | `test_asymmetric_registration_overlap_strong_and_unresolved` | One APK has strong registration, APK B has unresolved registration; rejects proven duplicate conflict. | Classified as `UNRESOLVED_REGISTRATION_OVERLAP`; `is_proven: False`. | **PASS** |
| **TC-CONFLICT-CAND-ONLY-01** | Unregistered Candidate Overlap | `test_duplicate_candidate_strings_never_proven_conflict` | 3 distinct APKs share identical candidate UUID string with zero registrations; never proven conflict. | Classified as `DUPLICATE_CANDIDATE_NO_REGISTRATION`; `is_proven: False`. | **PASS** |
| **TC-REPORT-TIERS-01** | Report Evidence Fidelity | `test_html_report_distinct_evidence_tiers_and_limitations` | Standalone HTML and JSON reports render distinct visual badges for all 3 evidence tiers and limitations. | Badges `STRONG STATIC`, `UNRESOLVED`, `CANDIDATE ONLY` cleanly rendered; JSON preserves categorical enums. | **PASS** |
| **TC-INPUT-DEGRADE-01** | Graceful Degradation | `conflict_apk_a` (missing KB) | Knowledge base unavailable; pipeline degrades to `status: "partial"`; records analytical limitations. | `status == "partial"`; limitations note added; registration findings preserved. | **PASS** |
| **TC-INPUT-DEGRADE-02** | Batch Corrupt Isolation | `conflict_apk_a` + `corrupt_zip_apk` | Valid APK analyzed; corrupt APK isolated into `failed_targets`; batch report succeeds. | `successful_count: 1`, `failed_count: 1`; `failed_targets` records `CorruptZipAPKError`. | **PASS** |
| **TC-IMMUTABILITY-01** | Input Immutability | `validation.apk` & `app.apk` | Input APK files in `/app/samples:ro` remain bit-for-bit identical before and after analysis. | SHA-256 and byte sizes before == after (0 byte divergence). | **PASS** |

---

## 3. Controlled Test Fixtures & Known Ground Truth

Synthetic APK fixtures are generated deterministically in [`tests/generate_fixtures.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/generate_fixtures.py) using real binary Dalvik executable (DEX v035) encoding and Android binary XML (AXML) chunk serialization.

### 3.1 Controlled Fixture Catalog

| Fixture Name | Package Name | DEX Characteristics | Ground Truth Description |
| :--- | :--- | :--- | :--- |
| `conflict_apk_a` | `org.example.service_a` | Dalvik opcodes: `const-string`, `UUID.fromString`, `new-instance BluetoothGattService`, `<init>`, `addService` | **Positive Registration**: Literal UUID `0000180d-0000-1000-8000-00805f9b34fb` registered locally in `registerService()V`. |
| `conflict_apk_b` | `org.example.service_b` | Dalvik opcodes: identical intra-method registration pattern under package B | **Positive Registration**: Exact identical UUID registered in a distinct application namespace. |
| `negative_candidate_apk` | `org.example.candidate_only` | DEX string pool contains `0000180d-0000-1000-8000-00805f9b34fb`; zero Bluetooth methods | **Negative Registration (Candidate Only)**: String constant present in string pool, but never passed to service constructor or server. |
| `client_only_ble_apk` | `org.example.client_only` | Invokes `BluetoothGatt.discoverServices()Z`; contains UUID `0000180d-...`; no `BluetoothGattServer` | **Negative Registration (Client Role)**: BLE Client operations only; zero GATT server registration call sites. |
| `ble_perm_no_service_api_apk` | `org.example.ble_perm_no_services` | Manifest has 4 Bluetooth permissions; DEX contains string `0000180a-...`; no Bluetooth APIs | **Negative Registration (Perms Only)**: Demonstrates that permission presence is not evidence of GATT service registration. |
| `unresolved_registration_apk` | `org.example.unresolved_reg` | Invokes `BluetoothGattServer.addService(v1)`; register `v1` is an incoming method argument | **Unresolved Registration (Cross-Method)**: Verified call site exists, but service object originates across method boundary. |
| `service_constructed_no_add_apk` | `org.example.service_no_add` | Invokes `BluetoothGattService.<init>` with literal `0x180D`; `addService` is never called | **Unresolved Registration (Unregistered Service)**: Service object instantiated locally, but never passed to `addService`. |

---

## 4. Manual Disassembly Comparison & Evidence Concordance

Disassembly was manually extracted and verified against UCSD's structured findings using [`tests/inspect_disassembly.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/inspect_disassembly.py). Full inspection artifacts are recorded in [`reports/disassembly_inspection.md`](file:///c:/Users/jhata/WEB-Projects/UCSD/reports/disassembly_inspection.md).

### 4.1 Positive Registration Concordance Check

- **Method**: `Lorg/example/positive/GattService;->registerService()V`
- **Candidate UUID**: `0000180d-0000-1000-8000-00805f9b34fb` (Heart Rate)

```text
[Bytecode Disassembly]
+0x0000  const-string v0, "0000180d-0000-1000-8000-00805f9b34fb"
+0x0004  invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;
+0x000a  move-result-object v1
+0x000c  const/4 v2, 0
+0x000e  new-instance v3, Landroid/bluetooth/BluetoothGattService;
+0x0012  invoke-direct {v3, v1, v2}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V
+0x0018  invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z
+0x001e  return-void
```

**UCSD Evidence Trace**:
1. Step 0: `load_uuid_string` at `+0x0000` (register `v0`) $\longrightarrow$ **Exact Match**
2. Step 1: `uuid_from_string` at `+0x0004` (input `v0`, result `v1`) $\longrightarrow$ **Exact Match**
3. Step 2: `service_constructor` at `+0x0012` (service `v3`, uuid `v1`) $\longrightarrow$ **Exact Match**
4. Step 3: `add_service_registration` at `+0x0018` (server `v4`, service `v3`) $\longrightarrow$ **Exact Match**

### 4.2 Real-APK Independent Bytecode Audit (`samples/validation.apk`)

- **Target**: `samples/validation.apk` (F-Droid v2.0.1, SHA-256 `83d3fe522281c3cb89fce3bc05038f81b3c3b32c108536941f184c5f9bb53778`, 12,537,183 bytes, 3 DEX files).
- **Independent Bytecode Inspection (`tests/audit_real_apk.py`)**:
  - Total method references scanned across all 3 DEX files: **139,863**.
  - Bluetooth framework references: **88** Classic RFCOMM socket methods (`BluetoothAdapter`, `BluetoothServerSocket`, `BluetoothSocket`).
  - References to `android.bluetooth.BluetoothGattServer.addService`: **strictly 0**.
  - References to `android.bluetooth.BluetoothGattService.<init>`: **strictly 0**.
  - Substring search caveat: Substring match for `"addservice"` yields non-GATT third-party methods (`Lcoil3/RealImageLoaderKt;->addServiceLoaderComponents` and `Ljavax/jmdns/JmDNS;->addServiceListener`); verified that zero match Bluetooth GATT server APIs.
  - Candidate UUIDs extracted from string pools: **88** unique canonical 128-bit strings (e.g. `UPCEReader::convertUPCEtoUPCA` and `FieldParser::<clinit>`).
- **UCSD Pipeline Concordance**:
  - All 88 candidate UUIDs are classified strictly as `UUID_CANDIDATE_ONLY` (`NO_REGISTRATION_CALL_SITE`).
  - Zero false-positive GATT service constructions or registrations detected.
  - Zero `STRONG_STATIC_ASSOCIATION` findings emitted $\longrightarrow$ **Exact Concordance**.


---

## 5. Distinction: Unit-Test vs. End-to-End Validation

UCSD enforces a strict conceptual and reporting distinction between validation tiers:

| Attribute | Unit-Test Validation | End-to-End Synthetic APK Validation | Real-World Production APK Evaluation |
| :--- | :--- | :--- | :--- |
| **Execution Scope** | Mock bytecode instructions, isolated parser functions, regex normalization. | Full APK intake $\rightarrow$ manifest $\rightarrow$ DEX $\rightarrow$ Dalvik tracer $\rightarrow$ KB lookup $\rightarrow$ JSON/HTML reports. | Real compiled Android APKs with multiple DEX files, resource tables, and third-party libraries. |
| **Target Artifacts** | Python memory objects (`MockDalvikInstruction`). | Deterministic synthetic APK archives (`conflict_apk_a.apk`). | `samples/validation.apk` (F-Droid v2.0.1). |
| **What It Proves** | Correctness of register state machine and normalization regex. | End-to-end integration and error resilience of the full CLI toolchain. | Practical resilience to real multi-DEX layouts and external framework signatures. |
| **What It CANNOT Prove** | Cannot prove APK file handling or CLI behavior. | Cannot prove detection of complex production obfuscation. | Cannot prove absence of runtime vulnerabilities or runtime behavior. |

---

## 6. Analytical Limitations & Technical Risks

### 6.1 Unsupported Patterns (False-Negative Risks)

1. **Inter-Procedural Data Flow**:
   When a `BluetoothGattService` is instantiated in a factory method (`ServiceFactory.create()`) and registered in a separate lifecycle callback (`onStartCommand()`), UCSD flags the call site as `REGISTRATION_PATTERN_UUID_UNRESOLVED` (`CROSS_METHOD_SERVICE_OBJECT`). The UUID is not linked.
2. **Field-Based Storage**:
   When a service object or UUID is saved to a class field (`this.mGattService = ...`) and accessed later, intra-method tracing safely aborts to `FIELD_BASED_SERVICE_OBJECT`.
3. **Dynamic / Reflected Identifiers**:
   UUIDs loaded from Android resources (`R.string.uuid`), SharedPreferences, JSON configs, network endpoints, or reflection (`Class.forName()`) cannot be resolved statically.
4. **Non-Standard Vendor Frameworks**:
   Proprietary BLE SDKs or native C++ libraries (JNI) that register GATT services without calling `android.bluetooth.BluetoothGattServer` directly are invisible to Dalvik analysis.

### 6.2 False-Positive Risks

1. **Dead Code / Unused Methods**:
   A method containing a valid static registration sequence that is never invoked at runtime will still be classified as `STRONG_STATIC_ASSOCIATION`.
2. **Short Hex / Base UUID Ambiguity**:
   16-bit hex values matching the Bluetooth Base UUID format in DEX string pools may represent unrelated integer constants (e.g. zip file flags, barcode offsets) rather than genuine BLE service identifiers.
3. **Common Sample Code Overlaps**:
   Two independent open-source projects using identical standard sample UUIDs (e.g. Bluetooth SIG Heart Rate `0x180D`) will produce `STRONG_DUPLICATE_STATIC_REGISTRATION` without indicating malicious service squatting.

---

## 7. Validation Summary & Unresolved Technical Risks

### What Is Validated:
- **Intake Pipeline**: Deterministic handling of valid, multidex, empty, missing, and corrupted APKs.
- **Evidence Hierarchy**: Strict categorical evidence levels (`STRONG_STATIC_ASSOCIATION`, `REGISTRATION_PATTERN_UUID_UNRESOLVED`, `UUID_CANDIDATE_ONLY`). Zero heuristic probabilities.
- **Explainability**: Every strong registration finding includes exact Dalvik opcodes, offsets, and registers.
- **Reporting & Safety**: Zero-dependency offline HTML reports with universal XSS escaping (`html.escape(..., quote=True)`).
- **Immutability**: Read-only preservation of target APKs inside `/app/samples:ro`.

### Unresolved Technical Risks:
1. **Dynamic Runtime Behavior**: Static analysis cannot observe runtime registration timing, permissions granted by the user, or peripheral connection states.
2. **Obfuscation Robustness**: Control-flow flattening, string encryption, and reflection intentionally sever intra-method static tracing.
3. **Host Security Context**: Proving service squatting requires active execution on an Android device to determine which service instance the OS binds to first.
