# UCSD Demonstration Guide: Evaluation & Verification

This directory contains approved sample inputs, expected outputs, and automation scripts to demonstrate and evaluate the **Universal Candidate Service Detector (UCSD)**.

---

## 1. Quick Start

Ensure Docker Desktop is running on Windows (or Linux/macOS), then run the automated demo script from the repository root:

### Windows PowerShell
```powershell
.\demo\run_demo.ps1
```

### Linux / macOS / Bash
```bash
bash demo/run_demo.sh
```

All generated HTML and JSON reports will be written to the host-mounted `./reports/` directory.

---

## 2. Approved Demo Inputs

The `demo/inputs/` directory provides three deterministic, binary-valid Android APK packages created with known ground truth:

| Sample APK | Package Name | DEX Characteristics | Ground Truth Description |
| :--- | :--- | :--- | :--- |
| [`demo/inputs/service_a.apk`](file:///c:/Users/jhata/WEB-Projects/UCSD/demo/inputs/service_a.apk) | `org.example.service_a` | Dalvik opcodes: `const-string`, `UUID.fromString`, `new-instance BluetoothGattService`, `<init>`, `addService` | **Positive Registration**: Literal UUID `0000180d-0000-1000-8000-00805f9b34fb` (Heart Rate) constructed and registered locally in `registerService()V`. |
| [`demo/inputs/service_b.apk`](file:///c:/Users/jhata/WEB-Projects/UCSD/demo/inputs/service_b.apk) | `org.example.service_b` | Identical intra-method registration pattern under a distinct application package | **Positive Registration**: Identical Heart Rate UUID registered in a distinct application namespace. |
| [`demo/inputs/client_only.apk`](file:///c:/Users/jhata/WEB-Projects/UCSD/demo/inputs/client_only.apk) | `org.example.client_only` | Invokes `BluetoothGatt.discoverServices()Z`; references Heart Rate UUID; zero GATT Server APIs | **Negative Registration (Client Role)**: BLE Client operations only; candidate UUID present without server registration call sites. |

Additionally, [`samples/validation.apk`](file:///c:/Users/jhata/WEB-Projects/UCSD/samples/validation.apk) (F-Droid v2.0.1, 12.5 MB, Multi-DEX) is available in the root `samples/` directory for evaluating real-world APK behavior.

---

## 3. Step-by-Step Demonstration Commands

Reviewers can run each command individually via Docker Compose:

### Step 1: Single APK Analysis — Positive Registration
Analyze an APK that registers a GATT service via verified intra-method register data-flow:
```bash
docker compose run --rm ucsd python -m ucsd.cli analyze /app/demo/inputs/service_a.apk --out /app/reports
```

**Key Evidence to Inspect**:
- **Console Output**: Reports `1 Strong Static Association` for UUID `0000180d-0000-1000-8000-00805f9b34fb`.
- **Knowledge Base**: Identifies the UUID as Bluetooth SIG standard `"Heart Rate Service"`.
- **Generated HTML**: Open `reports/service_a_<sha>_report.html` in a web browser. Inspect the **GATT Service Registration Analysis** card showing:
  - Evidence level badge: `STRONG STATIC`
  - Exact Dalvik register trace: `load_uuid_string` $\rightarrow$ `uuid_from_string` $\rightarrow$ `service_constructor` $\rightarrow$ `add_service_registration` with instruction offsets.

---

### Step 2: Single APK Analysis — Client-Only BLE Application
Analyze an APK that uses Bluetooth GATT Client APIs without registering GATT services:
```bash
docker compose run --rm ucsd python -m ucsd.cli analyze /app/demo/inputs/client_only.apk --out /app/reports
```

**Key Evidence to Inspect**:
- **API Indicators**: `GATT Client: True`, `GATT Server: False`.
- **Evidence Level**: The candidate UUID is classified as `UUID_CANDIDATE_ONLY`.
- **Registration Call Sites**: Exactly `0 addService` call sites detected. Zero false-positive service registrations.

---

### Step 3: Cross-APK Static Duplicate Registration Conflict
Compare two distinct applications (`service_a` and `service_b`) that associate the same GATT service UUID with `BluetoothGattServer.addService()`:
```bash
docker compose run --rm ucsd python -m ucsd.cli compare /app/demo/inputs/service_a.apk /app/demo/inputs/service_b.apk --out /app/reports/demo_conflict_report.json
```

**Key Evidence to Inspect**:
- **Condition**: Evaluated as `STRONG_DUPLICATE_STATIC_REGISTRATION`.
- **Explainability**: Identifies both distinct participating packages (`org.example.service_a` and `org.example.service_b`), declaring classes, method names, and bytecode offsets.
- **Conservative Phrasing**:
  > *"Two distinct APKs contain strong static evidence associating the same UUID with GATT service registration. This is a high-confidence static overlap and may warrant runtime/host-context validation."*
- **Report**: Open `reports/demo_conflict_report.html` to review the visual side-by-side evidence breakdown.

---

### Step 4: Multi-APK Batch Analysis
Run an automated intake and cross-comparison across all APKs in a directory:
```bash
docker compose run --rm ucsd python -m ucsd.cli batch /app/demo/inputs --out /app/reports/demo_batch
```

**Key Evidence to Inspect**:
- Analyzes all 3 demo APKs in a single pass.
- Emits aggregated batch report `reports/demo_batch/batch_report.html` and `batch_report.json`.
- Accurately reports:
  - 1 strong duplicate static registration between `service_a` and `service_b`.
  - Client-only APK included in candidate inventory without triggering false registration conflicts.

---

### Step 5: Real-World Multi-DEX APK Evaluation
Analyze the 12.5 MB production APK [`samples/validation.apk`](file:///c:/Users/jhata/WEB-Projects/UCSD/samples/validation.apk) (F-Droid v2.0.1, 3 DEX files):
```bash
docker compose run --rm ucsd python -m ucsd.cli analyze /app/samples/validation.apk --out /app/reports
```

**Key Evidence to Inspect**:
- **DEX Inventory**: Correctly parses 3 distinct DEX files (`classes.dex`, `classes2.dex`, `classes3.dex`).
- **UUID Candidates**: Extracts 88 unique canonical UUID strings from string pools.
- **Bytecode Verification**: Scans 139,863 method references. Confirms 88 Classic Bluetooth socket methods, but **0 references** to `BluetoothGattServer.addService`.
- **Evidence Level**: All 88 candidate UUIDs are classified strictly as `UUID_CANDIDATE_ONLY`. Zero false-positive registrations.

---

## 4. Expected Outputs Reference

Pre-generated reference outputs are stored in [`demo/expected_outputs/`](file:///c:/Users/jhata/WEB-Projects/UCSD/demo/expected_outputs/) for reviewer comparison:

| Expected Output File | Description |
| :--- | :--- |
| `service_a_report.json` | Expected single-APK JSON schema for positive GATT registration. |
| `client_only_report.json` | Expected single-APK JSON schema for client-only BLE application. |
| `conflict_report.json` | Expected cross-APK comparison report for `service_a` vs `service_b`. |
| `batch_report.json` | Expected batch report schema across all demo targets. |

---

## 5. Methodological & Ethical Boundaries

Reviewers should note the following scientific boundaries enforced by UCSD:

1. **Static Overlap vs. Runtime Exploit**:
   A `STRONG_DUPLICATE_STATIC_REGISTRATION` indicates high-confidence static Dalvik evidence that two apps register the same service UUID. It does **not** prove runtime service squatting or host collision, which depends on OS registration order, execution state, and runtime permissions.
2. **Standard Protocol Identifiers**:
   Matching a Bluetooth SIG assigned UUID (e.g. Heart Rate `0x180D`) is normal standards-compliant behavior. UCSD explicitly notes that assigned standard matches do **not** imply malicious intent.
3. **No Fabricated Probabilities**:
   UCSD findings are strictly categorical (`STRONG_STATIC_ASSOCIATION`, `REGISTRATION_PATTERN_UUID_UNRESOLVED`, `UUID_CANDIDATE_ONLY`). The pipeline never outputs speculative percentage confidence scores.
