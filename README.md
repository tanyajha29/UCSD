# UCSD: Universal Candidate Service Detector

**Static BLE Indicator Detection, UUID Candidate Extraction & GATT Service Registration Conflict Assessment**

UCSD is a containerized, evidence-grounded static analysis tool for Android APK binaries. It identifies Bluetooth Low Energy (BLE) indicators, extracts candidate service UUIDs, analyzes Dalvik bytecode data-flow for local GATT service registrations (`BluetoothGattServer.addService`), and assesses potential static service registration overlap across multiple applications.

> [!IMPORTANT]
> **Research Prototype Scope & Ethical Caveat**:
> UCSD is a **static analysis analyzer**, not a dynamic exploit generator or malware classifier. A detected static registration overlap (`STRONG_DUPLICATE_STATIC_REGISTRATION`) establishes that two distinct applications contain strong static evidence associating the same service UUID with GATT service construction and registration. It does **not** prove runtime exploitability, confirmed host collision, or malicious intent.

---

## 1. Problem Statement

On Android, Bluetooth Low Energy (BLE) peripheral and server functionality is implemented through the Generic Attribute Profile (GATT). Applications publish services identified by 128-bit Universally Unique Identifiers (UUIDs) via `BluetoothGattServer.addService()`. 

When multiple applications installed on the same host or operating in the same BLE environment register services with identical or colliding UUIDs (whether by collision, squatting, or reliance on common standard identifiers), ambiguous client-server routing and unexpected service shadow behavior can occur. 

Traditional static analysis tools either inspect only Manifest permissions or treat arbitrary string constants as proven service registrations. UCSD addresses this by implementing **conservative, intra-method Dalvik bytecode data-flow tracing** that connects UUID string literals to `BluetoothGattService` constructors and `BluetoothGattServer.addService()` call sites, accompanied by full instruction traces.

---

## 2. Project Scope & Non-Goals

### Within Scope (Project Capabilities)
- **Containerized APK Intake**: Streaming SHA-256 computation, ZIP header and CRC-32 integrity validation, multi-DEX enumeration, and Android binary XML (AXML) decoding.
- **BLE Indicators & Permissions**: Categorization of modern BLE permissions (`BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`, `BLUETOOTH_ADVERTISE`) versus legacy Classic Bluetooth permissions, and detection of BLE framework classes.
- **UUID Candidate Extraction & Normalization**: Canonical 128-bit and 16-bit UUID extraction from string pools and bytecode instructions, with deterministic RFC 4122 normalization and Bluetooth Base UUID expansion.
- **Intra-Method Bytecode Tracing**: Conservative Dalvik register data-flow tracking from UUID literal strings $\rightarrow$ `UUID.fromString()` / `ParcelUuid` $\rightarrow$ `BluetoothGattService.<init>()` $\rightarrow$ `BluetoothGattServer.addService()`.
- **Categorical Evidence Classification**: Strict classification into `STRONG_STATIC_ASSOCIATION`, `REGISTRATION_PATTERN_UUID_UNRESOLVED`, and `UUID_CANDIDATE_ONLY`. Zero heuristic scores or calibrated probabilities.
- **Curated Knowledge Base Lookup**: Exact-match lookup against a versioned, read-only dataset of verified Bluetooth SIG standards and sourced vendor specifications with documented provenance.
- **Cross-APK Conflict Evaluation**: Detection of high-confidence static registration overlap across distinct applications, clearly separated from benign duplicate candidate strings.
- **Analyst-Facing Reporting**: Generation of machine-readable JSON and standalone, offline HTML dashboards with universal XSS escaping.

### Explicit Non-Goals (What UCSD Does NOT Claim)
- **Not a Dynamic Exploit Detector**: UCSD does not execute APKs, monitor live Bluetooth traffic, or determine runtime OS registration race conditions.
- **Not a Malware Classifier**: UCSD does not assign malicious intent or compute risk percentages. Matching a standard or vendor UUID is often legitimate interoperability.
- **Not a Whole-Program Inter-Procedural Taint Engine**: UCSD does not perform whole-program inter-procedural data-flow or global points-to analysis. Cross-method, field-stored, and reflected service objects are explicitly reported as unresolved.
- **Not a Deobfuscator**: UCSD does not defeat advanced bytecode protection such as control-flow flattening, opaque predicates, or dynamic string decryption.

---

## 3. System Architecture & Module Responsibilities

```
                               +-----------------------------+
                               |     Input APK Binary        |
                               +--------------+--------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
       [UCSD Primary Engine]                              [Independent Validator]
       ucsd.apk_loader (Androguard)                        ucsd.validation (aapt + zipfile)
       - Streaming SHA-256                                - Streaming SHA-256
       - ZIP CRC-32 integrity check                       - ZIP CRC-32 testzip()
       - Manifest & multi-DEX collection                  - classes*.dex enumeration
                     |                                    - aapt dump badging & permissions
                     v                                                 |
       [Phase 2: ucsd.ble]                                             v
       - Permissions & API indicators                    IndependentAPKMetadata
       - Canonical & 16-bit UUID extraction                            |
                     |                                                 |
                     v                                                 |
       [Phase 3: ucsd.registration]                                    |
       - Intra-method Dalvik register tracer                           |
       - Constructor & addService call sites                           |
       - Categorical evidence levels                                   |
                     |                                                 |
                     v                                                 |
       [Phase 4: ucsd.knowledge & ucsd.conflict]                       |
       - Read-only versioned JSON KB                                   |
       - Exact-match lookup & provenance                               |
       - Cross-APK conflict assessment                                 |
                     |                                                 |
                     v                                                 |
       [Phase 5: ucsd.orchestrator & ucsd.reporting]                   |
       - Deterministic single & batch workflows                        |
       - JSON & offline standalone HTML reports                        |
                     \                                                 /
                      \                                               /
                       v                                             v
                      +-----------------------------------------------+
                      |           ucsd.validation.comparator          |
                      |   - Field-by-Field MATCH / MISMATCH checks    |
                      |   - Independent intake verification           |
                      +-----------------------------------------------+
```

### Module Directory Breakdown

| Directory / Module | Responsibility |
| :--- | :--- |
| `ucsd/apk_loader.py` | Primary intake pipeline: 64KB chunk SHA-256, ZIP CRC integrity, multi-DEX detection, manifest extraction, and orchestrator dispatch. |
| `ucsd/manifest.py` | Decodes Android package name, version codes, SDK targets, and requested/declared permissions without speculative assumptions. |
| `ucsd/ble/` | BLE permission extraction, framework class detection, canonical and 16-bit UUID candidate extraction, and Bluetooth Base UUID expansion. |
| `ucsd/registration/` | Intra-method Dalvik register data-flow tracer; identifies `BluetoothGattService` construction and `addService` call sites; produces step-by-step traces. |
| `ucsd/knowledge/` | Versioned UUID knowledge base repository (`/app/data/uuid_knowledge_base.json`), enforcing mandatory source provenance and exact-match lookups. |
| `ucsd/conflict/` | Cross-APK comparison engine evaluating static registration overlaps, duplicate candidate strings, and standard specifications. |
| `ucsd/orchestrator.py`| Central pipeline orchestrator managing single-APK and multi-APK batch workflows with partial-failure isolation. |
| `ucsd/reporting/` | Generates self-contained, offline HTML dashboards with strict XSS escaping and machine-readable JSON reports. |
| `ucsd/cli.py` | Unified CLI entrypoint supporting `analyze`, `batch`, `compare`, and `validate` commands. |
| `ucsd/validation/` | Independent verification package using standard library `zipfile` and AOSP `aapt`, completely decoupled from Androguard. |
| `ucsd/server/` | Production FastAPI application, background job executor, validation storage, and SQLite WAL persistence. |
| `frontend/` | React 18 + TypeScript + Vite + Tailwind CSS dark-slate cybersecurity investigation workstation. |

---

## 4. Full-Stack Web Application Interface

UCSD includes an analyst-grade, full-stack cybersecurity web workstation built with **React 18, TypeScript, Vite, Tailwind CSS, FastAPI, and SQLite**. The interface connects directly to the static Dalvik analysis engine without simulated data or client-side shortcuts.

```
+-----------------------------------------------------------------------------------------+
|                                     UCSD Web Console                                    |
|   [Dashboard]  [Upload & Analyze]  [Comparison Matrix]  [History]  [Reports]  [KB]      |
+-----------------------------------------------------------------------------------------+
|  Real-Time 5-Stage Pipeline  |  Intra-Method Dalvik Trace  | Cross-APK Collision Engine  |
|  - Intake & SHA-256          |  - const-string register    | - Exact UUID Collision      |
|  - Multi-DEX & Manifest      |  - UUID.fromString call     | - Static Dual Registration  |
|  - BLE UUID Extraction       |  - BluetoothGattService.<init> | - Vendor/Standard Match  |
|  - Dalvik Flow Tracing       |  - addService() Call Site   | - Unresolved Overlap        |
|  - Knowledge Base Lookup     |  - Instruction Offsets      | - Standalone HTML & JSON    |
+-----------------------------------------------------------------------------------------+
                                          | HTTP REST APIs (/api/*)
                                          v
+-----------------------------------------------------------------------------------------+
|                           FastAPI Backend & Background Workers                          |
|  - Staging & Validation (/app/workspace/uploads): 100MB limit, ZIP CRC check, DEX audit|
|  - Concurrent Job Thread Pool Executor (analyze_single_apk, compare_apks)               |
|  - Persistent SQLite WAL Database (/app/data/db/ucsd.db, survives container restarts)   |
|  - Pure Static Analyzer: Preserves conservative Dalvik bytecode facts & provenance      |
+-----------------------------------------------------------------------------------------+
```

### Key Interface Capabilities

1. **Investigation Dashboard**:
   - Live metrics calculated directly from persistent SQLite records: total analyzed APKs, candidate-only detections, verified strong static registrations, unresolved patterns, and cross-APK conflicts.
   - Recent jobs table with instant status badges (`running`, `completed`, `failed`).
   - Quick-action shortcuts and onboarding walkthrough.

2. **Drag & Drop Upload & Live Pipeline Visualization**:
   - Drag-and-drop or file-picker upload with automatic ZIP/DEX validation and 100MB staging guardrail.
   - Real-time 5-stage pipeline animation:
     1. `Intake & Validation` (SHA-256 calculation, ZIP CRC-32 integrity)
     2. `Manifest & DEX Inspection` (Permissions, target SDK, exported components)
     3. `BLE Indicator & UUID Extraction` (String pools, opcodes, 16-bit expansion)
     4. `Dalvik Registration Tracing` (Data-flow analysis to `addService`)
     5. `Report Generation & KB Lookup` (Bluetooth SIG correlation, JSON & HTML persistence)

3. **In-Depth Static Findings & Dalvik Trace Timeline**:
   - Categorical evidence badges (`STRONG_STATIC_ASSOCIATION`, `REGISTRATION_PATTERN_UUID_UNRESOLVED`, `UUID_CANDIDATE_ONLY`).
   - Expandable Dalvik bytecode trace timeline rendering step-by-step instruction offsets, Dalvik opcodes, registers, and target methods.
   - Bluetooth SIG and vendor assigned service lookup with direct links to official specifications.
   - One-click downloads for standalone offline HTML dashboards and structured JSON reports.

4. **Cross-APK Static Collision Matrix**:
   - Multi-select any two or more historical analyses to evaluate static service overlaps.
   - Categorizes findings into `STRONG_DUPLICATE_STATIC_REGISTRATION`, `UNRESOLVED_REGISTRATION_OVERLAP`, `DUPLICATE_CANDIDATE_NO_REGISTRATION`, and `KNOWN_ASSIGNED_STANDARD_MATCH`.
   - Side-by-side participating APK comparison cards.

5. **Persistent History & Search**:
   - Paginated, searchable analysis repository filtered by status, filename, package name, or SHA-256.
   - One-click report downloads and secure job purging.

6. **Curated Knowledge Base Browser**:
   - Searchable directory of all 24 curated Bluetooth SIG and vendor UUID records with documented provenance, source URLs, and analyst notes.

---

## 5. REST API Specification

The FastAPI backend exposes fully typed REST endpoints under `/api`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health, SQLite database connectivity, and workspace status |
| `GET` | `/api/dashboard` | Aggregate counts, evidence distribution, and recent analyses |
| `POST` | `/api/analyses` | Upload an APK (`multipart/form-data`) and initiate background analysis |
| `GET` | `/api/analyses` | Paginated analysis history (`page`, `page_size`, `status`, `query`) |
| `GET` | `/api/analyses/{id}` | Status, metadata, and summary findings for an analysis job |
| `GET` | `/api/analyses/{id}/results` | Full structured `AnalysisReport` JSON payload |
| `GET` | `/api/analyses/{id}/reports/json` | Download machine-readable JSON report file |
| `GET` | `/api/analyses/{id}/reports/html` | Download or view self-contained offline HTML report |
| `DELETE` | `/api/analyses/{id}` | Purge an analysis record and associated workspace artifacts |
| `POST` | `/api/comparisons` | Initiate cross-APK conflict evaluation across 2+ analysis IDs |
| `GET` | `/api/comparisons` | List historical cross-APK comparison records |
| `GET` | `/api/comparisons/{id}` | Detailed cross-APK conflict report payload |
| `GET` | `/api/knowledge-base` | Complete curated dataset of Bluetooth SIG and vendor UUIDs |

Interactive OpenAPI documentation is automatically available at **`http://localhost:8000/docs`** and Redoc at **`http://localhost:8000/redoc`**.

---

## 6. Docker Installation & Quickstart

The entire application runs in a unified, isolated Docker container exposing the web interface and API on port **8000**.

### Single-Command Startup
From the repository root:
```bash
docker compose up -d
```

Open your browser to:
```
http://localhost:8000
```

To stop the services:
```bash
docker compose down
```

### Build or Rebuild the Application
To build the frontend and backend container from scratch:
```bash
# Optional: rebuild frontend bundle on host if modifying UI code
cd frontend && npm run build && cd ..

# Build and start container
docker compose up -d --build
```

### Running Automated Tests in Docker
Execute the full 138-test automated test suite (including 10 server integration tests) inside Docker:
```bash
docker exec ucsd-ucsd-1 pytest -v
```

---

## 7. Host & Container Mount Points

UCSD enforces a secure, containerized boundary configured in [`compose.yaml`](file:///c:/Users/jhata/WEB-Projects/UCSD/compose.yaml):

| Host Path | Container Path | Mount Mode | Description |
| :--- | :--- | :--- | :--- |
| `./ucsd` | `/app/ucsd` | `rw` | Source code (hot reloading during development) |
| `./tests` | `/app/tests` | `rw` | Test suite and programmatic fixture generators |
| `./samples` | `/app/samples` | `ro` | Input APK binaries (**read-only** preservation) |
| `./demo` | `/app/demo` | `ro` | Approved demo inputs and scripts (**read-only**) |
| `./data` | `/app/data` | `rw` | Versioned UUID knowledge base JSON and persistent SQLite database |
| `./reports` | `/app/reports` | `rw` | Output directory for generated JSON and HTML reports |
| `./workspace` | `/app/workspace` | `rw` | Staging workspace for uploaded binaries |
| `./frontend/dist` | `/app/frontend/dist` | `ro` | Compiled React frontend production bundle |

> [!NOTE]
> - All sample input directories (`./samples` and `./demo`) are mounted **read-only (`:ro`)**. Target binaries cannot be altered by the container.
> - Container execution runs with `privileged: false` and `security_opt: ["no-new-privileges:true"]`. The Docker daemon socket is never mounted.

## 8. Digital Forensics Workbench & Web Interface

In addition to the CLI, UCSD features an interactive, evidence-centric **Digital Forensics Workbench** ("Evidence Lab") served directly from the containerized FastAPI server at `http://localhost:8000`.

### Starting the Workstation
```bash
# 1. Start the backend server and web workstation in Docker Compose
docker compose up -d

# 2. Access the Forensic Workbench in your browser
open http://localhost:8000
```

### Forensic Workspace Architecture

- **Persistent Left Navigation Rail**:
  - `[1] Evidence Desk`: Central triage dashboard displaying persistent SQLite case dossiers, actionable leads queue, and engine telemetry.
  - `[2] APK Intake`: Secure intake workstation with client-side WebCrypto SHA-256 pre-calculation, 100 MB guardrails, and instant duplicate detection.
  - `[3] Dalvik Workbench`: 3-pane reverse-engineering IDE:
    - *Pane 1 (Navigator)*: Multi-DEX inventory, GATT server/client flags, UUIDs, and finding leads.
    - *Pane 2 (Disassembly)*: Monospace Dalvik instruction viewer with hex offsets (`+0x0000`), opcodes, operand registers (`v0`, `v1`), method targets, and line linking.
    - *Pane 3 (Inspector)*: Ground-truth observed facts vs analytical interpretation, and Bluetooth SIG standard provenance.
  - `[4] Relationship Explorer`: Interactive SVG Node-Link graph connecting APK $\rightarrow$ Package $\rightarrow$ Method $\rightarrow$ Registration $\rightarrow$ UUID $\rightarrow$ Bluetooth SIG Standard with interactive pan, zoom, edge tracing, and filters.
  - `[5] Cross-APK Conflicts`: Side-by-side static collision matrix evaluating duplicate service registrations.
  - `[6] Forensic Ledger`: Searchable, filterable audit history backed by SQLite WAL persistence.
  - `[7] Reports & Exports`: Deterministic JSON downloads and standalone offline HTML report previews.
  - `[8] Engine & KB`: 24 curated Bluetooth SIG records with instant search and copy.

- **Top Contextual Investigation Bar**:
  - Global case switcher dropdown to change the active investigation context across all tools.
  - Quick SHA-256 copy and status badge (`STRONG`, `UNRESOLVED`, `CANDIDATE`).
  - Command Palette trigger (`⌘K` / `Ctrl+K`).
  - Real-time engine status pill (`ENGINE ONLINE • SQLite WAL • KB v1.0.0`).

- **Bottom Status Strip**:
  - Displays persistent database path, engine version, active target binary, and keyboard shortcuts.

---

## 9. Usage & CLI Command Reference

### Command 1: Single APK Analysis (`analyze`)
Runs the complete analysis pipeline (intake $\rightarrow$ BLE indicators $\rightarrow$ registration tracing $\rightarrow$ KB lookup $\rightarrow$ reports):

```bash
docker compose run --rm ucsd python -m ucsd.cli analyze /app/demo/inputs/service_a.apk --out /app/reports
```

**Optional Flags**:
- `--out <dir_or_file>`: Target output directory or JSON file path (default: `/app/reports`).
- `--no-html`: Suppress generation of the standalone HTML report.
- `--skip-ble`: Skip BLE indicator and UUID candidate extraction.
- `--skip-registration`: Skip Phase 3 GATT service registration analysis.
- `--skip-kb`: Skip Phase 4 UUID knowledge base matching.
- `--quiet` / `-q`: Suppress terminal stdout output.

---

### Command 2: Multi-APK Batch Analysis (`batch`)
Analyzes all APKs in a target directory, isolates corrupted targets, and performs automated cross-APK conflict evaluation:

```bash
docker compose run --rm ucsd python -m ucsd.cli batch /app/demo/inputs --out /app/reports/demo_batch
```

**Generated Outputs**:
- `/app/reports/demo_batch/batch_report.json`
- `/app/reports/demo_batch/batch_report.html`
- Individual per-APK JSON and HTML reports for each processed binary.

---

### Command 3: Cross-APK Conflict Comparison (`compare`)
Directly compares two or more analyzed reports or APK binaries to assess static registration conflicts:

```bash
docker compose run --rm ucsd python -m ucsd.cli compare /app/demo/inputs/service_a.apk /app/demo/inputs/service_b.apk --out /app/reports/demo_conflict_report.json
```

---

### Command 4: Independent APK Validation (`validate`)
Verifies intake extraction independently using AOSP `aapt` and standard library `zipfile`, producing a side-by-side concordance diff:

```bash
docker compose run --rm ucsd python -m ucsd.cli validate /app/samples/validation.apk --out /app/reports
```

---

## 10. Report Schema & Categorical Evidence Levels

### 10.1 Single-APK Registration Evidence Levels (Phase 3)

| Evidence Level | Strict Evidence Criteria |
| :--- | :--- |
| **`STRONG_STATIC_ASSOCIATION`** | Verified, unbroken intra-method Dalvik register data-flow connecting a static UUID string literal $\rightarrow$ `UUID.fromString` / `ParcelUuid` $\rightarrow$ `BluetoothGattService.<init>` $\rightarrow$ `BluetoothGattServer.addService()`. Includes instruction offsets and operand registers. |
| **`REGISTRATION_PATTERN_UUID_UNRESOLVED`** | Call sites for `BluetoothGattServer.addService()` or `BluetoothGattService.<init>` exist, but intra-method tracing cannot resolve the UUID literal (e.g., cross-method parameter, instance field, dynamic expression, or clobbered register). |
| **`UUID_CANDIDATE_ONLY`** | Candidate UUID string detected in DEX string pool or bytecode instruction, but has no verifiable connection to a local GATT service registration call site. |

### 10.2 Cross-APK Conflict Assessment Conditions (Phase 4)

| Conflict Condition | Classification Semantics | Is Proven? |
| :--- | :--- | :--- |
| **`STRONG_DUPLICATE_STATIC_REGISTRATION`** | Two or more distinct application packages each contain verified `STRONG_STATIC_ASSOCIATION` evidence associating the identical service UUID with `addService()`. Represents a high-confidence static overlap. | `true` (strictly per static criteria) |
| **`UNRESOLVED_REGISTRATION_OVERLAP`** | Multiple applications attempt service registrations associated with the same UUID, but one or more patterns remain unresolved across method or field boundaries. | `false` |
| **`DUPLICATE_CANDIDATE_NO_REGISTRATION`** | Identical UUID candidate strings discovered across multiple APKs without verified dual static GATT registration (e.g. shared utility libraries, constant tables). | `false` |
| **`KNOWN_ASSIGNED_STANDARD_MATCH`** | UUID matches an official Bluetooth SIG assigned service (e.g. Heart Rate `0x180D`). Standard protocol identifier; not indicative of conflict or malicious intent. | `false` |
| **`KNOWN_SYSTEM_OR_VENDOR_MATCH`** | UUID matches an OS-level (e.g. Google Fast Pair) or hardware vendor specification supported by documented provenance in the knowledge base. | `false` |
| **`UNKNOWN_UNCONFLICTED`** | UUID is absent from the curated knowledge base and confined to a single application. | `false` |

---

## 11. UUID Knowledge Base: Provenance & Maintenance

The knowledge base is maintained as a version-controlled, read-only JSON document located at [`data/uuid_knowledge_base.json`](file:///c:/Users/jhata/WEB-Projects/UCSD/data/uuid_knowledge_base.json) and mounted into the container at `/app/data/uuid_knowledge_base.json:ro`.

### Provenance Requirements
Every entry must include complete, verifiable documentation:
- `uuid`: 128-bit lowercase canonical UUID string.
- `name`: Human-readable identifier or service name.
- `source_type`: One of `STANDARDS_ORGANIZATION`, `OS_VENDOR`, `HARDWARE_VENDOR`, or `RESEARCH_SPECIFICATION`.
- `source_name`: Authoritative publishing body (e.g., `Bluetooth SIG`, `Google LLC`, `Nordic Semiconductor`).
- `source_url`: Verifiable URL to official specifications, developer documentation, or standard registry.
- `is_system_or_vendor`: Boolean indicating system-level or proprietary vendor status.
- `analyst_notes`: Technical context explaining expected usage and protocol purpose.

Entries without authoritative provenance are rejected during validation.

---

## 12. Test Methodology & Validation Results

UCSD's test suite contains **138 automated tests** executed via Pytest inside Docker Compose:

```bash
docker exec ucsd-ucsd-1 pytest -v
```

### Test Suite Composition

| Module / Test File | Test Count | Scope & Coverage |
| :--- | :---: | :--- |
| [`tests/test_validation_matrix.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_validation_matrix.py) | 17 | Core 9-dimension validation matrix: invalid inputs, client-only BLE, unresolved calls, duplicate candidates, strong duplicate registrations, graceful degradation, and input immutability. |
| [`tests/test_registration.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_registration.py) | 24 | Intra-method Dalvik register tracer: positive flows, ParcelUuid, register moves, register clobbering negative tests, out-of-order calls, and register reuse isolation. |
| [`tests/test_conflict.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_conflict.py) | 19 | Cross-APK conflict evaluation: exact-match KB lookups, strong static registration overlaps, asymmetric evidence overlaps, candidate string overlaps, and package identity scoping. |
| [`tests/test_reporting.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_reporting.py) | 12 | HTML escaping (XSS payload safety), offline independence (zero CDNs), single-APK dashboards, batch aggregation, and distinct evidence tier rendering. |
| [`tests/test_knowledge.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_knowledge.py) | 13 | Knowledge base integrity: JSON schema validation, mandatory provenance, exact-match lookup, and malformed database handling. |
| [`tests/test_ble.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_ble.py) | 16 | UUID normalization, 16-bit expansion, regex extraction, DEX method reference scanning, and permission categorization. |
| [`tests/test_manifest.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_manifest.py) | 6 | AXML parsing: package identity, SDK versions, permissions, and activities. |
| [`tests/test_apk_loader.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_apk_loader.py) | 7 | Intake pipeline: SHA-256 computation, ZIP integrity checks, multi-DEX collection. |
| [`tests/test_validation.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_validation.py) | 11 | Decoupled AOSP `aapt` independent verification and comparator assertions. |
| [`tests/test_cli.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_cli.py) | 3 | Command-line interface argument parsing, flag behavior, and exit code handling. |
| [`tests/test_server.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/test_server.py) | 10 | FastAPI REST server & SQLite persistence integration tests: health, dashboard metrics, upload validation, background execution, conflict comparison, report downloads, and record deletion. |
| **Total** | **138** | **138 passed in ~225s (100% pass rate)** |

---

## 13. Distinction: Controlled Fixtures vs. Real-World APK Evaluation

UCSD enforces a strict distinction between testing methodologies:

| Dimension | Controlled Synthetic APK Fixtures | Real-World Production APK Evaluation |
| :--- | :--- | :--- |
| **Target Artifacts** | Deterministic binary APKs generated in [`tests/generate_fixtures.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/generate_fixtures.py) (`demo/inputs/service_a.apk`, etc.). | Real-world compiled APK: [`samples/validation.apk`](file:///c:/Users/jhata/WEB-Projects/UCSD/samples/validation.apk) (F-Droid v2.0.1, 12.5 MB, 3 DEX files). |
| **Known Ground Truth** | Exact opcodes, registers, and strings known a priori. | Ground truth established via independent manual disassembly and bytecode audit script ([`tests/audit_real_apk.py`](file:///c:/Users/jhata/WEB-Projects/UCSD/tests/audit_real_apk.py)). |
| **What It Validates** | Confirms the correctness of Dalvik register state tracking, boundary condition handling, and cross-APK conflict algorithms. | Validates multi-DEX scalability, handling of 139,800+ real method references, and zero false-positive service registrations on real-world code. |
| **What It CANNOT Validate** | Cannot prove detection against complex commercial obfuscators. | Cannot prove absence of runtime vulnerabilities or dynamic behavior. |

---

## 14. Analytical Limitations & Ethical Boundaries

### Technical Limitations & False-Negative Risks
1. **Inter-Procedural Data Flow**: If a `BluetoothGattService` is constructed in one method (e.g., a factory or helper class) and registered in another (e.g., `onStartCommand`), UCSD safely classifies the call site as `REGISTRATION_PATTERN_UUID_UNRESOLVED` (`CROSS_METHOD_SERVICE_OBJECT`). The UUID is not associated.
2. **Field-Based Storage**: When a service or UUID is saved to an instance or static field (`this.mService = ...`) and registered later, intra-method tracing marks the finding as unresolved (`FIELD_BASED_SERVICE_OBJECT`).
3. **Dynamic Identifiers**: UUIDs loaded dynamically from Android string resources (`R.string.uuid`), SharedPreferences, network payloads, or reflection cannot be resolved by static Dalvik tracing.
4. **Native Code (JNI)**: BLE services registered via native C/C++ libraries bypass the Java framework and are not visible to Dalvik bytecode analysis.

### False-Positive Considerations
1. **Dead Code**: Uncalled methods containing valid registration bytecode sequences are still classified as `STRONG_STATIC_ASSOCIATION`.
2. **Standard Sample Code**: Independent applications embedding standard Bluetooth SIG examples (e.g. Heart Rate `0x180D`) will produce a static overlap finding. Analysts must consult the Knowledge Base section of the report to observe that the identifier is an assigned standard.

### Ethical Boundaries
- UCSD is designed exclusively for defensive security review, vulnerability research, and protocol validation.
- An overlap finding is **not proof of exploitation**. No CVE, exploit claim, or malicious accusation should be made based solely on static Dalvik evidence without runtime host verification.

---

## 15. Demonstration Package

An end-to-end evaluation package is located in the [`demo/`](file:///c:/Users/jhata/WEB-Projects/UCSD/demo/) folder:
- **`demo/inputs/`**: Contains `service_a.apk`, `service_b.apk`, and `client_only.apk`.
- **`demo/expected_outputs/`**: Contains pre-generated reference JSON reports.
- **`demo/run_demo.ps1`**: Automated demo script for Windows PowerShell.
- **`demo/run_demo.sh`**: Automated demo script for POSIX/Bash.
- **`demo/README.md`**: Step-by-step walkthrough for evaluation and report inspection.