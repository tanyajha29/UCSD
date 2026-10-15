# UCSD Phase 6: Manual Disassembly Inspection & Evidence Verification

**Evaluation Objective**: Validate that UCSD's static evidence assertions directly and conservatively reflect genuine Dalvik bytecode instructions.

---

## 1. Positive Registration Case: `STRONG_STATIC_ASSOCIATION`

- **Target**: `positive_fixture.apk` (`org.example.positive`)
- **Class**: `Lorg/example/positive/GattService;`
- **Method**: `registerService()V`
- **Candidate UUID**: `0000180d-0000-1000-8000-00805f9b34fb` (Heart Rate Service)

### Raw Dalvik Disassembly

| Offset | Bytecode Mnemonic | Operands / Details | Raw Disassembly |
| :--- | :--- | :--- | :--- |
| `+0x0000` | `const-string` | `[(<Operand.REGISTER: 0>, 0), (257, 4, '0000180d-0000-1000-8000-00805f9b34fb')]` | `v0, "0000180d-0000-1000-8000-00805f9b34fb"` |
| `+0x0004` | `invoke-static` | `[(<Operand.REGISTER: 0>, 0), (256, 3, 'Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;')]` | `v0, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;` |
| `+0x000a` | `move-result-object` | `[(<Operand.REGISTER: 0>, 1)]` | `v1` |
| `+0x000c` | `const/4` | `[(<Operand.REGISTER: 0>, 2), (<Operand.LITERAL: 1>, 0)]` | `v2, 0` |
| `+0x000e` | `new-instance` | `[(<Operand.REGISTER: 0>, 3), (259, 2, 'Landroid/bluetooth/BluetoothGattService;')]` | `v3, Landroid/bluetooth/BluetoothGattService;` |
| `+0x0012` | `invoke-direct` | `[(<Operand.REGISTER: 0>, 3), (<Operand.REGISTER: 0>, 1), (<Operand.REGISTER: 0>, 2), (256, 1, 'Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID; I)V')]` | `v3, v1, v2, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID; I)V` |
| `+0x0018` | `invoke-virtual` | `[(<Operand.REGISTER: 0>, 4), (<Operand.REGISTER: 0>, 3), (256, 0, 'Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z')]` | `v4, v3, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z` |
| `+0x001e` | `return-void` | `[]` | `` |

### UCSD Extracted Evidence & Trace Steps

- **Evidence Level**: `STRONG_STATIC_ASSOCIATION`
- **Normalized UUID**: `0000180d-0000-1000-8000-00805f9b34fb`
- **Diagnosis**: Verified intra-method registration: Literal UUID '0000180d-0000-1000-8000-00805f9b34fb' loaded at offset 0x0000, converted via UUID.fromString at offset 0x0004, used in BluetoothGattService constructor at offset 0x0012, and registered via BluetoothGattServer.addService() at offset 0x0018.

| Step | Trace Type | Offset | Opcode | Details | Bytecode Verification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 0 | `load_uuid_string` | `+0x0000` | `const-string` | `{'register': 0, 'string_value': '0000180d-0000-1000-8000-00805f9b34fb'}` | **Verified Exact Match** |
| 1 | `uuid_from_string` | `+0x0004` | `invoke-static` | `{'method': 'Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;', 'input_register': 0, 'result_register': 1}` | **Verified Exact Match** |
| 2 | `service_constructor` | `+0x0012` | `invoke-direct` | `{'method': 'Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID; I)V', 'service_register': 3, 'uuid_register': 1, 'resolved_uuid': '0000180d-0000-1000-8000-00805f9b34fb'}` | **Verified Exact Match** |
| 3 | `add_service_registration` | `+0x0018` | `invoke-virtual` | `{'method': 'Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z', 'server_register': 4, 'service_register': 3}` | **Verified Exact Match** |

**Analysis**: All 4 trace steps correspond exactly to the Dalvik instruction offsets `+0x0000`, `+0x0002`, `+0x0009`, and `+0x000c`. The data flow from literal UUID string to `UUID.fromString` into `BluetoothGattService.<init>` and finally into `BluetoothGattServer.addService` is fully established by actual bytecode.

---

## 2. Negative Case 1: Unused UUID Constant (`UUID_CANDIDATE_ONLY`)

- **Target**: `negative_candidate.apk` (`org.example.candidate_only`)
- **Candidate UUID**: `0000180d-0000-1000-8000-00805f9b34fb`

### UCSD Finding
- **Evidence Level**: `UUID_CANDIDATE_ONLY`
- **Unresolved Reason**: `NO_REGISTRATION_CALL_SITE`
- **Diagnosis**: UUID candidate '0000180d-0000-1000-8000-00805f9b34fb' discovered in DEX constants/strings, but has no static data-flow link to BluetoothGattService constructor or BluetoothGattServer.addService() registration call sites.
- **Trace Steps**: `0` (None fabricated)

**Analysis**: Although the UUID string exists in the DEX string pool, bytecode inspection confirms zero constructor or `addService` invocations. UCSD conservatively keeps the finding as `UUID_CANDIDATE_ONLY` and refuses to assert service registration.

---

## 3. Negative Case 2: Cross-Method Service Object (`REGISTRATION_PATTERN_UUID_UNRESOLVED`)

- **Target**: `unresolved_callsite.apk` (`org.example.unresolved`)
- **Class**: `Lorg/example/unresolved/ServerHelper;`
- **Method**: `registerExternal()V`

### Raw Dalvik Disassembly

| Offset | Bytecode Mnemonic | Operands / Details | Raw Disassembly |
| :--- | :--- | :--- | :--- |
| `+0x0000` | `invoke-virtual` | `[(<Operand.REGISTER: 0>, 0), (<Operand.REGISTER: 0>, 1), (256, 0, 'Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z')]` | `v0, v1, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z` |
| `+0x0006` | `return-void` | `[]` | `` |

### UCSD Finding
- **Evidence Level**: `REGISTRATION_PATTERN_UUID_UNRESOLVED`
- **Unresolved Reason**: `CROSS_METHOD_SERVICE_OBJECT`
- **Normalized UUID**: `None` (None fabricated)
- **Diagnosis**: Registration pattern detected: BluetoothGattServer.addService() invoked at offset 0x0000, but the service object in register v1 was not constructed locally within this method (originates from method parameter, field read, or external method call).

**Analysis**: Disassembly proves `BluetoothGattServer.addService` is invoked at offset `+0x0000`, but register `v1` (the service object) is an uninitialized parameter. UCSD correctly detects the registration call site without falsely attributing any candidate UUID.

---

## 4. Real-World APK Verification: `validation.apk` (F-Droid v2.0.1)

- **SHA-256**: `83d3fe522281c3cb89fce3bc05038f81b3c3b32c108536941f184c5f9bb53778`
- **DEX Count**: 3 (`classes.dex`, `classes2.dex`, `classes3.dex`)
- **Manifest Permissions**: 5 Bluetooth permissions (`BLUETOOTH`, `BLUETOOTH_ADMIN`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN`)
- **Candidate UUIDs Found**: 88 unique candidate strings in DEX
- **Strong Static Associations**: `0`
- **Unresolved Patterns**: `0`
- **Candidate Only**: `88` (All 88)

**Analysis**: In this real-world production application, Bluetooth socket communication is used for peer-to-peer FDroid exchange. No GATT server service registration APIs (`BluetoothGattServer.addService`) are referenced. Despite 88 candidate UUID strings being present (from ZXing barcodes, Okio zip attributes, and database identifiers), UCSD correctly labels all 88 candidates as `UUID_CANDIDATE_ONLY`. Zero false-positive GATT registrations were generated.

---

## Summary Conclusion

| Test Case | Ground Truth State | UCSD Evidence Level | Verified Concordance |
| :--- | :--- | :--- | :--- |
| Controlled Registration | Full intra-method registration of `0x180D` | `STRONG_STATIC_ASSOCIATION` | **100% Match** |
| Unused UUID Constant | String in pool, no service construction | `UUID_CANDIDATE_ONLY` | **100% Match** |
| Unresolved Call Site | `addService` with cross-method argument | `REGISTRATION_PATTERN_UUID_UNRESOLVED` | **100% Match** |
| Real APK (`validation.apk`) | Classic BT socket, no GATT server | `UUID_CANDIDATE_ONLY` (88/88) | **100% Match** |