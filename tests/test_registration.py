"""Comprehensive test suite for UCSD Phase 3: conservative GATT service registration detection."""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from ucsd.apk_loader import load_apk
from ucsd.cli import main, run_analyze
from ucsd.models import APKMetadata, AnalysisReport
from ucsd.registration.detector import KNOWN_BLIND_SPOTS, detect_gatt_registrations
from ucsd.registration.models import (
    AddServiceCallSite,
    EvidenceLevel,
    RegistrationAnalysisResult,
    RegistrationFinding,
    ServiceConstructionSite,
    TraceStep,
    UnresolvedReason,
)
from ucsd.registration.tracer import trace_method_registrations


class MockDalvikInstruction:
    """Mock Dalvik bytecode instruction for deterministic register tracing tests."""

    def __init__(
        self,
        name: str,
        length: int = 2,
        operands: list = None,
        string_val: str = None,
        output: str = "",
    ):
        self._name = name
        self._length = length
        self._operands = operands if operands is not None else []
        self._string_val = string_val
        self._output = output

    def get_name(self) -> str:
        return self._name

    def get_length(self) -> int:
        return self._length

    def get_operands(self) -> list:
        return self._operands

    def get_string(self) -> str:
        return self._string_val

    def get_output(self) -> str:
        return self._output


class TestRegistrationModels:
    """Test suite for Phase 3 Pydantic data models and categorical evidence requirements."""

    def test_evidence_levels_are_strictly_categorical(self):
        """Verify evidence levels are distinct strings and not numeric probabilities."""
        levels = [e.value for e in EvidenceLevel]
        assert "STRONG_STATIC_ASSOCIATION" in levels
        assert "REGISTRATION_PATTERN_UUID_UNRESOLVED" in levels
        assert "UUID_CANDIDATE_ONLY" in levels
        assert len(levels) == 3

        # Must be string subclasses, never floats/ints
        for level in EvidenceLevel:
            assert isinstance(level.value, str)
            assert not isinstance(level.value, (int, float))

    def test_unresolved_reasons_coverage(self):
        """Verify explicit technical reasons for unresolved cases."""
        reasons = [r.value for r in UnresolvedReason]
        assert "CROSS_METHOD_SERVICE_OBJECT" in reasons
        assert "FIELD_BASED_SERVICE_OBJECT" in reasons
        assert "CROSS_METHOD_UUID" in reasons
        assert "FIELD_BASED_UUID" in reasons
        assert "DYNAMIC_UUID_EXPRESSION" in reasons
        assert "SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE" in reasons
        assert "NO_REGISTRATION_CALL_SITE" in reasons
        assert "REGISTER_CLOBBERED_BEFORE_USE" in reasons

    def test_model_immutability(self):
        """Verify models are frozen against accidental post-creation mutation."""
        step = TraceStep(
            step_index=0,
            step_type="load_uuid_string",
            instruction_offset=0,
            opcode="const-string",
            details={"register": 0, "string_value": "0000180d-0000-1000-8000-00805f9b34fb"},
        )
        with pytest.raises(ValidationError):
            step.step_index = 1

        finding = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid="0000180d-0000-1000-8000-00805f9b34fb",
            dex_file="classes.dex",
            class_name="com.example.GattManager",
            method_name="setupServer",
            descriptor="()V",
            diagnosis="Verified registration",
            construction_site=None,
            registration_site=None,
            trace_steps=[step],
            unresolved_reason=None,
        )
        with pytest.raises(ValidationError):
            finding.normalized_uuid = "changed"

    def test_result_serialization_roundtrip(self):
        """Verify RegistrationAnalysisResult serializes and deserializes without loss."""
        result = RegistrationAnalysisResult(
            has_gatt_registrations=True,
            total_add_service_calls=1,
            total_service_constructions=1,
            strong_associations_count=1,
            unresolved_patterns_count=0,
            candidate_only_count=0,
            findings=[
                RegistrationFinding(
                    evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
                    normalized_uuid="0000180d-0000-1000-8000-00805f9b34fb",
                    dex_file="classes.dex",
                    class_name="com.example.GattManager",
                    method_name="setupServer",
                    descriptor="()V",
                    diagnosis="Verified registration",
                    construction_site=None,
                    registration_site=None,
                    trace_steps=[],
                    unresolved_reason=None,
                )
            ],
            blind_spots_and_limitations=KNOWN_BLIND_SPOTS,
        )
        json_data = result.model_dump_json()
        restored = RegistrationAnalysisResult.model_validate_json(json_data)
        assert restored.has_gatt_registrations is True
        assert restored.strong_associations_count == 1
        assert restored.findings[0].evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION
        assert restored.findings[0].normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"


class TestIntraMethodTracer:
    """Test suite for intra-method forward Dalvik register data-flow tracing."""

    def test_strong_static_association_single_method(self):
        """Test Case 1: Literal UUID -> UUID.fromString -> BluetoothGattService.<init> -> addService."""
        instructions = [
            # v0 = "0000180d-0000-1000-8000-00805f9b34fb"
            MockDalvikInstruction(
                "const-string",
                length=2,
                operands=[(0, 0), (256, 0, "0000180d-0000-1000-8000-00805f9b34fb")],
                string_val="0000180d-0000-1000-8000-00805f9b34fb",
            ),
            # UUID.fromString(v0)
            MockDalvikInstruction(
                "invoke-static",
                length=3,
                operands=[(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")],
                output="invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;",
            ),
            # v1 = result (UUID object)
            MockDalvikInstruction(
                "move-result-object",
                length=1,
                operands=[(0, 1)],
            ),
            # v2 = 0 (service type)
            MockDalvikInstruction(
                "const/4",
                length=1,
                operands=[(0, 2), 0],
            ),
            # v3 = new BluetoothGattService
            MockDalvikInstruction(
                "new-instance",
                length=2,
                operands=[(0, 3)],
            ),
            # BluetoothGattService.<init>(v3, v1, v2)
            MockDalvikInstruction(
                "invoke-direct",
                length=3,
                operands=[
                    (0, 3),
                    (0, 1),
                    (0, 2),
                    (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V"),
                ],
                output="invoke-direct {v3, v1, v2}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
            # BluetoothGattServer.addService(v4, v3)
            MockDalvikInstruction(
                "invoke-virtual",
                length=3,
                operands=[
                    (0, 4),
                    (0, 3),
                    (256, 3, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z"),
                ],
                output="invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.GattServerManager",
            method_name="initGattService",
            descriptor="()V",
            instructions=instructions,
        )

        assert len(findings) == 1
        assert len(constructions) == 1
        assert len(add_services) == 1

        f = findings[0]
        assert f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION
        assert f.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"
        assert f.dex_file == "classes.dex"
        assert f.class_name == "com.example.GattServerManager"
        assert f.method_name == "initGattService"
        assert f.unresolved_reason is None
        assert f.construction_site is not None
        assert f.registration_site is not None

        # Verify trace steps
        assert len(f.trace_steps) == 4
        assert f.trace_steps[0].step_type == "load_uuid_string"
        assert f.trace_steps[0].details["string_value"] == "0000180d-0000-1000-8000-00805f9b34fb"
        assert f.trace_steps[1].step_type == "uuid_from_string"
        assert f.trace_steps[2].step_type == "service_constructor"
        assert f.trace_steps[3].step_type == "add_service_registration"

    def test_strong_static_association_with_parcel_uuid(self):
        """Test Case 1b: Flow using ParcelUuid.fromString and ParcelUuid.getUuid."""
        instructions = [
            # v0 = "0000180f-0000-1000-8000-00805f9b34fb"
            MockDalvikInstruction(
                "const-string",
                length=2,
                operands=[(0, 0), (256, 0, "0000180f-0000-1000-8000-00805f9b34fb")],
                string_val="0000180f-0000-1000-8000-00805f9b34fb",
            ),
            # ParcelUuid.fromString(v0)
            MockDalvikInstruction(
                "invoke-static",
                length=3,
                operands=[(0, 0), (256, 1, "Landroid/os/ParcelUuid;->fromString(Ljava/lang/String;)Landroid/os/ParcelUuid;")],
                output="invoke-static {v0}, Landroid/os/ParcelUuid;->fromString(Ljava/lang/String;)Landroid/os/ParcelUuid;",
            ),
            # v1 = ParcelUuid
            MockDalvikInstruction("move-result-object", length=1, operands=[(0, 1)]),
            # v1.getUuid()
            MockDalvikInstruction(
                "invoke-virtual",
                length=3,
                operands=[(0, 1), (256, 2, "Landroid/os/ParcelUuid;->getUuid()Ljava/util/UUID;")],
                output="invoke-virtual {v1}, Landroid/os/ParcelUuid;->getUuid()Ljava/util/UUID;",
            ),
            # v2 = UUID
            MockDalvikInstruction("move-result-object", length=1, operands=[(0, 2)]),
            # BluetoothGattService.<init>(v3, v2, v0)
            MockDalvikInstruction(
                "invoke-direct",
                length=3,
                operands=[(0, 3), (0, 2), (0, 0), (256, 3, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")],
                output="invoke-direct {v3, v2, v0}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
            # BluetoothGattServer.addService(v4, v3)
            MockDalvikInstruction(
                "invoke-virtual",
                length=3,
                operands=[(0, 4), (0, 3), (256, 4, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.ParcelService",
            method_name="registerBattery",
            descriptor="()V",
            instructions=instructions,
        )

        assert len(findings) == 1
        assert findings[0].evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION
        assert findings[0].normalized_uuid == "0000180f-0000-1000-8000-00805f9b34fb"

    def test_strong_association_with_register_moves(self):
        """Test Case 1c: Register data flow correctly tracked through move-object instructions."""
        instructions = [
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 0, "0x180D")], string_val="0x180D"),
            # move-object v5, v0 (copy string register)
            MockDalvikInstruction("move-object", 1, [(0, 5), (0, 0)]),
            MockDalvikInstruction(
                "invoke-static",
                3,
                [(0, 5), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")],
                output="invoke-static {v5}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;",
            ),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            MockDalvikInstruction(
                "invoke-direct",
                3,
                [(0, 3), (0, 1), (0, 0), (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")],
                output="invoke-direct {v3, v1, v0}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
            # move-object v6, v3 (copy service register)
            MockDalvikInstruction("move-object", 1, [(0, 6), (0, 3)]),
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 6), (256, 3, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v6}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, _, _ = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.MoveTest",
            method_name="testMove",
            descriptor="()V",
            instructions=instructions,
        )

        assert len(findings) == 1
        assert findings[0].evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION
        # 0x180D expanded to 128-bit base UUID
        assert findings[0].normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"

    def test_unused_uuid_constant_no_registration_call(self):
        """Test Case 2: Unused UUID constant generates zero intra-method registration findings."""
        instructions = [
            MockDalvikInstruction(
                "const-string",
                2,
                [(0, 0), (256, 0, "cd59ba31-5729-b3bb-cb29-732b59eb61aa")],
                string_val="cd59ba31-5729-b3bb-cb29-732b59eb61aa",
            ),
            MockDalvikInstruction(
                "invoke-static",
                3,
                [(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")],
                output="invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;",
            ),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            # No BluetoothGattService constructor, no addService
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.UnusedUUID",
            method_name="getConstant",
            descriptor="()Ljava/util/UUID;",
            instructions=instructions,
        )

        assert len(findings) == 0
        assert len(constructions) == 0
        assert len(add_services) == 0

    def test_unresolved_service_object_cross_method(self):
        """Test Case 3a: addService called with service object passed from method argument."""
        instructions = [
            # addService(v4, v1) where v1 is a method parameter (never initialized in this method)
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 1), (256, 1, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v1}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.ServerWrapper",
            method_name="registerExternalService",
            descriptor="(Landroid/bluetooth/BluetoothGattService;)V",
            instructions=instructions,
        )

        assert len(findings) == 1
        assert findings[0].evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED
        assert findings[0].normalized_uuid is None
        assert findings[0].unresolved_reason == UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT
        assert findings[0].construction_site is None
        assert findings[0].registration_site is not None
        assert len(findings[0].trace_steps) == 0

    def test_unresolved_service_object_field_based(self):
        """Test Case 3b: addService called with service object retrieved via iget (instance field)."""
        instructions = [
            # v1 = this.mService (iget-object)
            MockDalvikInstruction(
                "iget-object",
                2,
                [(0, 1), (0, 0), (256, 1, "Lcom/example/MyClass;->mService:Landroid/bluetooth/BluetoothGattService;")],
            ),
            # addService(v4, v1)
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 1), (256, 2, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v1}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.FieldService",
            method_name="registerFromField",
            descriptor="()V",
            instructions=instructions,
        )

        assert len(findings) == 1
        assert findings[0].evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED
        assert findings[0].unresolved_reason == UnresolvedReason.FIELD_BASED_SERVICE_OBJECT

    def test_service_construction_without_local_add_service(self):
        """Test Case 4a: Service constructor invoked with known UUID, but addService is in another method."""
        instructions = [
            MockDalvikInstruction(
                "const-string",
                2,
                [(0, 0), (256, 0, "0000180d-0000-1000-8000-00805f9b34fb")],
                string_val="0000180d-0000-1000-8000-00805f9b34fb",
            ),
            MockDalvikInstruction(
                "invoke-static",
                3,
                [(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")],
                output="invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;",
            ),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            MockDalvikInstruction("new-instance", 2, [(0, 3)]),
            MockDalvikInstruction(
                "invoke-direct",
                3,
                [(0, 3), (0, 1), (0, 0), (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")],
                output="invoke-direct {v3, v1, v0}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
            # Service returned or stored; addService NOT called here
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.ServiceFactory",
            method_name="createHeartRateService",
            descriptor="()Landroid/bluetooth/BluetoothGattService;",
            instructions=instructions,
        )

        assert len(findings) == 1
        assert len(constructions) == 1
        assert len(add_services) == 0

        f = findings[0]
        assert f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED
        assert f.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"
        assert f.unresolved_reason == UnresolvedReason.SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE
        assert f.construction_site is not None
        assert f.registration_site is None
        assert len(f.trace_steps) >= 3

    def test_service_construction_with_unresolved_uuid_parameter(self):
        """Test Case 4b: Service constructor called where UUID argument is an untracked parameter."""
        instructions = [
            # v1 is UUID parameter passed from caller
            MockDalvikInstruction("new-instance", 2, [(0, 3)]),
            MockDalvikInstruction(
                "invoke-direct",
                3,
                [(0, 3), (0, 1), (0, 0), (256, 1, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")],
                output="invoke-direct {v3, v1, v0}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
            # addService(v4, v3)
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 3), (256, 2, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.DynamicService",
            method_name="buildAndRegister",
            descriptor="(Ljava/util/UUID;)V",
            instructions=instructions,
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED
        assert f.normalized_uuid is None
        assert f.unresolved_reason == UnresolvedReason.CROSS_METHOD_UUID

    def test_multiple_registrations_and_uuids_no_crosstalk(self):
        """Test Case 5: Multiple UUIDs, services, and registrations in one method without crosstalk."""
        uuid_a = "0000180d-0000-1000-8000-00805f9b34fb"
        uuid_b = "0000180f-0000-1000-8000-00805f9b34fb"
        uuid_c = "12345678-1234-5678-1234-567812345678"

        instructions = [
            # Service A
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 0, uuid_a)], string_val=uuid_a),
            MockDalvikInstruction("invoke-static", 3, [(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            MockDalvikInstruction("new-instance", 2, [(0, 2)]),
            MockDalvikInstruction("invoke-direct", 3, [(0, 2), (0, 1), (0, 0), (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")]),
            MockDalvikInstruction("invoke-virtual", 3, [(0, 9), (0, 2), (256, 3, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")]),

            # Service B
            MockDalvikInstruction("const-string", 2, [(0, 3), (256, 4, uuid_b)], string_val=uuid_b),
            MockDalvikInstruction("invoke-static", 3, [(0, 3), (256, 5, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 4)]),
            MockDalvikInstruction("new-instance", 2, [(0, 5)]),
            MockDalvikInstruction("invoke-direct", 3, [(0, 5), (0, 4), (0, 0), (256, 6, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")]),
            MockDalvikInstruction("invoke-virtual", 3, [(0, 9), (0, 5), (256, 7, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")]),

            # Service C (Constructed but NOT registered with addService)
            MockDalvikInstruction("const-string", 2, [(0, 6), (256, 8, uuid_c)], string_val=uuid_c),
            MockDalvikInstruction("invoke-static", 3, [(0, 6), (256, 9, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 7)]),
            MockDalvikInstruction("new-instance", 2, [(0, 8)]),
            MockDalvikInstruction("invoke-direct", 3, [(0, 8), (0, 7), (0, 0), (256, 10, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")]),
        ]

        findings, constructions, add_services = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.MultiServiceManager",
            method_name="registerAll",
            descriptor="()V",
            instructions=instructions,
        )

        assert len(constructions) == 3
        assert len(add_services) == 2
        assert len(findings) == 3

        strong_findings = [f for f in findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION]
        unresolved_findings = [f for f in findings if f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED]

        assert len(strong_findings) == 2
        assert len(unresolved_findings) == 1

        strong_uuids = {f.normalized_uuid for f in strong_findings}
        assert strong_uuids == {uuid_a, uuid_b}

        assert unresolved_findings[0].normalized_uuid == uuid_c
        assert unresolved_findings[0].unresolved_reason == UnresolvedReason.SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE

    def test_register_clobbering_prevents_false_association(self):
        """Test Case 5b: Clobbering service register before addService prevents false association."""
        instructions = [
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 0, "0000180d-0000-1000-8000-00805f9b34fb")], string_val="0000180d-0000-1000-8000-00805f9b34fb"),
            MockDalvikInstruction("invoke-static", 3, [(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            MockDalvikInstruction("invoke-direct", 3, [(0, 2), (0, 1), (0, 0), (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")]),
            # CLOBBER v2 with an integer constant!
            MockDalvikInstruction("const/4", 1, [(0, 2), 0]),
            # addService(v4, v2)
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 2), (256, 3, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v2}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, _, _ = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.ClobberTest",
            method_name="testClobber",
            descriptor="()V",
            instructions=instructions,
        )

        # Must NOT produce STRONG_STATIC_ASSOCIATION because v2 was clobbered
        strong_findings = [f for f in findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION]
        assert len(strong_findings) == 0

        # Produces unresolved findings
        assert any(f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED for f in findings)

    def test_clobbered_uuid_register_before_service_constructor(self):
        """Negative Test: Clobbering UUID register before service constructor prevents strong association."""
        instructions = [
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 0, "0000180d-0000-1000-8000-00805f9b34fb")], string_val="0000180d-0000-1000-8000-00805f9b34fb"),
            MockDalvikInstruction("invoke-static", 3, [(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            # CLOBBER v1 (UUID register) with an integer before constructor is invoked!
            MockDalvikInstruction("const/4", 1, [(0, 1), 0]),
            MockDalvikInstruction("new-instance", 2, [(0, 3)]),
            MockDalvikInstruction(
                "invoke-direct",
                3,
                [(0, 3), (0, 1), (0, 0), (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")],
                output="invoke-direct {v3, v1, v0}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 3), (256, 3, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, _, _ = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.ClobberUuidTest",
            method_name="testUuidClobber",
            descriptor="()V",
            instructions=instructions,
        )

        strong = [f for f in findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION]
        assert len(strong) == 0
        unres = [f for f in findings if f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED]
        assert len(unres) >= 1
        assert unres[0].normalized_uuid is None

    def test_clobbered_service_register_with_new_instance(self):
        """Negative Test: Reassigning service register with new-instance before addService prevents strong association."""
        instructions = [
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 0, "0000180d-0000-1000-8000-00805f9b34fb")], string_val="0000180d-0000-1000-8000-00805f9b34fb"),
            MockDalvikInstruction("invoke-static", 3, [(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            MockDalvikInstruction("new-instance", 2, [(0, 3)]),
            MockDalvikInstruction(
                "invoke-direct",
                3,
                [(0, 3), (0, 1), (0, 0), (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")],
                output="invoke-direct {v3, v1, v0}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
            # CLOBBER v3 with an arbitrary new-instance before addService
            MockDalvikInstruction("new-instance", 2, [(0, 3)]),
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 3), (256, 3, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, _, _ = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.ClobberServiceNewInstance",
            method_name="testServiceClobber",
            descriptor="()V",
            instructions=instructions,
        )

        strong = [f for f in findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION]
        assert len(strong) == 0
        unres = [f for f in findings if f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED]
        assert len(unres) >= 1

    def test_out_of_order_add_service_before_constructor(self):
        """Negative Test: addService called before BluetoothGattService.<init> does not produce strong association."""
        instructions = [
            # v3 allocated via new-instance, but <init> not yet called
            MockDalvikInstruction("new-instance", 2, [(0, 3)]),
            # addService called prematurely with uninitialized register
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 3), (256, 1, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
            # Now UUID and constructor are invoked afterwards
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 2, "0000180d-0000-1000-8000-00805f9b34fb")], string_val="0000180d-0000-1000-8000-00805f9b34fb"),
            MockDalvikInstruction("invoke-static", 3, [(0, 0), (256, 3, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            MockDalvikInstruction(
                "invoke-direct",
                3,
                [(0, 3), (0, 1), (0, 0), (256, 4, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")],
                output="invoke-direct {v3, v1, v0}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V",
            ),
        ]

        findings, _, _ = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.OutOfOrderTest",
            method_name="testOutOfOrder",
            descriptor="()V",
            instructions=instructions,
        )

        strong = [f for f in findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION]
        assert len(strong) == 0

    def test_register_reuse_associates_correct_uuid(self):
        """Test: Register reused for multiple UUIDs correctly associates each service with its specific UUID."""
        uuid_a = "0000180d-0000-1000-8000-00805f9b34fb"
        uuid_b = "0000180f-0000-1000-8000-00805f9b34fb"

        instructions = [
            # Load UUID A into v1
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 0, uuid_a)], string_val=uuid_a),
            MockDalvikInstruction("invoke-static", 3, [(0, 0), (256, 1, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            # Create Service A in v3 using v1 (UUID A)
            MockDalvikInstruction("new-instance", 2, [(0, 3)]),
            MockDalvikInstruction("invoke-direct", 3, [(0, 3), (0, 1), (0, 0), (256, 2, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")]),

            # Overwrite v1 with UUID B!
            MockDalvikInstruction("const-string", 2, [(0, 0), (256, 3, uuid_b)], string_val=uuid_b),
            MockDalvikInstruction("invoke-static", 3, [(0, 0), (256, 4, "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;")]),
            MockDalvikInstruction("move-result-object", 1, [(0, 1)]),
            # Create Service B in v5 using v1 (UUID B)
            MockDalvikInstruction("new-instance", 2, [(0, 5)]),
            MockDalvikInstruction("invoke-direct", 3, [(0, 5), (0, 1), (0, 0), (256, 5, "Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V")]),

            # Register ONLY Service A (v3)
            MockDalvikInstruction(
                "invoke-virtual",
                3,
                [(0, 4), (0, 3), (256, 6, "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z")],
                output="invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z",
            ),
        ]

        findings, _, _ = trace_method_registrations(
            dex_file="classes.dex",
            class_name="com.example.ReuseRegisterTest",
            method_name="testRegisterReuse",
            descriptor="()V",
            instructions=instructions,
        )

        strong = [f for f in findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION]
        assert len(strong) == 1
        assert strong[0].normalized_uuid == uuid_a


class TestRegistrationDetector:
    """Test suite for high-level GATT registration detection across APK DEX files."""

    def test_detector_on_no_ble_apk(self, no_ble_apk: Path):
        """Verify detector runs safely on APK without Bluetooth APIs."""
        result = detect_gatt_registrations(no_ble_apk, candidate_uuids=[])
        assert isinstance(result, RegistrationAnalysisResult)
        assert result.has_gatt_registrations is False
        assert result.total_add_service_calls == 0
        assert result.total_service_constructions == 0
        assert result.strong_associations_count == 0
        assert result.unresolved_patterns_count == 0
        assert result.candidate_only_count == 0
        assert len(result.findings) == 0
        assert len(result.blind_spots_and_limitations) > 0

    def test_detector_candidate_only_correlation(self, ble_single_dex_apk: Path):
        """Verify candidate UUIDs are categorized as UUID_CANDIDATE_ONLY when no registration exists."""
        candidates = [
            "0000180d-0000-1000-8000-00805f9b34fb",
            "0000180f-0000-1000-8000-00805f9b34fb",
            "12345678-1234-5678-1234-567812345678",
        ]
        result = detect_gatt_registrations(ble_single_dex_apk, candidate_uuids=candidates)

        assert result.has_gatt_registrations is False
        assert result.strong_associations_count == 0
        assert result.unresolved_patterns_count == 0
        assert result.candidate_only_count == 3
        assert len(result.findings) == 3

        for finding in result.findings:
            assert finding.evidence_level == EvidenceLevel.UUID_CANDIDATE_ONLY
            assert finding.normalized_uuid in candidates
            assert finding.unresolved_reason == UnresolvedReason.NO_REGISTRATION_CALL_SITE
            assert finding.construction_site is None
            assert finding.registration_site is None

    def test_real_sample_apk_zero_false_positives(self):
        """Test Case 6: Real F-Droid sample APK has classic Bluetooth RFCOMM but 0 GATT server calls.

        All candidate UUIDs must remain strictly UUID_CANDIDATE_ONLY.
        Zero false positive GATT service registrations.
        """
        sample_path = Path("/app/samples/validation.apk")
        if not sample_path.is_file():
            pytest.skip("Sample APK /app/samples/validation.apk not present")

        meta = load_apk(str(sample_path), scan_ble=True, scan_registration=True)
        assert meta.registration_analysis is not None
        reg = meta.registration_analysis

        assert reg.has_gatt_registrations is False
        assert reg.total_add_service_calls == 0
        assert reg.total_service_constructions == 0
        assert reg.strong_associations_count == 0
        assert reg.unresolved_patterns_count == 0

        # All candidates must be UUID_CANDIDATE_ONLY
        assert reg.candidate_only_count == len(meta.ble_analysis.uuid_candidates)
        assert reg.candidate_only_count > 0

        for f in reg.findings:
            assert f.evidence_level == EvidenceLevel.UUID_CANDIDATE_ONLY
            assert f.unresolved_reason == UnresolvedReason.NO_REGISTRATION_CALL_SITE


class TestRegistrationCLI:
    """Test suite for CLI integration of Phase 3 GATT registration detection."""

    def test_cli_report_includes_registration_analysis(self, valid_single_dex_apk: Path, tmp_path: Path):
        """Verify CLI produces registration_analysis block in output JSON report."""
        out_file = tmp_path / "cli_reg_report.json"
        exit_code = run_analyze(str(valid_single_dex_apk), str(out_file), quiet=True)

        assert exit_code == 0
        assert out_file.is_file()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert "registration_analysis" in data
        assert data["registration_analysis"] is not None
        assert data["registration_analysis"]["has_gatt_registrations"] is False
        assert "blind_spots_and_limitations" in data["registration_analysis"]

    def test_cli_skip_registration_flag(self, valid_single_dex_apk: Path, tmp_path: Path):
        """Verify --skip-registration flag suppresses registration analysis."""
        out_file = tmp_path / "cli_skip_reg.json"
        exit_code = run_analyze(
            str(valid_single_dex_apk),
            str(out_file),
            skip_registration=True,
            quiet=True,
        )

        assert exit_code == 0
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["registration_analysis"] is None
        assert data["metadata"]["registration_analysis"] is None

    def test_cli_main_skip_registration_argument(self, valid_single_dex_apk: Path, tmp_path: Path):
        """Verify main() parses --skip-registration flag correctly."""
        reports_dir = tmp_path / "reports_skip"
        exit_code = main([
            "analyze",
            str(valid_single_dex_apk),
            "--skip-registration",
            "--out",
            str(reports_dir),
            "--quiet",
        ])

        assert exit_code == 0
        report_files = list(reports_dir.glob("*.json"))
        assert len(report_files) == 1

        with open(report_files[0], "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["registration_analysis"] is None
