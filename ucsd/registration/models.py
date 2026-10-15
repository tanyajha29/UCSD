"""Data models for Phase 3: conservative, evidence-grounded registration detection."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceLevel(str, Enum):
    """Categorical static evidence levels for UUID registration association.

    Strictly categorical: NEVER represented as calibrated probabilities or heuristic percentages.
    """
    STRONG_STATIC_ASSOCIATION = "STRONG_STATIC_ASSOCIATION"
    REGISTRATION_PATTERN_UUID_UNRESOLVED = "REGISTRATION_PATTERN_UUID_UNRESOLVED"
    UUID_CANDIDATE_ONLY = "UUID_CANDIDATE_ONLY"


class UnresolvedReason(str, Enum):
    """Explicit technical reason when registration or UUID linkage is unresolved."""
    CROSS_METHOD_SERVICE_OBJECT = "CROSS_METHOD_SERVICE_OBJECT"
    FIELD_BASED_SERVICE_OBJECT = "FIELD_BASED_SERVICE_OBJECT"
    CROSS_METHOD_UUID = "CROSS_METHOD_UUID"
    FIELD_BASED_UUID = "FIELD_BASED_UUID"
    DYNAMIC_UUID_EXPRESSION = "DYNAMIC_UUID_EXPRESSION"
    SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE = "SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE"
    NO_REGISTRATION_CALL_SITE = "NO_REGISTRATION_CALL_SITE"
    REGISTER_CLOBBERED_BEFORE_USE = "REGISTER_CLOBBERED_BEFORE_USE"


class TraceStep(BaseModel):
    """Single observation step in an intra-method register data-flow trace."""
    model_config = ConfigDict(frozen=True)

    step_index: int = Field(..., description="0-indexed sequence position in the trace")
    step_type: str = Field(..., description="Type of operation, e.g. load_uuid_string, uuid_from_string, service_constructor, add_service")
    instruction_offset: int = Field(..., description="Bytecode offset in bytes within the method")
    opcode: str = Field(..., description="Dalvik opcode name, e.g. const-string, invoke-static, invoke-direct, invoke-virtual")
    details: Dict[str, Any] = Field(default_factory=dict, description="Operand registers, values, and signatures")


class ServiceConstructionSite(BaseModel):
    """Call site of a BluetoothGattService constructor."""
    model_config = ConfigDict(frozen=True)

    dex_file: str = Field(..., description="DEX file containing the construction, e.g. classes.dex")
    class_name: str = Field(..., description="Enclosing class name")
    method_name: str = Field(..., description="Enclosing method name")
    descriptor: str = Field(..., description="Enclosing method descriptor")
    instruction_offset: int = Field(..., description="Bytecode offset of the constructor call")
    service_register: int = Field(..., description="Register holding the service instance ('this')")
    uuid_register: int = Field(..., description="Register holding the UUID object passed to constructor")
    service_type_register: Optional[int] = Field(None, description="Register holding serviceType int if present")
    resolved_uuid: Optional[str] = Field(None, description="Normalized UUID string if resolved via intra-method trace")
    unresolved_reason: Optional[UnresolvedReason] = Field(None, description="Reason if UUID could not be resolved")


class AddServiceCallSite(BaseModel):
    """Call site of BluetoothGattServer.addService(BluetoothGattService)."""
    model_config = ConfigDict(frozen=True)

    dex_file: str = Field(..., description="DEX file containing the call site")
    class_name: str = Field(..., description="Enclosing class name")
    method_name: str = Field(..., description="Enclosing method name")
    descriptor: str = Field(..., description="Enclosing method descriptor")
    instruction_offset: int = Field(..., description="Bytecode offset of addService call")
    server_register: int = Field(..., description="Register holding BluetoothGattServer instance ('this')")
    service_register: int = Field(..., description="Register holding BluetoothGattService passed to addService")
    is_service_resolved_locally: bool = Field(..., description="True if service instance was constructed in this method")
    unresolved_reason: Optional[UnresolvedReason] = Field(None, description="Reason if service object is not resolved locally")


class RegistrationFinding(BaseModel):
    """Evaluated association between a UUID / service and a registration call site."""
    model_config = ConfigDict(frozen=True)

    evidence_level: EvidenceLevel = Field(..., description="STRONG_STATIC_ASSOCIATION, REGISTRATION_PATTERN_UUID_UNRESOLVED, or UUID_CANDIDATE_ONLY")
    normalized_uuid: Optional[str] = Field(None, description="Associated normalized 128-bit UUID, or None if unresolved")
    dex_file: str = Field(..., description="DEX file of the primary observation")
    class_name: str = Field(..., description="Declaring class name")
    method_name: str = Field(..., description="Declaring method name")
    descriptor: str = Field(..., description="Declaring method descriptor")
    diagnosis: str = Field(..., description="Clear explanation of the evidence or lack thereof")
    construction_site: Optional[ServiceConstructionSite] = Field(None, description="Service construction call site if present")
    registration_site: Optional[AddServiceCallSite] = Field(None, description="addService call site if present")
    trace_steps: List[TraceStep] = Field(default_factory=list, description="Verified sequence of intra-method data-flow steps")
    unresolved_reason: Optional[UnresolvedReason] = Field(None, description="Explicit reason if not STRONG_STATIC_ASSOCIATION")


class RegistrationAnalysisResult(BaseModel):
    """Structured report of Phase 3 GATT service registration analysis."""
    model_config = ConfigDict(frozen=True)

    has_gatt_registrations: bool = Field(..., description="True if any strong associations or unresolved registration patterns exist")
    total_add_service_calls: int = Field(..., description="Total BluetoothGattServer.addService call sites detected")
    total_service_constructions: int = Field(..., description="Total BluetoothGattService constructor call sites detected")
    strong_associations_count: int = Field(..., description="Number of STRONG_STATIC_ASSOCIATION findings")
    unresolved_patterns_count: int = Field(..., description="Number of REGISTRATION_PATTERN_UUID_UNRESOLVED findings")
    candidate_only_count: int = Field(..., description="Number of UUID_CANDIDATE_ONLY findings")
    findings: List[RegistrationFinding] = Field(default_factory=list, description="All evaluated findings")
    blind_spots_and_limitations: List[str] = Field(default_factory=list, description="Explicit known blind spots and analysis constraints")
