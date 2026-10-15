"""UCSD Phase 3: Conservative, evidence-grounded registration detection."""

from ucsd.registration.detector import detect_gatt_registrations, KNOWN_BLIND_SPOTS
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

__all__ = [
    "detect_gatt_registrations",
    "trace_method_registrations",
    "EvidenceLevel",
    "UnresolvedReason",
    "TraceStep",
    "ServiceConstructionSite",
    "AddServiceCallSite",
    "RegistrationFinding",
    "RegistrationAnalysisResult",
    "KNOWN_BLIND_SPOTS",
]
