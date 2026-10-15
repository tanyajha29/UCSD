"""UUID conflict assessment and cross-APK comparison package."""

from ucsd.conflict.assessor import (
    METHODOLOGY_NOTES,
    assess_single_apk,
    compare_apks,
)
from ucsd.conflict.models import (
    ConflictCondition,
    CrossAPKEvidence,
    CrossAPKConflictReport,
    SingleAPKKnowledgeAssessment,
    UUIDConflictAssessment,
)

__all__ = [
    "ConflictCondition",
    "CrossAPKEvidence",
    "UUIDConflictAssessment",
    "SingleAPKKnowledgeAssessment",
    "CrossAPKConflictReport",
    "METHODOLOGY_NOTES",
    "assess_single_apk",
    "compare_apks",
]
