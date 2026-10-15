"""Analyst-facing reporting package for UCSD."""

from ucsd.reporting.models import SingleAPKSummary, BatchAnalysisReport
from ucsd.reporting.html_generator import (
    esc,
    generate_single_apk_html_report,
    generate_batch_html_report,
    generate_conflict_html_report,
)

__all__ = [
    "SingleAPKSummary",
    "BatchAnalysisReport",
    "esc",
    "generate_single_apk_html_report",
    "generate_batch_html_report",
    "generate_conflict_html_report",
]
