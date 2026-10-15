#!/usr/bin/env bash
# =====================================================================
# UCSD Demo Script (POSIX Shell / Bash)
# Universal Candidate Service Detector: Static BLE & GATT Analysis Demo
# =====================================================================

set -euo pipefail

echo "================================================================="
echo "  UCSD: Universal Candidate Service Detector - Demo Workflow     "
echo "================================================================="
echo ""

mkdir -p reports

echo "[Step 1/4] Analyzing Positive GATT Service Registration (service_a.apk)..."
docker compose run --rm ucsd python -m ucsd.cli analyze /app/demo/inputs/service_a.apk --out /app/reports
echo "-> Check reports/ for service_a HTML and JSON reports."
echo ""

echo "[Step 2/4] Analyzing Client-Only BLE Application (client_only.apk)..."
docker compose run --rm ucsd python -m ucsd.cli analyze /app/demo/inputs/client_only.apk --out /app/reports
echo "-> Demonstrates rejection of false-positive service registration."
echo ""

echo "[Step 3/4] Multi-APK Batch Analysis across demo/inputs/..."
docker compose run --rm ucsd python -m ucsd.cli batch /app/demo/inputs --out /app/reports/demo_batch
echo "-> Demonstrates cross-APK static duplicate registration conflict detection."
echo "-> Open reports/demo_batch/batch_report.html in your browser."
echo ""

echo "[Step 4/4] Cross-APK Comparison Workflow (service_a vs service_b)..."
docker compose run --rm ucsd python -m ucsd.cli compare /app/demo/inputs/service_a.apk /app/demo/inputs/service_b.apk --out /app/reports/demo_conflict_report.json
echo "-> Saved conflict report to reports/demo_conflict_report.json & .html"
echo ""

echo "================================================================="
echo "  Demo Complete! All reports generated in ./reports/             "
echo "================================================================="
