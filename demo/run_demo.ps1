# =====================================================================
# UCSD Demo Script (Windows PowerShell)
# Universal Candidate Service Detector: Static BLE & GATT Analysis Demo
# =====================================================================

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  UCSD: Universal Candidate Service Detector - Demo Workflow     " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# Ensure reports directory exists
if (-not (Test-Path -Path "reports")) {
    New-Item -ItemType Directory -Path "reports" | Out-Null
}

Write-Host "[Step 1/4] Analyzing Positive GATT Service Registration (service_a.apk)..." -ForegroundColor Yellow
docker compose run --rm ucsd python -m ucsd.cli analyze /app/demo/inputs/service_a.apk --out /app/reports
Write-Host "-> Check reports/ for service_a HTML and JSON reports." -ForegroundColor Green
Write-Host ""

Write-Host "[Step 2/4] Analyzing Client-Only BLE Application (client_only.apk)..." -ForegroundColor Yellow
docker compose run --rm ucsd python -m ucsd.cli analyze /app/demo/inputs/client_only.apk --out /app/reports
Write-Host "-> Demonstrates rejection of false-positive service registration." -ForegroundColor Green
Write-Host ""

Write-Host "[Step 3/4] Multi-APK Batch Analysis across demo/inputs/..." -ForegroundColor Yellow
docker compose run --rm ucsd python -m ucsd.cli batch /app/demo/inputs --out /app/reports/demo_batch
Write-Host "-> Demonstrates cross-APK static duplicate registration conflict detection." -ForegroundColor Green
Write-Host "-> Open reports/demo_batch/batch_report.html in your browser." -ForegroundColor Green
Write-Host ""

Write-Host "[Step 4/4] Cross-APK Comparison Workflow (service_a vs service_b)..." -ForegroundColor Yellow
docker compose run --rm ucsd python -m ucsd.cli compare /app/demo/inputs/service_a.apk /app/demo/inputs/service_b.apk --out /app/reports/demo_conflict_report.json
Write-Host "-> Saved conflict report to reports/demo_conflict_report.json & .html" -ForegroundColor Green
Write-Host ""

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Demo Complete! All reports generated in ./reports/             " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
