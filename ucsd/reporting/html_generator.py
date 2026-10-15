"""Standalone HTML report generator for UCSD static analysis.

Produces self-contained, offline-capable, responsive HTML reports with complete
escaping of APK-controlled strings and no external runtime dependencies.
"""

import html
from typing import Any, List, Optional
from ucsd.conflict.models import ConflictCondition, CrossAPKConflictReport
from ucsd.models import AnalysisReport
from ucsd.reporting.models import BatchAnalysisReport


def esc(val: Any) -> str:
    """Safely escape any value for inclusion in HTML attributes or text content."""
    if val is None:
        return ""
    if hasattr(val, "value"):
        val = val.value
    return html.escape(str(val), quote=True)



_BASE_CSS = """
:root {
  --bg-main: #0b0f19;
  --bg-card: #151e32;
  --bg-card-sub: #1a253e;
  --bg-code: #0d1322;
  --border-color: #23324d;
  --border-light: #2e4166;
  --text-main: #f1f5f9;
  --text-muted: #94a3b8;
  --text-dim: #64748b;
  --accent-blue: #38bdf8;
  --accent-green: #10b981;
  --accent-amber: #f59e0b;
  --accent-red: #ef4444;
  --accent-purple: #a855f7;
  --accent-indigo: #818cf8;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background-color: var(--bg-main);
  color: var(--text-main);
  line-height: 1.5;
  padding: 1.5rem;
}
.container { max-width: 1300px; margin: 0 auto; }

/* Header Banner */
header {
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1.5rem 2rem;
  margin-bottom: 1.5rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
}
.header-title h1 {
  font-size: 1.5rem;
  font-weight: 700;
  color: #fff;
  letter-spacing: -0.025em;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.header-title p {
  color: var(--text-muted);
  font-size: 0.875rem;
  margin-top: 0.25rem;
}
.header-meta {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 0.25rem 0.65rem;
  font-size: 0.75rem;
  font-weight: 600;
  border-radius: 9999px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.badge-success { background-color: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
.badge-danger { background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
.badge-warning { background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
.badge-info { background-color: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
.badge-purple { background-color: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
.badge-secondary { background-color: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid var(--border-light); }

/* Metrics Grid */
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.metric-card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1rem 1.25rem;
}
.metric-title {
  color: var(--text-muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 600;
}
.metric-val {
  font-size: 1.5rem;
  font-weight: 700;
  color: #fff;
  margin-top: 0.25rem;
  font-family: "SFMono-Regular", Consolas, monospace;
}
.metric-sub {
  font-size: 0.75rem;
  color: var(--text-dim);
  margin-top: 0.25rem;
}

/* Cards & Sections */
.card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border-color);
}
.card-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

/* Callouts / Banners */
.alert {
  padding: 1rem 1.25rem;
  border-radius: 6px;
  margin-bottom: 1rem;
  font-size: 0.875rem;
}
.alert-danger {
  background-color: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: #fca5a5;
}
.alert-warning {
  background-color: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.3);
  color: #fde68a;
}
.alert-info {
  background-color: rgba(56, 189, 248, 0.1);
  border: 1px solid rgba(56, 189, 248, 0.3);
  color: #bae6fd;
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
  margin-top: 0.5rem;
}
th, td {
  padding: 0.65rem 0.85rem;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
}
th {
  background-color: var(--bg-card-sub);
  color: var(--text-muted);
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
tr:hover td {
  background-color: rgba(255, 255, 255, 0.02);
}
.mono {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 0.8125rem;
}
.hash-pill {
  background: var(--bg-code);
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  border: 1px solid var(--border-color);
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 0.8rem;
  word-break: break-all;
}

/* Details and Lists */
details {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  margin-top: 0.5rem;
  padding: 0.5rem 1rem;
}
summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--accent-blue);
  padding: 0.25rem 0;
}
.details-content {
  padding-top: 0.75rem;
  font-size: 0.8125rem;
}

.chip-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
}
.chip {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-light);
  border-radius: 4px;
  padding: 0.25rem 0.5rem;
  font-size: 0.8rem;
  font-family: "SFMono-Regular", Consolas, monospace;
}

/* Limitations */
.limitations-list {
  list-style-type: disc;
  padding-left: 1.5rem;
  font-size: 0.875rem;
  color: var(--text-muted);
}
.limitations-list li {
  margin-bottom: 0.5rem;
}

footer {
  text-align: center;
  color: var(--text-dim);
  font-size: 0.75rem;
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}
"""


def _render_header(
    title: str,
    target: str,
    status: str,
    timestamp: str,
    analyzer_version: str,
    kb_version: Optional[str] = None,
) -> str:
    status_lower = status.lower()
    if status_lower == "success":
        badge_cls = "badge-success"
    elif status_lower == "partial":
        badge_cls = "badge-warning"
    else:
        badge_cls = "badge-danger"

    kb_badge = (
        f'<span class="badge badge-purple">KB v{esc(kb_version)}</span>'
        if kb_version
        else '<span class="badge badge-secondary">KB: N/A</span>'
    )

    return f"""
<header>
  <div class="header-title">
    <h1>{esc(title)}</h1>
    <p>Target: <span class="mono">{esc(target)}</span> &bull; Analyzed at {esc(timestamp)} UTC</p>
  </div>
  <div class="header-meta">
    <span class="badge {badge_cls}">Status: {esc(status)}</span>
    <span class="badge badge-info">Analyzer v{esc(analyzer_version)}</span>
    {kb_badge}
  </div>
</header>
"""


def _render_limitations(limitations: List[str]) -> str:
    if not limitations:
        return ""
    items = "".join(f"<li>{esc(lim)}</li>" for lim in limitations)
    return f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">Analytical Boundaries & Methodological Limitations</div>
  </div>
  <ul class="limitations-list">
    {items}
  </ul>
</div>
"""


def generate_single_apk_html_report(report: AnalysisReport) -> str:
    """Generate a self-contained, offline HTML report for a single APK analysis."""
    meta = report.metadata
    ble = report.ble_analysis
    reg = report.registration_analysis
    kb = report.knowledge_base_assessment
    err = report.error

    title = f"UCSD APK Analysis: {meta.file_name}" if meta else "UCSD APK Analysis Report"
    target_display = report.target
    timestamp = report.timestamp
    version = report.analyzer_version
    kb_ver = report.knowledge_base_version

    header_html = _render_header(
        title=title,
        target=target_display,
        status=report.status,
        timestamp=timestamp,
        analyzer_version=version,
        kb_version=kb_ver,
    )

    # 1. Error Banner (if error / failed)
    error_section = ""
    if err:
        err_type = esc(err.get("error_type", "Error"))
        err_msg = esc(err.get("message", "An error occurred during analysis"))
        err_details = esc(err.get("details", ""))
        details_html = f"<pre class='details-content'>{err_details}</pre>" if err_details else ""
        error_section = f"""
<div class="alert alert-danger">
  <strong>Analysis Error ({err_type}):</strong> {err_msg}
  {details_html}
</div>
"""

    # 2. Metrics Grid
    if meta:
        cand_count = len(ble.uuid_candidates) if ble else 0
        strong_count = reg.strong_associations_count if reg else 0
        perm_count = len(meta.manifest.requested_permissions) if meta.manifest else 0
        file_size_mb = f"{meta.file_size_bytes / (1024 * 1024):.2f} MB"
        metrics_html = f"""
<div class="metrics-grid">
  <div class="metric-card">
    <div class="metric-title">Package ID</div>
    <div class="metric-val" style="font-size: 1.1rem; word-break: break-all;">{esc(meta.manifest.package_name if meta.manifest else "Unknown")}</div>
    <div class="metric-sub">Version: {esc(meta.manifest.version_name if meta.manifest else "N/A")} ({esc(meta.manifest.version_code if meta.manifest else 0)})</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Archive Size</div>
    <div class="metric-val">{esc(file_size_mb)}</div>
    <div class="metric-sub">{meta.dex_count} DEX file(s) (Multi-DEX: {meta.is_multidex})</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Permissions</div>
    <div class="metric-val">{perm_count}</div>
    <div class="metric-sub">Declared: {len(meta.manifest.declared_permissions) if meta.manifest else 0}</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">UUID Candidates</div>
    <div class="metric-val">{cand_count}</div>
    <div class="metric-sub">Extracted from DEX files</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">GATT Registrations</div>
    <div class="metric-val" style="color: {'#34d399' if strong_count > 0 else '#94a3b8'};">{strong_count}</div>
    <div class="metric-sub">Strong static associations</div>
  </div>
</div>
"""
    else:
        metrics_html = ""

    # 3. APK & Intake Metadata Card
    intake_card = ""
    if meta:
        manifest = meta.manifest
        pkg = esc(manifest.package_name if manifest else "N/A")
        vcode = esc(manifest.version_code if manifest else "N/A")
        vname = esc(manifest.version_name if manifest else "N/A")
        min_sdk = esc(manifest.min_sdk_version if manifest else "N/A")
        tgt_sdk = esc(manifest.target_sdk_version if manifest else "N/A")
        main_act = esc(manifest.main_activity if manifest else "None")

        dex_rows = "".join(
            f"<tr><td class='mono'>{esc(d.name)}</td><td class='mono'>{esc(d.sha256)}</td><td>{d.size_bytes} B</td></tr>"
            for d in sorted(meta.dex_files, key=lambda x: x.name)
        )

        intake_card = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">APK Intake & Manifest Integrity</div>
    <span class="badge badge-secondary">SHA-256</span>
  </div>
  <p style="margin-bottom: 1rem;"><span class="hash-pill">{esc(meta.sha256)}</span></p>
  <table>
    <thead>
      <tr><th>Property</th><th>Value</th><th>Property</th><th>Value</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Package Name</strong></td><td class="mono">{pkg}</td>
        <td><strong>Version</strong></td><td>{vname} (code: {vcode})</td>
      </tr>
      <tr>
        <td><strong>Min SDK</strong></td><td>{min_sdk}</td>
        <td><strong>Target SDK</strong></td><td>{tgt_sdk}</td>
      </tr>
      <tr>
        <td><strong>Main Activity</strong></td><td colspan="3" class="mono">{main_act}</td>
      </tr>
    </tbody>
  </table>

  <details>
    <summary>DEX File Inventory ({len(meta.dex_files)} files)</summary>
    <table>
      <thead><tr><th>DEX Name</th><th>SHA-256</th><th>Size</th></tr></thead>
      <tbody>{dex_rows}</tbody>
    </table>
  </details>
</div>
"""

    # 4. Bluetooth & BLE Indicators Card
    ble_card = ""
    if ble:
        perm_chips = ""
        for p in sorted(ble.permissions.requested):
            tag = "[BLE]" if any(x in p.lower() for x in ["scan", "connect", "advertise"]) else "[Classic]"
            cls = "badge-info" if "[BLE]" in tag else "badge-secondary"
            perm_chips += f'<span class="badge {cls}">{esc(p)} {tag}</span> '

        if not perm_chips:
            perm_chips = "<span style='color: var(--text-muted);'>No Bluetooth permissions requested.</span>"

        api_ind = ble.api_indicators
        api_chips = f"""
<div class="chip-list">
  <span class="badge {'badge-success' if api_ind.has_gatt_server else 'badge-secondary'}">GATT Server: {api_ind.has_gatt_server}</span>
  <span class="badge {'badge-info' if api_ind.has_gatt_client else 'badge-secondary'}">GATT Client: {api_ind.has_gatt_client}</span>
  <span class="badge {'badge-info' if api_ind.has_le_scanner else 'badge-secondary'}">LE Scanner: {api_ind.has_le_scanner}</span>
  <span class="badge {'badge-info' if api_ind.has_le_advertiser else 'badge-secondary'}">LE Advertiser: {api_ind.has_le_advertiser}</span>
</div>
"""

        fw_classes = "".join(f"<li><span class='mono'>{esc(c)}</span></li>" for c in api_ind.framework_classes[:10])
        app_classes = "".join(f"<li><span class='mono'>{esc(c)}</span></li>" for c in api_ind.app_classes[:10])

        ble_card = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">Bluetooth &amp; BLE Static Indicators (Phase 2)</div>
  </div>
  <div style="margin-bottom: 1rem;">
    <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 0.25rem;">Bluetooth Permissions</div>
    <div class="chip-list">{perm_chips}</div>
  </div>

  <div style="margin-bottom: 1rem;">
    <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 0.25rem;">API Framework Capabilities</div>
    {api_chips}
  </div>

  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; margin-top: 1rem;">
    <details>
      <summary>Framework Classes Referenced ({len(api_ind.framework_classes)})</summary>
      <ul style="padding-left: 1.25rem; margin-top: 0.5rem; font-size: 0.8125rem;">{fw_classes}</ul>
    </details>
    <details>
      <summary>Application BLE Classes ({len(api_ind.app_classes)})</summary>
      <ul style="padding-left: 1.25rem; margin-top: 0.5rem; font-size: 0.8125rem;">{app_classes}</ul>
    </details>
  </div>
</div>
"""

    # 5. GATT Service Registration Card
    reg_card = ""
    if reg:
        strong_findings = [f for f in reg.findings if f.evidence_level == "STRONG_STATIC_ASSOCIATION"]
        unres_findings = [f for f in reg.findings if f.evidence_level == "REGISTRATION_PATTERN_UUID_UNRESOLVED"]

        banner = ""
        if strong_findings:
            banner = f"""
<div class="alert alert-danger">
  <strong>HIGH-CONFIDENCE STATIC REGISTRATIONS DETECTED:</strong> This APK statically constructs and registers {len(strong_findings)} GATT service(s) via verified Dalvik register data-flow to <code>BluetoothGattServer.addService()</code>.
</div>
"""

        finding_rows = ""
        for f in reg.findings:
            if f.evidence_level == "STRONG_STATIC_ASSOCIATION":
                badge = '<span class="badge badge-danger">STRONG STATIC</span>'
            elif f.evidence_level == "REGISTRATION_PATTERN_UUID_UNRESOLVED":
                badge = f'<span class="badge badge-warning">UNRESOLVED ({esc(f.unresolved_reason)})</span>'
            else:
                badge = '<span class="badge badge-secondary">CANDIDATE ONLY</span>'

            loc = f"{esc(f.class_name)}::{esc(f.method_name)}" if f.class_name else "N/A"
            uuid_disp = esc(f.normalized_uuid or "Unresolved")

            # Trace steps breakdown
            trace_html = ""
            if f.trace_steps:
                steps_rows = "".join(
                    f"<tr><td>{s.step_index}</td><td class='mono'>{f'+0x{s.instruction_offset:04x}' if s.instruction_offset is not None else 'N/A'}</td><td class='mono'>{esc(s.opcode)}</td><td>{esc(s.step_type)}</td></tr>"
                    for s in f.trace_steps
                )
                trace_html = f"""
<details style="margin-top: 0.5rem;">
  <summary>Dalvik Register Trace ({len(f.trace_steps)} steps)</summary>
  <table>
    <thead><tr><th>#</th><th>Offset</th><th>Opcode</th><th>Action</th></tr></thead>
    <tbody>{steps_rows}</tbody>
  </table>
</details>
"""

            finding_rows += f"""
<tr>
  <td>{badge}</td>
  <td class="mono">{uuid_disp}</td>
  <td class="mono">{loc}</td>
  <td>{esc(f.diagnosis)}{trace_html}</td>
</tr>
"""

        if not finding_rows:
            finding_rows = "<tr><td colspan='4' style='text-align: center; color: var(--text-muted);'>No GATT service registration call sites detected.</td></tr>"

        reg_card = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">GATT Service Registration Analysis (Phase 3)</div>
    <span class="badge badge-info">{reg.total_add_service_calls} addService calls</span>
  </div>
  {banner}
  <table>
    <thead>
      <tr><th>Evidence Level</th><th>UUID</th><th>Method Location</th><th>Diagnosis & Trace</th></tr>
    </thead>
    <tbody>
      {finding_rows}
    </tbody>
  </table>
</div>
"""

    # 6. UUID Candidates & Knowledge Base Card
    cand_card = ""
    if kb and kb.findings:
        sorted_findings = sorted(kb.findings, key=lambda x: x.normalized_uuid)
        cand_rows = ""
        for f in sorted_findings:
            u = esc(f.normalized_uuid)
            cond = f.condition
            if cond == ConflictCondition.KNOWN_ASSIGNED_STANDARD_MATCH:
                badge = '<span class="badge badge-success">Bluetooth SIG</span>'
            elif cond == ConflictCondition.KNOWN_SYSTEM_OR_VENDOR_MATCH:
                badge = '<span class="badge badge-purple">System / Vendor</span>'
            elif cond == ConflictCondition.STRONG_DUPLICATE_STATIC_REGISTRATION:
                badge = '<span class="badge badge-danger">Strong Overlap</span>'
            else:
                badge = '<span class="badge badge-secondary">Unknown</span>'

            kb_info = ""
            if f.knowledge_base_match:
                entry = f.knowledge_base_match
                url_link = f"<a href='{esc(entry.source_url)}' target='_blank' style='color: var(--accent-blue);'>{esc(entry.source_name)}</a>"
                kb_info = f"<strong>{esc(entry.name)}</strong> ({url_link}) &bull; {esc(entry.analyst_notes)}"
            else:
                kb_info = "<span style='color: var(--text-dim);'>No curated knowledge base record</span>"

            ev_count = len(f.participating_apks)
            sample_loc = ""
            if f.participating_apks and f.participating_apks[0].class_name:
                sample_loc = f"<br><span class='mono' style='font-size: 0.75rem; color: var(--text-muted);'>{esc(f.participating_apks[0].class_name)}::{esc(f.participating_apks[0].method_name or '')}</span>"

            cand_rows += f"""
<tr>
  <td class="mono">{u}</td>
  <td>{badge}</td>
  <td>{kb_info}{sample_loc}</td>
</tr>
"""

        cand_card = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">UUID Knowledge Base & Candidate Findings (Phase 4)</div>
    <span class="badge badge-info">{len(sorted_findings)} Candidates</span>
  </div>
  <table>
    <thead>
      <tr><th>Normalized 128-bit UUID</th><th>Category</th><th>Provenance & Technical Context</th></tr>
    </thead>
    <tbody>
      {cand_rows}
    </tbody>
  </table>
</div>
"""
    elif ble and ble.uuid_candidates:
        cand_rows = ""
        for c in sorted(ble.uuid_candidates, key=lambda x: x.normalized_uuid):
            type_str = "Bluetooth SIG" if c.is_bluetooth_sig_range else "Custom 128-bit"
            badge = '<span class="badge badge-success">SIG</span>' if c.is_bluetooth_sig_range else '<span class="badge badge-secondary">128-bit</span>'
            cand_rows += f"<tr><td class='mono'>{esc(c.normalized_uuid)}</td><td>{badge}</td><td>{c.occurrence_count} location(s)</td></tr>"
        cand_card = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">UUID Candidates ({len(ble.uuid_candidates)} unique)</div>
  </div>
  <table>
    <thead><tr><th>Normalized UUID</th><th>Format</th><th>Occurrences</th></tr></thead>
    <tbody>{cand_rows}</tbody>
  </table>
</div>
"""

    limitations_html = _render_limitations(report.limitations)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{esc(title)}</title>
  <style>{_BASE_CSS}</style>
</head>
<body>
  <div class="container">
    {header_html}
    {error_section}
    {metrics_html}
    {intake_card}
    {ble_card}
    {reg_card}
    {cand_card}
    {limitations_html}
    <footer>
      Generated by UCSD (UUID Confusion Static Detection) &bull; Standalone Offline Report
    </footer>
  </div>
</body>
</html>
"""


def generate_batch_html_report(batch_report: BatchAnalysisReport) -> str:
    """Generate a self-contained, offline HTML report for batch analysis and cross-comparison."""
    title = f"UCSD Multi-APK Batch Assessment ({batch_report.total_targets} APKs)"
    timestamp = batch_report.timestamp
    version = batch_report.analyzer_version
    kb_ver = batch_report.knowledge_base_version

    header_html = _render_header(
        title=title,
        target=batch_report.target_directory or "Batch Targets",
        status=batch_report.status,
        timestamp=timestamp,
        analyzer_version=version,
        kb_version=kb_ver,
    )

    conf = batch_report.cross_apk_conflicts
    strong_conflicts = conf.strong_duplicate_static_registrations_count if conf else 0
    dup_candidates = conf.duplicate_candidates_unregistered_count if conf else 0
    std_matches = conf.known_standard_matches_count if conf else 0
    vendor_matches = conf.known_system_vendor_matches_count if conf else 0

    metrics_html = f"""
<div class="metrics-grid">
  <div class="metric-card">
    <div class="metric-title">Total Targets</div>
    <div class="metric-val">{batch_report.total_targets}</div>
    <div class="metric-sub">{batch_report.successful_count} passed, {batch_report.failed_count} failed</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Strong Static Overlaps</div>
    <div class="metric-val" style="color: {'#f87171' if strong_conflicts > 0 else '#94a3b8'};">{strong_conflicts}</div>
    <div class="metric-sub">Dual verified GATT registrations</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Candidate String Duplicates</div>
    <div class="metric-val">{dup_candidates}</div>
    <div class="metric-sub">Without dual static registration</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Sourced Standards (SIG)</div>
    <div class="metric-val" style="color: #34d399;">{std_matches}</div>
    <div class="metric-sub">Bluetooth SIG specifications</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Vendor / System Matches</div>
    <div class="metric-val" style="color: #c084fc;">{vendor_matches}</div>
    <div class="metric-sub">Sourced OS/Hardware specs</div>
  </div>
</div>
"""

    # 1. Strong Duplicate Static Registrations Section
    strong_section = ""
    if conf and strong_conflicts > 0:
        strong_items = ""
        for ass in conf.assessments:
            if ass.condition == ConflictCondition.STRONG_DUPLICATE_STATIC_REGISTRATION:
                u = esc(ass.normalized_uuid)
                diag = esc(ass.explanation)
                app_rows = "".join(
                    f"<tr><td class='mono'><strong>{esc(ev.package_name or ev.file_name)}</strong></td><td class='mono'>{esc(ev.sha256[:12])}...</td><td class='mono'>{esc(ev.class_name)}::{esc(ev.method_name)}</td><td class='mono'>{f'+0x{ev.instruction_offset:04x}' if ev.instruction_offset is not None else 'N/A'}</td><td>{esc(ev.diagnosis)}</td></tr>"
                    for ev in ass.participating_apks
                )
                strong_items += f"""
<div style="background-color: var(--bg-card-sub); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 6px; padding: 1rem; margin-bottom: 1rem;">
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
    <span class="mono" style="font-size: 1.1rem; font-weight: 700; color: #f87171;">{u}</span>
    <span class="badge badge-danger">HIGH-CONFIDENCE STATIC OVERLAP</span>
  </div>
  <p style="font-size: 0.875rem; color: #fca5a5; margin-bottom: 0.75rem;">{diag}</p>
  <table>
    <thead><tr><th>Package ID</th><th>SHA-256</th><th>Declaring Method</th><th>Offset</th><th>Static Evidence</th></tr></thead>
    <tbody>{app_rows}</tbody>
  </table>
</div>
"""
        strong_section = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title" style="color: #f87171;">Strong Duplicate Static Registrations (High-Confidence Overlap)</div>
    <span class="badge badge-danger">{strong_conflicts} Conflict(s)</span>
  </div>
  <div class="alert alert-warning" style="margin-bottom: 1rem;">
    <strong>Interpretation Note:</strong> Two distinct APK packages contain verified intra-method Dalvik register data-flow associating the identical UUID with GATT service registration. This is a high-confidence static overlap and may warrant runtime/host-context validation. It does NOT constitute proof of runtime vulnerability or confirmed service squatting.
  </div>
  {strong_items}
</div>
"""

    # 2. Duplicate Candidate Strings Without Dual Registration
    dup_section = ""
    if conf and dup_candidates > 0:
        dup_rows = ""
        for ass in conf.assessments:
            if ass.condition == ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION:
                pkgs = ", ".join(sorted({esc(ev.package_name or ev.file_name) for ev in ass.participating_apks}))
                dup_rows += f"""
<tr>
  <td class="mono">{esc(ass.normalized_uuid)}</td>
  <td><span class="badge badge-secondary">DUPLICATE STRINGS</span></td>
  <td>{len(ass.participating_apks)} APKs ({pkgs})</td>
  <td style="color: var(--text-muted);">{esc(ass.explanation)}</td>
</tr>
"""
        dup_section = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">Duplicate Candidate Strings (No Dual Static Registration)</div>
    <span class="badge badge-secondary">{dup_candidates} Shared UUIDs</span>
  </div>
  <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1rem;">
    Identical candidate strings discovered across multiple APKs without verified dual GATT service registration. This is commonly caused by shared third-party SDKs, utility libraries, or constant pools and is explicitly <strong>not</strong> presented as proven service conflicts.
  </p>
  <table>
    <thead><tr><th>Candidate UUID</th><th>Category</th><th>Participating APKs</th><th>Evaluation</th></tr></thead>
    <tbody>{dup_rows}</tbody>
  </table>
</div>
"""

    # 3. APK Inventory Matrix
    apk_rows = ""
    for apk in sorted(batch_report.apk_summaries, key=lambda x: x.file_name):
        report_link = ""
        if apk.report_html_path:
            report_link = f"<a href='{esc(apk.report_html_path)}' style='color: var(--accent-blue); margin-left: 0.5rem;'>[HTML]</a>"
        if apk.report_json_path:
            report_link += f"<a href='{esc(apk.report_json_path)}' style='color: var(--accent-blue); margin-left: 0.5rem;'>[JSON]</a>"

        apk_rows += f"""
<tr>
  <td class="mono"><strong>{esc(apk.file_name)}</strong>{report_link}</td>
  <td class="mono">{esc(apk.package_name or 'N/A')}</td>
  <td>{esc(apk.version_name or 'N/A')} ({esc(apk.version_code or 0)})</td>
  <td class="mono">{esc(apk.sha256[:16])}...</td>
  <td>{apk.candidate_count}</td>
  <td style="color: {'#34d399' if apk.strong_registrations_count > 0 else '#94a3b8'};">{apk.strong_registrations_count}</td>
  <td><span class="badge {'badge-success' if apk.status == 'success' else 'badge-warning'}">{esc(apk.status)}</span></td>
</tr>
"""

    inventory_card = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title">Analyzed APK Inventory Matrix</div>
    <span class="badge badge-info">{len(batch_report.apk_summaries)} Successful</span>
  </div>
  <table>
    <thead>
      <tr><th>APK File Name</th><th>Package ID</th><th>Version</th><th>SHA-256</th><th>Candidates</th><th>Registrations</th><th>Status</th></tr>
    </thead>
    <tbody>
      {apk_rows}
    </tbody>
  </table>
</div>
"""

    # 4. Failed Targets Card (if any)
    failed_card = ""
    if batch_report.failed_targets:
        failed_rows = "".join(
            f"<tr><td class='mono'>{esc(f.get('target', ''))}</td><td><span class='badge badge-danger'>{esc(f.get('error_type', 'Error'))}</span></td><td>{esc(f.get('message', ''))}</td></tr>"
            for f in batch_report.failed_targets
        )
        failed_card = f"""
<div class="card">
  <div class="card-header">
    <div class="card-title" style="color: #f87171;">Failed Target Ingestion ({len(batch_report.failed_targets)})</div>
    <span class="badge badge-danger">Intake Errors</span>
  </div>
  <table>
    <thead><tr><th>Target Path</th><th>Error Type</th><th>Details</th></tr></thead>
    <tbody>{failed_rows}</tbody>
  </table>
</div>
"""

    limitations_html = _render_limitations(batch_report.limitations)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{esc(title)}</title>
  <style>{_BASE_CSS}</style>
</head>
<body>
  <div class="container">
    {header_html}
    {metrics_html}
    {strong_section}
    {dup_section}
    {inventory_card}
    {failed_card}
    {limitations_html}
    <footer>
      Generated by UCSD (UUID Confusion Static Detection) &bull; Standalone Batch Report
    </footer>
  </div>
</body>
</html>
"""


def generate_conflict_html_report(report: CrossAPKConflictReport) -> str:
    """Convenience wrapper converting CrossAPKConflictReport to HTML report."""
    batch_rep = BatchAnalysisReport(
        status="success",
        timestamp=report.knowledge_base_metadata.last_updated,
        analyzer_version="0.1.0",
        knowledge_base_version=report.knowledge_base_metadata.knowledge_base_version,
        target_directory="Multi-APK Comparison",
        total_targets=report.total_apks_analyzed,
        successful_count=report.total_apks_analyzed,
        failed_count=0,
        apk_summaries=[],
        cross_apk_conflicts=report,
        failed_targets=[],
        limitations=report.methodology_and_limitations,
    )
    return generate_batch_html_report(batch_rep)
