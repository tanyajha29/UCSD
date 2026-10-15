import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  ExternalLink,
  Search,
  FileCode,
  FileJson,
  Layers,
  Database,
  ArrowRight,
} from 'lucide-react';
import { api } from '../api/client';
import { AnalysisSummary } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<AnalysisSummary[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'failed'>('all');

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await api.listAnalyses(1, 100);
        const validReports = data.items.filter((i) => i.report_json_path || i.report_html_path);
        setReports(validReports);
        if (validReports.length > 0) {
          setSelectedReportId(validReports[0].id);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to load report archive');
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

  const filtered = reports.filter((r) => {
    const matchesSearch =
      r.file_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.package_name && r.package_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (r.sha256 && r.sha256.toLowerCase().includes(searchTerm.toLowerCase()));
    
    if (statusFilter === 'all') return matchesSearch;
    return matchesSearch && r.status === statusFilter;
  });

  const selectedReport = reports.find((r) => r.id === selectedReportId);

  const downloadAllManifest = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(reports, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `ucsd_forensic_archive_index_${new Date().toISOString().substring(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      
      {/* 1. Top Forensic Archive Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#1A2332] pb-6">
        <div>
          <div className="flex items-center space-x-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-[#00E5A0]" />
            <span className="text-[11px] font-mono tracking-tracked text-[#7A8794] uppercase font-semibold">
              FORENSIC REPORT REPOSITORY & EXPORTS
            </span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#E8EDF2]">
            Evidence Archive & Standalone Artifacts
          </h1>
          <p className="text-xs text-[#7A8794] mt-1 font-mono">
            Immutable offline HTML dashboards and deterministic JSON reports generated from Dalvik register traces.
          </p>
        </div>

        {/* Download Archive Index Terminal Button */}
        <button
          onClick={downloadAllManifest}
          disabled={reports.length === 0}
          className="btn-terminal px-4 py-2.5 rounded border border-[#1A2332] bg-[#0B0F14] hover:border-[#00E5A0] hover:text-[#00E5A0] text-[#C5D0DA] text-xs font-mono inline-flex items-center space-x-2 transition-all self-start sm:self-auto shrink-0"
        >
          <Download className="w-3.5 h-3.5" />
          <span>&gt; EXPORT REPOSITORY MANIFEST</span>
        </button>
      </div>

      {error && <ErrorBanner title="ARCHIVE ERROR" message={error} onDismiss={() => setError(null)} />}

      {/* 2. Filter & Search Controls */}
      <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg p-3 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-96">
          <Search className="w-3.5 h-3.5 text-[#7A8794] absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by binary name, package, or SHA-256..."
            className="w-full pl-9 pr-3 py-1.5 bg-[#05070A] border border-[#1A2332] rounded text-xs font-mono text-[#E8EDF2] placeholder-[#7A8794] focus:outline-none focus:border-[#00E5A0]"
          />
        </div>

        <div className="flex items-center space-x-1.5 w-full sm:w-auto">
          {(['all', 'success', 'failed'] as const).map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1 rounded text-[11px] font-mono uppercase transition-colors ${
                statusFilter === s
                  ? 'bg-[#11171F] border border-[#00E5A0] text-[#00E5A0]'
                  : 'bg-[#05070A] border border-[#1A2332] text-[#7A8794] hover:text-[#C5D0DA]'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* 3. Two-Column Forensic Archive Layout */}
      {loading ? (
        <LoadingSpinner message="INDEXING ARCHIVED FORENSIC ARTIFACTS..." size="lg" />
      ) : filtered.length === 0 ? (
        <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg p-12 text-center text-[#7A8794] space-y-3 font-mono">
          <FileCode className="w-8 h-8 mx-auto text-[#7A8794]/60" />
          <p className="text-xs uppercase">NO REPORT ARTIFACTS FOUND MATCHING QUERY</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Left Column: Filterable List (5 cols) */}
          <div className="lg:col-span-5 space-y-2 max-h-[700px] overflow-y-auto pr-1 scrollbar-thin">
            {filtered.map((item) => {
              const isSelected = item.id === selectedReportId;
              const isSuccess = item.status === 'success';

              return (
                <div
                  key={item.id}
                  onClick={() => setSelectedReportId(item.id)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all duration-150 ${
                    isSelected
                      ? 'bg-[#11171F] border-[#00E5A0] shadow-[0_0_12px_rgba(0,229,160,0.15)]'
                      : 'bg-[#0B0F14] border-[#1A2332] hover:border-[#2A3A4F]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-medium text-[#E8EDF2] truncate max-w-[220px]" title={item.file_name}>
                      {item.file_name}
                    </span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded ${
                      isSuccess ? 'bg-[#00E5A0]/10 text-[#00E5A0] border border-[#00E5A0]/40' : 'bg-[#FF3B5C]/10 text-[#FF3B5C]'
                    }`}>
                      {item.status.toUpperCase()}
                    </span>
                  </div>

                  <div className="text-[11px] font-mono text-[#7A8794] truncate mb-2">
                    {item.package_name || 'UNRESOLVED PACKAGE'}
                  </div>

                  {item.sha256 && (
                    <div className="text-[10px] font-mono text-[#7A8794] mb-2 truncate">
                      SHA: {item.sha256.substring(0, 16)}...
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-2 border-t border-[#1A2332]/60 text-[10px] font-mono">
                    <div className="flex items-center space-x-2">
                      <span className="px-1.5 py-0.5 rounded bg-[#05070A] border border-[#1A2332] text-[#00E5A0]">
                        REG: {item.strong_count}
                      </span>
                      <span className="px-1.5 py-0.5 rounded bg-[#05070A] border border-[#1A2332] text-[#4DA6FF]">
                        CAND: {item.candidate_count}
                      </span>
                    </div>

                    <a
                      href={api.getHtmlReportUrl(item.id)}
                      target="_blank"
                      rel="noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="text-[#00E5A0] hover:underline flex items-center space-x-1"
                    >
                      <span>OPEN</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right Column: Preview Pane (7 cols) */}
          <div className="lg:col-span-7 bg-[#0B0F14] border border-[#1A2332] rounded-lg p-5 space-y-4">
            {selectedReport ? (
              <>
                <div className="flex items-center justify-between pb-4 border-b border-[#1A2332]">
                  <div>
                    <span className="text-[10px] font-mono tracking-tracked text-[#7A8794] uppercase block">
                      SELECTED EVIDENCE ARTIFACT
                    </span>
                    <h3 className="text-sm font-mono font-semibold text-[#E8EDF2] mt-0.5">
                      {selectedReport.file_name}
                    </h3>
                  </div>

                  {/* Download Options */}
                  <div className="flex items-center space-x-2">
                    <a
                      href={api.getJsonReportUrl(selectedReport.id)}
                      download
                      className="px-2.5 py-1.5 rounded border border-[#1A2332] bg-[#05070A] hover:border-[#00E5A0] hover:text-[#00E5A0] text-xs font-mono text-[#C5D0DA] flex items-center space-x-1.5 transition-colors"
                    >
                      <FileJson className="w-3.5 h-3.5" />
                      <span>JSON</span>
                    </a>
                    <a
                      href={api.getHtmlReportUrl(selectedReport.id, true)}
                      download
                      className="px-2.5 py-1.5 rounded border border-[#00E5A0] bg-[#00E5A0]/10 hover:bg-[#00E5A0]/20 text-xs font-mono text-[#00E5A0] flex items-center space-x-1.5 transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>HTML REPORT</span>
                    </a>
                  </div>
                </div>

                {/* Evidence Metadata Readout */}
                <div className="grid grid-cols-2 gap-3 p-3 bg-[#05070A] border border-[#1A2332] rounded text-xs font-mono">
                  <div>
                    <span className="text-[#7A8794] text-[10px] uppercase block">Package ID</span>
                    <span className="text-[#E8EDF2] font-medium truncate block">
                      {selectedReport.package_name || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#7A8794] text-[10px] uppercase block">SHA-256 Hash</span>
                    <span className="text-[#C5D0DA] text-[11px] truncate block" title={selectedReport.sha256}>
                      {selectedReport.sha256 || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#7A8794] text-[10px] uppercase block">Strong Static Registrations</span>
                    <span className="text-[#00E5A0] font-bold">
                      {selectedReport.strong_count} verified
                    </span>
                  </div>
                  <div>
                    <span className="text-[#7A8794] text-[10px] uppercase block">Analysis Engine Status</span>
                    <span className="text-[#E8EDF2]">
                      {selectedReport.status.toUpperCase()}
                    </span>
                  </div>
                </div>

                {/* Standalone HTML Iframe Live Preview */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-mono text-[#7A8794]">
                    <span>OFFLINE REPORT PREVIEW</span>
                    <a
                      href={api.getHtmlReportUrl(selectedReport.id)}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[#00E5A0] hover:underline flex items-center space-x-1"
                    >
                      <span>VIEW FULLSCREEN</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <div className="border border-[#1A2332] rounded-lg overflow-hidden bg-white h-[450px]">
                    <iframe
                      src={api.getHtmlReportUrl(selectedReport.id)}
                      title={`Report Preview - ${selectedReport.file_name}`}
                      className="w-full h-full border-0"
                    />
                  </div>
                </div>
              </>
            ) : (
              <div className="py-20 text-center font-mono text-xs text-[#7A8794]">
                SELECT AN ARCHIVE ENTRY TO PREVIEW EVIDENCE
              </div>
            )}
          </div>

        </div>
      )}

    </div>
  );
};
