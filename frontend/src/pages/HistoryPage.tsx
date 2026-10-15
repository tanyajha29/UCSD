import React, { useEffect, useState } from 'react';
import {
  History as HistoryIcon,
  Search,
  Download,
  Trash2,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  FileCode,
  ArrowRight,
} from 'lucide-react';
import { api } from '../api/client';
import { AnalysisSummary } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';

interface Props {
  onSelectAnalysis: (analysisId: string) => void;
}

export const HistoryPage: React.FC<Props> = ({ onSelectAnalysis }) => {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hoveredRowId, setHoveredRowId] = useState<string | null>(null);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.listAnalyses(
        page,
        15,
        statusFilter || undefined,
        searchQuery || undefined
      );
      setAnalyses(data.items);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page, statusFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`PURGE RECORD: Are you sure you want to permanently delete '${name}' and its disk artifacts?`)) {
      return;
    }

    try {
      await api.deleteAnalysis(id);
      fetchHistory();
    } catch (err: any) {
      setError(err.message || 'Failed to delete record');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      
      {/* 1. Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#1A2332] pb-6">
        <div>
          <div className="flex items-center space-x-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-[#00E5A0]" />
            <span className="text-[11px] font-mono tracking-tracked text-[#7A8794] uppercase font-semibold">
              PERSISTENT EVIDENCE LEDGER
            </span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#E8EDF2]">
            Analysis History & Artifact Catalog
          </h1>
          <p className="text-xs text-[#7A8794] mt-1 font-mono">
            Persistent SQLite database records of all intake jobs, Dalvik traces, and compiled reports.
          </p>
        </div>

        <div className="text-xs font-mono text-[#7A8794] bg-[#0B0F14] border border-[#1A2332] px-3 py-1.5 rounded self-start">
          TOTAL ARCHIVED: <strong className="text-[#00E5A0]">{total}</strong> ENTRIES
        </div>
      </div>

      {error && <ErrorBanner title="LEDGER EXCEPTION" message={error} onDismiss={() => setError(null)} />}

      {/* 2. Filter & Search Controls */}
      <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg p-3 flex flex-col md:flex-row gap-3 items-center justify-between">
        <form onSubmit={handleSearch} className="flex-1 w-full flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-[#7A8794] absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by binary filename, package, or SHA-256..."
              className="w-full pl-9 pr-3 py-1.5 bg-[#05070A] border border-[#1A2332] rounded text-xs font-mono text-[#E8EDF2] placeholder-[#7A8794] focus:outline-none focus:border-[#00E5A0]"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-[#11171F] border border-[#1A2332] hover:border-[#00E5A0] hover:text-[#00E5A0] text-xs font-mono text-[#C5D0DA] rounded transition-colors"
          >
            SEARCH
          </button>
        </form>

        <div className="flex items-center space-x-2 w-full md:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter analyses by engine status"
            className="bg-[#05070A] border border-[#1A2332] text-xs font-mono text-[#C5D0DA] rounded px-3 py-1.5 focus:outline-none focus:border-[#00E5A0]"
          >
            <option value="">ALL STATUSES</option>
            <option value="success">SUCCESS</option>
            <option value="running">RUNNING</option>
            <option value="failed">FAILED</option>
          </select>
        </div>
      </div>

      {/* 3. Evidence Ledger Table */}
      {loading ? (
        <LoadingSpinner message="QUERYING PERSISTENT SQLITE REPOSITORY..." size="lg" />
      ) : analyses.length === 0 ? (
        <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg p-12 text-center text-[#7A8794] space-y-3 font-mono">
          <FileCode className="w-8 h-8 mx-auto text-[#7A8794]/50" />
          <p className="text-xs uppercase">NO EVIDENCE RECORDS MATCH YOUR FILTER</p>
        </div>
      ) : (
        <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg overflow-hidden space-y-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#05070A] text-[#7A8794] font-mono uppercase text-[10px] tracking-wider border-b border-[#1A2332]">
                <tr>
                  <th className="py-3 px-4">Binary Target</th>
                  <th className="py-3 px-4">Package ID</th>
                  <th className="py-3 px-4">Engine Status</th>
                  <th className="py-3 px-4 text-center">Strong Reg</th>
                  <th className="py-3 px-4 text-center">Candidates</th>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A2332] font-mono text-[#C5D0DA]">
                {analyses.map((item) => {
                  const isHovered = hoveredRowId === item.id;
                  const isSuccess = item.status === 'success';
                  const isRunning = item.status === 'running';

                  return (
                    <tr
                      key={item.id}
                      onMouseEnter={() => setHoveredRowId(item.id)}
                      onMouseLeave={() => setHoveredRowId(null)}
                      className="group relative hover:bg-[#11171F] transition-colors duration-150"
                    >
                      {/* Left-edge phosphor bar on hover */}
                      <td className="p-0 w-0">
                        <div className={`absolute left-0 top-0 bottom-0 w-1 bg-[#00E5A0] transition-transform duration-150 origin-top ${
                          isHovered ? 'scale-y-100' : 'scale-y-0'
                        }`} />
                      </td>

                      {/* Filename & SHA */}
                      <td className="py-3 px-4 font-medium text-[#E8EDF2]">
                        <div className="flex items-center space-x-2">
                          <FileCode className="w-4 h-4 text-[#7A8794] shrink-0" />
                          <span className="truncate max-w-[200px]" title={item.file_name}>
                            {item.file_name}
                          </span>
                        </div>
                        {item.sha256 && (
                          <div className="text-[10px] text-[#7A8794] font-mono mt-0.5">
                            SHA: {item.sha256.substring(0, 12)}...
                          </div>
                        )}
                      </td>

                      {/* Package ID */}
                      <td className="py-3 px-4 text-[#7A8794]">
                        <span className="truncate max-w-[180px] block" title={item.package_name || ''}>
                          {item.package_name || 'UNRESOLVED'}
                        </span>
                      </td>

                      {/* Status dot + label */}
                      <td className="py-3 px-4">
                        <div className="flex items-center space-x-2">
                          <span className={`inline-flex rounded-full h-2 w-2 ${
                            isSuccess ? 'bg-[#00E5A0]' : isRunning ? 'bg-[#4DA6FF] animate-ping' : 'bg-[#FF3B5C]'
                          }`} />
                          <span className={`text-[11px] font-medium tracking-tight ${
                            isSuccess ? 'text-[#00E5A0]' : isRunning ? 'text-[#4DA6FF]' : 'text-[#FF3B5C]'
                          }`}>
                            {item.status.toUpperCase()}
                          </span>
                        </div>
                      </td>

                      {/* Strong Count */}
                      <td className="py-3 px-4 text-center font-bold text-[#00E5A0] tabular-nums">
                        {item.strong_count}
                      </td>

                      {/* Candidate Count */}
                      <td className="py-3 px-4 text-center text-[#7A8794] tabular-nums">
                        {item.candidate_count}
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 px-4 text-[#7A8794] text-[11px]">
                        {new Date(item.created_at).toISOString().replace('T', ' ').substring(0, 19)}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => onSelectAnalysis(item.id)}
                            className="px-2.5 py-1 text-[11px] font-mono border border-[#1A2332] bg-[#05070A] hover:border-[#00E5A0] hover:text-[#00E5A0] text-[#C5D0DA] rounded transition-all duration-150 inline-flex items-center space-x-1"
                          >
                            <span>INSPECT</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>

                          {isSuccess && (
                            <a
                              href={api.getHtmlReportUrl(item.id)}
                              target="_blank"
                              rel="noreferrer"
                              className="p-1 text-[#7A8794] hover:text-[#00E5A0] transition-colors"
                              title="View Standalone HTML Report"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}

                          <button
                            onClick={() => handleDelete(item.id, item.file_name)}
                            className="p-1 text-[#7A8794] hover:text-[#FF3B5C] transition-colors"
                            title="Purge Analysis Record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="p-3 border-t border-[#1A2332] flex items-center justify-between text-xs font-mono text-[#7A8794] bg-[#05070A]">
              <span>
                PAGE {page} OF {totalPages}
              </span>
              <div className="flex items-center space-x-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="p-1.5 rounded border border-[#1A2332] disabled:opacity-30 hover:border-[#00E5A0] hover:text-[#00E5A0] transition-colors"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  className="p-1.5 rounded border border-[#1A2332] disabled:opacity-30 hover:border-[#00E5A0] hover:text-[#00E5A0] transition-colors"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

    </div>
  );
};
