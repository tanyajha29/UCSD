import React, { useEffect, useState } from 'react';
import {
  GitCompare,
  ArrowRight,
  ExternalLink,
  Layers,
  Check,
  AlertOctagon,
  RefreshCw,
  Search,
} from 'lucide-react';
import { api } from '../api/client';
import { AnalysisSummary, ComparisonRecord, CrossAPKConflictReport } from '../types';
import { ConflictBadge } from '../components/ConflictBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';

export const ComparisonPage: React.FC = () => {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [comparisons, setComparisons] = useState<ComparisonRecord[]>([]);
  const [activeComparison, setActiveComparison] = useState<ComparisonRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState('');

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Load successful analyses for selection
      const aData = await api.listAnalyses(1, 100, 'success');
      setAnalyses(aData.items);

      // Default select first two if available and nothing selected
      if (aData.items.length >= 2 && selectedIds.length === 0) {
        setSelectedIds([aData.items[0].id, aData.items[1].id]);
      }

      // Load previous comparisons
      const cData = await api.listComparisons(20);
      setComparisons(cData);

      if (cData.length > 0) {
        const latest = await api.getComparisonDetail(cData[0].id);
        setActiveComparison(latest);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load comparison data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const runComparison = async () => {
    if (selectedIds.length < 2) {
      setError('Please select at least 2 analyzed applications to compare.');
      return;
    }

    try {
      setEvaluating(true);
      setError(null);
      const res = await api.createComparison(selectedIds);
      setActiveComparison(res);

      const cData = await api.listComparisons(20);
      setComparisons(cData);
    } catch (err: any) {
      setError(err.detail || err.message || 'Comparison failed');
    } finally {
      setEvaluating(false);
    }
  };

  const loadPastComparison = async (id: string) => {
    try {
      setLoading(true);
      const res = await api.getComparisonDetail(id);
      setActiveComparison(res);
      if (res.analysis_ids && res.analysis_ids.length >= 2) {
        setSelectedIds(res.analysis_ids);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load comparison record');
    } finally {
      setLoading(false);
    }
  };

  if (loading && !activeComparison && analyses.length === 0) {
    return <LoadingSpinner message="INITIALIZING CROSS-APK COLLISION MATRIX..." size="lg" />;
  }

  const report: CrossAPKConflictReport | undefined = activeComparison?.report_data;

  // Selected APK details
  const selectedApkObjs = analyses.filter((a) => selectedIds.includes(a.id));
  const apkA = selectedApkObjs[0];
  const apkB = selectedApkObjs[1];

  // Filter analyses by search
  const filteredAnalyses = analyses.filter((a) => 
    a.file_name.toLowerCase().includes(searchFilter.toLowerCase()) ||
    (a.package_name && a.package_name.toLowerCase().includes(searchFilter.toLowerCase()))
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* 1. Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1A2332] pb-6">
        <div>
          <div className="flex items-center space-x-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-[#FF3B5C] animate-pulse" />
            <span className="text-[11px] font-mono tracking-tracked text-[#FF3B5C] uppercase font-semibold">
              CROSS-APPLICATION CONFLICT DETECTION
            </span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#E8EDF2]">
            Static Duplicate Registration Collision Matrix
          </h1>
          <p className="text-xs text-[#7A8794] mt-1 max-w-2xl font-mono">
            Evaluates whether two distinct Android packages attempt local GATT registration (<code className="text-[#00E5A0]">BluetoothGattServer.addService</code>) 
            for the identical service UUID, establishing static overlap without runtime ambiguity.
          </p>
        </div>

        {/* Compare Action Button with Scanline sweep */}
        <div className="shrink-0">
          <button
            onClick={runComparison}
            disabled={selectedIds.length < 2 || evaluating}
            className={`btn-terminal px-5 py-3 rounded text-xs font-mono font-medium flex items-center space-x-2 transition-all ${
              selectedIds.length >= 2 && !evaluating
                ? 'border border-[#00E5A0] bg-[#00E5A0]/10 text-[#00E5A0] hover:bg-[#00E5A0]/20 shadow-[0_0_20px_rgba(0,229,160,0.15)] cursor-pointer'
                : 'border border-[#1A2332] bg-[#0B0F14] text-[#7A8794] cursor-not-allowed opacity-50'
            }`}
          >
            {evaluating ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-[#00E5A0]" />
                <span>EVALUATING STATIC COLLISIONS...</span>
              </>
            ) : (
              <>
                <span>&gt; COMPARE SELECTED ({selectedIds.length})</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </div>

      {error && <ErrorBanner title="EVALUATION ERROR" message={error} onDismiss={() => setError(null)} />}

      {/* 2. Timeline Strip: Recent Conflict Evaluations */}
      {comparisons.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono tracking-tracked text-[#7A8794] uppercase">
              RECENT CONFLICT EVALUATION TIMELINE
            </span>
            <span className="text-[10px] font-mono text-[#7A8794]">
              TOTAL RUNS: {comparisons.length}
            </span>
          </div>

          <div className="relative border-t border-[#1A2332] pt-4">
            <div className="flex items-center space-x-3 overflow-x-auto pb-2 scrollbar-thin">
              {comparisons.map((c, idx) => {
                const isActive = activeComparison?.id === c.id;
                const hasCritical = c.strong_duplicates_count > 0;
                return (
                  <div
                    key={c.id}
                    onClick={() => loadPastComparison(c.id)}
                    className={`shrink-0 cursor-pointer p-3 rounded-lg border transition-all duration-150 min-w-[220px] ${
                      isActive
                        ? 'bg-[#11171F] border-[#00E5A0] shadow-[0_0_12px_rgba(0,229,160,0.2)]'
                        : 'bg-[#0B0F14] border-[#1A2332] hover:border-[#2A3A4F]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[10px] font-mono text-[#7A8794]">
                        RUN #{comparisons.length - idx}
                      </span>
                      {hasCritical ? (
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-[#FF3B5C]/20 border border-[#FF3B5C] text-[#FF3B5C]">
                          {c.strong_duplicates_count} CRITICAL
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-[#1A2332] text-[#7A8794]">
                          0 CONFLICTS
                        </span>
                      )}
                    </div>

                    <div className="text-[11px] font-mono text-[#E8EDF2] truncate font-medium">
                      {c.title || `Evaluation of ${c.target_count} APKs`}
                    </div>

                    <div className="text-[10px] font-mono text-[#7A8794] mt-1">
                      {new Date(c.created_at).toISOString().substring(11, 19)} UTC
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* 3. The Visual Centerpiece: Split-Screen Collision Visualizer */}
      {selectedApkObjs.length >= 2 && (
        <div className="relative bg-[#0B0F14] border border-[#1A2332] rounded-lg p-6 overflow-hidden forensic-grid">
          {/* Scanning sweep animation line during evaluation */}
          {evaluating && (
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[#00E5A0]/10 to-transparent w-full h-full animate-scanline pointer-events-none z-20" />
          )}

          <div className="flex items-center justify-between mb-6 pb-3 border-b border-[#1A2332]">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-[#00E5A0]" />
              <span className="text-[11px] font-mono tracking-tracked text-[#E8EDF2] uppercase font-semibold">
                DUAL-TARGET COLLISION VISUALIZATION ENGINE
              </span>
            </div>
            <div className="text-[10px] font-mono text-[#7A8794]">
              PAIR: <span className="text-[#00E5A0]">{apkA?.file_name}</span> vs <span className="text-[#4DA6FF]">{apkB?.file_name}</span>
            </div>
          </div>

          {/* Node Dissection Diagram */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-center">
            
            {/* Left Node: APK A */}
            <div className="md:col-span-2 bg-[#05070A] border border-[#2A3A4F] rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-[#00E5A0] px-1.5 py-0.5 rounded bg-[#00E5A0]/10 border border-[#00E5A0]/30 uppercase">
                  PRIMARY EXHIBIT A
                </span>
                <span className="text-[10px] font-mono text-[#7A8794]">
                  {apkA?.strong_count} REG SITES
                </span>
              </div>
              <div>
                <div className="text-xs font-mono font-semibold text-[#E8EDF2] truncate">
                  {apkA?.file_name}
                </div>
                <div className="text-[11px] font-mono text-[#7A8794] truncate">
                  {apkA?.package_name}
                </div>
              </div>

              {/* Service Candidate Node Pills */}
              <div className="pt-2 border-t border-[#1A2332] space-y-1.5">
                <div className="text-[9px] font-mono text-[#7A8794] uppercase tracking-wider">
                  EXTRACTED GATT SERVICE NODES
                </div>
                <div className="p-2 rounded bg-[#0B0F14] border border-[#1A2332] flex items-center justify-between">
                  <span className="text-[10px] font-mono text-[#C5D0DA] truncate">
                    0000180d-0000-1000-8000-00805f9b34fb
                  </span>
                  <span className="w-2 h-2 rounded-full bg-[#00E5A0] shrink-0 ml-2" title="Strong Static" />
                </div>
              </div>
            </div>

            {/* Middle: Collision Connector Graphic */}
            <div className="md:col-span-1 flex flex-col items-center justify-center py-4 space-y-2">
              <div className="relative w-full flex items-center justify-center">
                <svg width="100%" height="60" viewBox="0 0 100 60" preserveAspectRatio="none">
                  {/* Glowing collision line if conflict exists */}
                  <line
                    x1="0"
                    y1="30"
                    x2="100"
                    y2="30"
                    stroke={report?.assessments?.some((f: any) => f.condition === 'STRONG_DUPLICATE_STATIC_REGISTRATION') ? '#FF3B5C' : '#00E5A0'}
                    strokeWidth="2"
                    strokeDasharray="4 2"
                    className="animate-pulse"
                  />
                </svg>

                <div className="absolute p-2 rounded-full bg-[#05070A] border border-[#FF3B5C] shadow-[0_0_16px_rgba(255,59,92,0.4)]">
                  <AlertOctagon className="w-4 h-4 text-[#FF3B5C] animate-pulse" />
                </div>
              </div>

              <div className="text-[10px] font-mono text-center">
                {report?.assessments?.some((f: any) => f.condition === 'STRONG_DUPLICATE_STATIC_REGISTRATION') ? (
                  <span className="text-[#FF3B5C] font-bold tracking-tight">COLLISION IDENTIFIED</span>
                ) : (
                  <span className="text-[#7A8794]">EVALUATING MATCHES</span>
                )}
              </div>
            </div>

            {/* Right Node: APK B */}
            <div className="md:col-span-2 bg-[#05070A] border border-[#2A3A4F] rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-[#4DA6FF] px-1.5 py-0.5 rounded bg-[#4DA6FF]/10 border border-[#4DA6FF]/30 uppercase">
                  COMPARISON TARGET B
                </span>
                <span className="text-[10px] font-mono text-[#7A8794]">
                  {apkB?.strong_count} REG SITES
                </span>
              </div>
              <div>
                <div className="text-xs font-mono font-semibold text-[#E8EDF2] truncate">
                  {apkB?.file_name}
                </div>
                <div className="text-[11px] font-mono text-[#7A8794] truncate">
                  {apkB?.package_name}
                </div>
              </div>

              {/* Service Candidate Node Pills */}
              <div className="pt-2 border-t border-[#1A2332] space-y-1.5">
                <div className="text-[9px] font-mono text-[#7A8794] uppercase tracking-wider">
                  EXTRACTED GATT SERVICE NODES
                </div>
                <div className="p-2 rounded bg-[#0B0F14] border border-[#1A2332] flex items-center justify-between">
                  <span className="text-[10px] font-mono text-[#C5D0DA] truncate">
                    0000180d-0000-1000-8000-00805f9b34fb
                  </span>
                  <span className="w-2 h-2 rounded-full bg-[#00E5A0] shrink-0 ml-2" title="Strong Static" />
                </div>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* 4. Selection Area: Evidence Exhibits */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <span className="text-[11px] font-mono tracking-tracked text-[#7A8794] uppercase font-semibold">
              EVIDENCE EXHIBITS SELECTION ({selectedIds.length} SELECTED)
            </span>
            <p className="text-xs text-[#7A8794]">
              Select two or more analyzed APK binaries to evaluate static Dalvik collision.
            </p>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-[#7A8794] absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter exhibit binaries..."
              className="w-full bg-[#0B0F14] border border-[#1A2332] text-xs font-mono text-[#E8EDF2] pl-8 pr-3 py-1.5 rounded focus:outline-none focus:border-[#00E5A0]"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {filteredAnalyses.map((apk) => {
            const isSelected = selectedIds.includes(apk.id);
            return (
              <div
                key={apk.id}
                onClick={() => toggleSelect(apk.id)}
                className={`relative p-4 rounded-lg border cursor-pointer transition-all duration-150 ${
                  isSelected
                    ? 'bg-[#11171F] border-[#00E5A0] shadow-[0_0_15px_rgba(0,229,160,0.1)]'
                    : 'bg-[#0B0F14] border-[#1A2332] hover:border-[#2A3A4F]'
                }`}
              >
                {/* Top-Right Animated Checkmark Node Graph */}
                {isSelected && (
                  <div className="absolute top-3 right-3 flex items-center space-x-1 p-1 rounded bg-[#00E5A0]/10 border border-[#00E5A0]">
                    <Check className="w-3.5 h-3.5 text-[#00E5A0]" />
                  </div>
                )}

                <div className="text-xs font-mono font-medium text-[#E8EDF2] truncate pr-6" title={apk.file_name}>
                  {apk.file_name}
                </div>
                <div className="text-[11px] font-mono text-[#7A8794] truncate mt-0.5" title={apk.package_name}>
                  {apk.package_name || 'UNRESOLVED'}
                </div>

                {/* Mini Metrics */}
                <div className="mt-3 pt-3 border-t border-[#1A2332] flex items-center justify-between text-[10px] font-mono">
                  <span className="text-[#00E5A0]">
                    REG: {apk.strong_count}
                  </span>
                  <span className="text-[#7A8794]">
                    CAND: {apk.candidate_count}
                  </span>
                  <span className="text-[#7A8794]">
                    UNRES: {apk.unresolved_count}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 5. Detailed Findings Matrix */}
      {report && (
        <div className="space-y-4 pt-4 border-t border-[#1A2332]">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono tracking-tracked text-[#7A8794] uppercase font-semibold">
              CORRELATION FINDINGS & PROVENANCE EVALUATION
            </span>
            <span className="text-xs font-mono text-[#7A8794]">
              {report.assessments?.length || 0} UUIDS EVALUATED
            </span>
          </div>

          <div className="space-y-3">
            {report.assessments?.map((finding: any, idx: number) => (
              <div
                key={idx}
                className="bg-[#0B0F14] border border-[#1A2332] rounded-lg p-5 space-y-3 hover:border-[#2A3A4F] transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1A2332] pb-3">
                  <div className="flex items-center space-x-3">
                    <span className="font-mono text-sm text-[#00E5A0] font-semibold tracking-tight">
                      {finding.normalized_uuid}
                    </span>
                    <ConflictBadge condition={finding.condition} isProven={finding.is_proven} />
                  </div>

                  {finding.knowledge_base_match && (
                    <div className="text-xs font-mono text-[#4DA6FF] flex items-center space-x-1">
                      <span>KB: {finding.knowledge_base_match.name}</span>
                      {finding.knowledge_base_match.source_url && (
                        <a
                          href={finding.knowledge_base_match.source_url}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:underline text-[#00E5A0]"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  )}
                </div>

                <p className="text-xs text-[#C5D0DA] font-mono leading-relaxed">
                  {finding.explanation}
                </p>

                {/* Participating APKs Cards */}
                <div className="pt-2">
                  <span className="text-[10px] font-mono tracking-wider text-[#7A8794] uppercase block mb-2">
                    PARTICIPATING BINARY INSTANCES ({finding.participating_apks.length})
                  </span>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {finding.participating_apks.map((p: any, pIdx: number) => (
                      <div
                        key={pIdx}
                        className="p-3 rounded bg-[#05070A] border border-[#1A2332] space-y-1 text-xs font-mono"
                      >
                        <div className="font-medium text-[#E8EDF2] truncate">{p.package_name}</div>
                        <div className="text-[11px] text-[#7A8794]">
                          Evidence: <span className="text-[#00E5A0]">{p.evidence_level}</span>
                        </div>
                        {p.class_name && p.method_name && (
                          <div className="text-[10px] text-[#7A8794] truncate">
                            {p.class_name}::{p.method_name}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
};
