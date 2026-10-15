import React, { useState, useEffect } from 'react';
import {
  Binary,
  Layers,
  Search,
  Copy,
  Check,
  ChevronRight,
  Code,
  ShieldAlert,
  ShieldCheck,
  ExternalLink,
  Share2,
  FileText,
  Download,
  AlertCircle,
  FileCode,
  Radio,
  FolderArchive,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api/client';
import {
  AnalysisReport,
  RegistrationFinding,
  TraceStep,
  UUIDCandidate,
  EvidenceLevel,
} from '../types';
import { EvidenceBadge } from '../components/EvidenceBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';
import { NavTab } from '../components/SidebarNav';

interface WorkbenchPageProps {
  analysisId: string | null;
  onSelectCase?: (caseId: string) => void;
  onNavigateTab?: (tab: NavTab) => void;
}

export const WorkbenchPage: React.FC<WorkbenchPageProps> = ({
  analysisId,
  onSelectCase,
  onNavigateTab,
}) => {
  const [currentId, setCurrentId] = useState<string | null>(analysisId);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Navigator state
  const [filterLevel, setFilterLevel] = useState<'ALL' | 'STRONG' | 'UNRESOLVED' | 'CANDIDATE'>('ALL');
  const [navigatorSearch, setNavigatorSearch] = useState('');
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [isCandidateOnlySelected, setIsCandidateOnlySelected] = useState(false);
  const [selectedCandidate, setSelectedCandidate] = useState<UUIDCandidate | null>(null);

  // Disassembly viewer state
  const [selectedStepIndex, setSelectedStepIndex] = useState<number | null>(null);
  const [disassemblySearch, setDisassemblySearch] = useState('');
  const [copiedTrace, setCopiedTrace] = useState(false);

  // Load latest analysis if none provided
  useEffect(() => {
    if (!analysisId) {
      api.listAnalyses(1, 1).then((res) => {
        if (res.items.length > 0) {
          setCurrentId(res.items[0].id);
          if (onSelectCase) onSelectCase(res.items[0].id);
        }
      }).catch(() => {});
    } else {
      setCurrentId(analysisId);
    }
  }, [analysisId]);

  // Fetch report data
  useEffect(() => {
    if (!currentId) return;

    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getAnalysisResults(currentId);
        setReport(data.report);
        setFileName(data.file_name || data.report?.metadata?.file_name || 'APK Target');
        setSelectedIndex(0);
        setSelectedStepIndex(null);
        setIsCandidateOnlySelected(false);
      } catch (err: any) {
        setError(err.message || 'Failed to load analysis report');
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [currentId]);

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center p-12">
        <LoadingSpinner message="DISSECTING DALVIK BYTECODE REGISTERS & TRACES..." size="lg" />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-4xl mx-auto p-8 space-y-4">
        <ErrorBanner title="EVIDENCE RETRIEVAL EXCEPTION" message={error || 'No analysis case selected'} />
        <div className="bg-[#151921] border border-[#262E3B] rounded-lg p-6 text-center space-y-4">
          <FolderArchive className="w-12 h-12 text-[#64748B] mx-auto" />
          <h3 className="text-sm font-semibold text-[#F1F5F9]">No Active Analysis Case Selected</h3>
          <p className="text-xs text-[#94A3B8] max-w-md mx-auto">
            Select an existing APK from the top investigation selector or intake a new binary to inspect its Dalvik disassembly.
          </p>
          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('intake')}
              className="px-4 py-2 rounded bg-teal-500/10 text-teal-400 border border-teal-500/30 text-xs font-mono hover:bg-teal-500/20 transition-colors"
            >
              + Ingest New APK Archive
            </button>
          )}
        </div>
      </div>
    );
  }

  const meta = report.metadata;
  const manifest = meta?.manifest;
  const ble = meta?.ble_analysis;
  const reg = meta?.registration_analysis;
  const kb = meta?.knowledge_base_assessment;

  // Findings list
  const findings: RegistrationFinding[] = reg?.findings || [];
  const candidates: UUIDCandidate[] = ble?.uuid_candidates || [];

  // Filter findings according to selected filter and search term
  const filteredFindings = findings.filter((f) => {
    if (filterLevel === 'STRONG' && f.evidence_level !== 'STRONG_STATIC_ASSOCIATION') return false;
    if (filterLevel === 'UNRESOLVED' && f.evidence_level !== 'REGISTRATION_PATTERN_UUID_UNRESOLVED') return false;
    if (filterLevel === 'CANDIDATE') return false;

    if (!navigatorSearch.trim()) return true;
    const q = navigatorSearch.toLowerCase();
    return (
      (f.normalized_uuid && f.normalized_uuid.toLowerCase().includes(q)) ||
      f.class_name.toLowerCase().includes(q) ||
      f.method_name.toLowerCase().includes(q) ||
      f.diagnosis.toLowerCase().includes(q)
    );
  });

  // Filter candidate-only list
  const filteredCandidates = candidates.filter((c) => {
    if (filterLevel === 'STRONG' || filterLevel === 'UNRESOLVED') return false;
    if (!navigatorSearch.trim()) return true;
    const q = navigatorSearch.toLowerCase();
    return (
      c.normalized_uuid.toLowerCase().includes(q) ||
      c.raw_string.toLowerCase().includes(q)
    );
  });

  // Currently selected finding
  const selectedFinding = !isCandidateOnlySelected && filteredFindings.length > selectedIndex
    ? filteredFindings[selectedIndex]
    : null;

  // Selected step or default to first step
  const activeTraceSteps = selectedFinding?.trace_steps || [];
  const activeStep = selectedStepIndex !== null && activeTraceSteps[selectedStepIndex]
    ? activeTraceSteps[selectedStepIndex]
    : activeTraceSteps.length > 0
    ? activeTraceSteps[0]
    : null;

  // Filter disassembly trace lines
  const visibleSteps = activeTraceSteps.filter((step) => {
    if (!disassemblySearch.trim()) return true;
    const q = disassemblySearch.toLowerCase();
    return (
      step.opcode.toLowerCase().includes(q) ||
      step.step_type.toLowerCase().includes(q) ||
      JSON.stringify(step.details).toLowerCase().includes(q)
    );
  });

  // Knowledge base match for current finding/candidate
  const currentUUID = selectedFinding?.normalized_uuid || selectedCandidate?.normalized_uuid;
  const kbMatch = kb?.findings?.find(
    (item) => item.normalized_uuid.toLowerCase() === (currentUUID || '').toLowerCase()
  );

  const copyDalvikTrace = () => {
    if (!selectedFinding) return;
    const text = selectedFinding.trace_steps
      .map(
        (s) =>
          `+0x${s.instruction_offset.toString(16).padStart(4, '0')}  ${s.opcode.padEnd(16)} ${JSON.stringify(s.details)}`
      )
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopiedTrace(true);
    setTimeout(() => setCopiedTrace(false), 1500);
  };

  return (
    <div className="h-[calc(100vh-3.5rem-1.75rem)] flex flex-col bg-[#0A0D12] overflow-hidden select-none">
      
      {/* Top Workbench Context Header */}
      <div className="h-10 bg-[#0E1116] border-b border-[#262E3B] px-4 flex items-center justify-between text-xs font-mono shrink-0">
        <div className="flex items-center space-x-3 truncate">
          <span className="text-[#64748B] flex items-center space-x-1">
            <Binary className="w-3.5 h-3.5 text-[#14B8A6]" />
            <span>DALVIK WORKBENCH:</span>
          </span>
          <span className="font-semibold text-[#F1F5F9] truncate">{fileName}</span>
          <span className="text-[#64748B] hidden md:inline">
            ({manifest?.package_name || 'No package'})
          </span>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <span className="text-[10px] text-[#94A3B8] px-2 py-0.5 rounded bg-[#151921] border border-[#262E3B]">
            {findings.length} GATT CALL SITES
          </span>
          <span className="text-[10px] text-teal-400 px-2 py-0.5 rounded bg-teal-500/10 border border-teal-500/30">
            {reg?.strong_associations_count || 0} VERIFIED
          </span>
          <span className="text-[10px] text-amber-400 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30">
            {reg?.unresolved_patterns_count || 0} UNRESOLVED
          </span>
        </div>
      </div>

      {/* 3-Pane Reverse-Engineering IDE Body */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* PANE 1: APK & Evidence Navigator (Left, ~320px) */}
        <div className="w-80 bg-[#0E1116] border-r border-[#262E3B] flex flex-col shrink-0">
          
          {/* Navigator Header & Filter Tabs */}
          <div className="p-2.5 border-b border-[#262E3B] space-y-2 bg-[#12161E]">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono tracking-wider text-[#64748B] uppercase">
                EVIDENCE NAVIGATOR
              </span>
              <span className="text-[10px] font-mono text-[#94A3B8]">
                {filteredFindings.length + (filterLevel === 'ALL' || filterLevel === 'CANDIDATE' ? filteredCandidates.length : 0)} items
              </span>
            </div>

            {/* Filter Pills */}
            <div className="grid grid-cols-4 gap-1">
              {(['ALL', 'STRONG', 'UNRESOLVED', 'CANDIDATE'] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => {
                    setFilterLevel(lvl);
                    setSelectedIndex(0);
                    setIsCandidateOnlySelected(lvl === 'CANDIDATE');
                  }}
                  className={`py-1 text-[9px] font-mono rounded text-center transition-colors ${
                    filterLevel === lvl
                      ? 'bg-[#1C222B] text-[#14B8A6] border border-[#3B4656] font-medium'
                      : 'text-[#64748B] hover:text-[#94A3B8] bg-[#0E1116]'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>

            {/* Search Input */}
            <div className="relative">
              <Search className="w-3 h-3 text-[#64748B] absolute left-2 top-2" />
              <input
                type="text"
                value={navigatorSearch}
                onChange={(e) => setNavigatorSearch(e.target.value)}
                placeholder="Filter by class, method, or UUID..."
                className="w-full pl-7 pr-2 py-1 bg-[#0E1116] border border-[#262E3B] rounded text-[11px] font-mono text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#14B8A6]"
              />
            </div>
          </div>

          {/* Navigator Item List */}
          <div className="flex-1 overflow-y-auto p-1.5 space-y-1">
            
            {/* 1. Verified & Unresolved Registration Findings */}
            {filteredFindings.map((finding, idx) => {
              const isSelected = !isCandidateOnlySelected && selectedIndex === idx;
              const isStrong = finding.evidence_level === 'STRONG_STATIC_ASSOCIATION';

              return (
                <div
                  key={`finding-${idx}`}
                  onClick={() => {
                    setSelectedIndex(idx);
                    setIsCandidateOnlySelected(false);
                    setSelectedCandidate(null);
                    setSelectedStepIndex(null);
                  }}
                  className={`p-2 rounded cursor-pointer text-xs font-mono border transition-all ${
                    isSelected
                      ? 'bg-[#181E27] border-[#14B8A6] text-[#F1F5F9] shadow-[0_0_8px_rgba(20,184,166,0.15)]'
                      : 'bg-[#12161E] border-[#262E3B] text-[#94A3B8] hover:border-[#3B4656] hover:text-[#F1F5F9]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span
                      className={`text-[9px] px-1 py-0.2 rounded font-semibold border ${
                        isStrong
                          ? 'bg-teal-500/10 text-teal-400 border-teal-500/30'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}
                    >
                      {isStrong ? 'STRONG' : 'UNRESOLVED'}
                    </span>
                    <span className="text-[10px] text-[#64748B]">
                      {finding.trace_steps.length} steps
                    </span>
                  </div>

                  <div className="font-semibold text-[11px] truncate text-[#F1F5F9]">
                    {finding.method_name}()
                  </div>

                  <div className="text-[10px] text-[#64748B] truncate mt-0.5">
                    {finding.class_name.split('.').pop()}
                  </div>

                  {finding.normalized_uuid && (
                    <div className="text-[10px] text-[#14B8A6] font-mono truncate mt-1 bg-[#0E1116] px-1 py-0.5 rounded border border-[#262E3B]">
                      {finding.normalized_uuid}
                    </div>
                  )}
                </div>
              );
            })}

            {/* 2. Candidate-Only UUIDs */}
            {(filterLevel === 'ALL' || filterLevel === 'CANDIDATE') &&
              filteredCandidates.map((cand, idx) => {
                const isSelected = isCandidateOnlySelected && selectedCandidate?.normalized_uuid === cand.normalized_uuid;

                return (
                  <div
                    key={`cand-${idx}`}
                    onClick={() => {
                      setIsCandidateOnlySelected(true);
                      setSelectedCandidate(cand);
                      setSelectedStepIndex(null);
                    }}
                    className={`p-2 rounded cursor-pointer text-xs font-mono border transition-all ${
                      isSelected
                        ? 'bg-[#181E27] border-[#3B4656] text-[#F1F5F9]'
                        : 'bg-[#12161E]/60 border-[#262E3B] text-[#64748B] hover:border-[#3B4656] hover:text-[#94A3B8]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[9px] px-1 py-0.2 rounded font-semibold bg-[#1C222B] text-[#64748B] border border-[#262E3B]">
                        CANDIDATE ONLY
                      </span>
                      <span className="text-[10px] text-[#64748B]">
                        {cand.occurrence_count}x pool
                      </span>
                    </div>

                    <div className="font-mono text-[10px] text-[#94A3B8] truncate">
                      {cand.normalized_uuid}
                    </div>
                  </div>
                );
              })}

            {filteredFindings.length === 0 && filteredCandidates.length === 0 && (
              <div className="p-6 text-center text-xs font-mono text-[#64748B]">
                No findings match filter
              </div>
            )}
          </div>

          {/* Navigator Footer: DEX & Target Profile */}
          <div className="p-2 border-t border-[#262E3B] bg-[#12161E] text-[10px] font-mono text-[#64748B] space-y-1">
            <div className="flex justify-between">
              <span>DEX FILES:</span>
              <span className="text-[#94A3B8]">{meta?.dex_files?.length || 1} file(s)</span>
            </div>
            <div className="flex justify-between">
              <span>GATT SERVER:</span>
              <span className={ble?.is_gatt_server ? 'text-teal-400 font-semibold' : 'text-[#94A3B8]'}>
                {ble?.is_gatt_server ? 'TRUE' : 'FALSE'}
              </span>
            </div>
          </div>
        </div>

        {/* PANE 2: Dalvik Evidence Viewer (Center, Flex-1) */}
        <div className="flex-1 bg-[#0A0D12] flex flex-col border-r border-[#262E3B] overflow-hidden">
          
          {/* Disassembly Header */}
          <div className="h-10 bg-[#0E1116] border-b border-[#262E3B] px-4 flex items-center justify-between text-xs font-mono shrink-0">
            <div className="flex items-center space-x-2 truncate">
              <Code className="w-3.5 h-3.5 text-[#14B8A6]" />
              <span className="text-[#64748B]">DISASSEMBLY:</span>
              <span className="text-[#F1F5F9] font-medium truncate">
                {selectedFinding
                  ? `${selectedFinding.class_name}.${selectedFinding.method_name}()`
                  : selectedCandidate
                  ? `String Literal: ${selectedCandidate.raw_string}`
                  : 'No sequence loaded'}
              </span>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              {/* Disassembly Filter */}
              <div className="relative">
                <input
                  type="text"
                  value={disassemblySearch}
                  onChange={(e) => setDisassemblySearch(e.target.value)}
                  placeholder="Filter opcodes..."
                  className="w-36 px-2 py-0.5 bg-[#151921] border border-[#262E3B] rounded text-[10px] font-mono text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#14B8A6]"
                />
              </div>

              {/* Copy Dalvik Trace Button */}
              {selectedFinding && (
                <button
                  onClick={copyDalvikTrace}
                  className="flex items-center space-x-1 px-2 py-1 rounded bg-[#151921] hover:bg-[#1C222B] text-[#94A3B8] hover:text-[#F1F5F9] text-[10px] font-mono border border-[#262E3B] transition-colors"
                  title="Copy Dalvik trace to clipboard"
                >
                  {copiedTrace ? <Check className="w-3 h-3 text-teal-400" /> : <Copy className="w-3 h-3" />}
                  <span>Copy Trace</span>
                </button>
              )}
            </div>
          </div>

          {/* Disassembly Monospace Instruction Table */}
          <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-1">
            {selectedFinding ? (
              activeTraceSteps.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center p-8 text-[#64748B]">
                  <AlertCircle className="w-8 h-8 mb-2 opacity-50" />
                  <p className="text-xs">No intra-method Dalvik trace steps recorded for this call site.</p>
                  <p className="text-[11px] text-[#64748B] mt-1">
                    {selectedFinding.diagnosis}
                  </p>
                </div>
              ) : (
                <div className="space-y-1">
                  {/* Table header */}
                  <div className="grid grid-cols-12 gap-2 pb-2 text-[10px] font-semibold text-[#64748B] border-b border-[#262E3B]">
                    <span className="col-span-1">#</span>
                    <span className="col-span-2">OFFSET</span>
                    <span className="col-span-3">OPCODE</span>
                    <span className="col-span-6">OPERANDS & TARGET METHOD</span>
                  </div>

                  {/* Disassembly rows */}
                  {visibleSteps.map((step, sIdx) => {
                    const isSelected = selectedStepIndex === sIdx;
                    const hexOffset = `+0x${step.instruction_offset.toString(16).padStart(4, '0')}`;
                    const isAddService = step.step_type === 'add_service' || step.opcode.includes('addService');
                    const isConstructor = step.step_type === 'service_constructor';

                    return (
                      <div
                        key={`step-${sIdx}`}
                        onClick={() => setSelectedStepIndex(sIdx)}
                        className={`grid grid-cols-12 gap-2 py-1.5 px-2 rounded cursor-pointer transition-all ${
                          isSelected
                            ? 'disassembly-line-selected bg-teal-500/10 text-[#F1F5F9]'
                            : isAddService
                            ? 'bg-amber-500/5 text-[#F1F5F9] hover:bg-[#151921]'
                            : 'text-[#94A3B8] hover:bg-[#12161E] hover:text-[#F1F5F9]'
                        }`}
                      >
                        <span className="col-span-1 text-[#64748B] text-[10px]">{sIdx + 1}</span>
                        <span className="col-span-2 font-mono text-[#14B8A6] text-[11px]">{hexOffset}</span>
                        <span className="col-span-3 font-semibold text-[#CBD5E1] text-[11px] truncate">
                          {step.opcode}
                        </span>

                        <div className="col-span-6 font-mono text-[11px] truncate flex items-center space-x-1">
                          {step.details.register && (
                            <span className="text-amber-400 font-semibold">{step.details.register}, </span>
                          )}
                          {step.details.value && (
                            <span className="text-teal-400 truncate">"{step.details.value}"</span>
                          )}
                          {step.details.method && (
                            <span className="text-[#38BDF8] truncate">{step.details.method}</span>
                          )}
                          {step.details.service_register !== undefined && (
                            <span className="text-[#94A3B8]">
                              service=v{step.details.service_register}
                            </span>
                          )}
                          {step.details.server_register !== undefined && (
                            <span className="text-[#94A3B8]">
                              server=v{step.details.server_register}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )
            ) : selectedCandidate ? (
              <div className="space-y-4 p-4 bg-[#12161E] border border-[#262E3B] rounded-lg">
                <div className="flex items-center space-x-2 text-teal-400 font-semibold">
                  <Binary className="w-4 h-4" />
                  <span>UUID Literal Candidate (String Pool Constant)</span>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <span className="text-[#64748B]">Normalized 128-bit UUID:</span>
                    <p className="text-[#F1F5F9] font-medium mt-0.5">{selectedCandidate.normalized_uuid}</p>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Raw Literal String:</span>
                    <p className="text-teal-400 mt-0.5">{selectedCandidate.raw_string}</p>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Format Type:</span>
                    <p className="text-[#94A3B8] mt-0.5">{selectedCandidate.format_type}</p>
                  </div>
                </div>

                <div className="border-t border-[#262E3B] pt-3">
                  <span className="text-[11px] font-semibold text-[#64748B] uppercase">Bytecode References</span>
                  <div className="mt-2 space-y-1">
                    {selectedCandidate.evidence?.map((ev, eIdx) => (
                      <div key={eIdx} className="p-2 bg-[#0E1116] rounded border border-[#262E3B] text-[11px]">
                        <span className="text-[#14B8A6]">{ev.dex_file}</span>
                        {ev.class_name && <span className="text-[#94A3B8]"> • {ev.class_name}</span>}
                        {ev.method_name && <span className="text-[#F1F5F9]">.{ev.method_name}()</span>}
                        {ev.instruction_offset !== undefined && (
                          <span className="text-amber-400"> [+0x{ev.instruction_offset.toString(16)}]</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-[#64748B]">
                Select an evidence finding from the Navigator to view its Dalvik instructions
              </div>
            )}
          </div>

          {/* Dalvik Viewer Footer: Instruction Details Strip */}
          {activeStep && (
            <div className="h-10 bg-[#0E1116] border-t border-[#262E3B] px-4 flex items-center justify-between text-[11px] font-mono shrink-0">
              <div className="flex items-center space-x-2 truncate">
                <span className="text-[#64748B]">FOCUSED OP:</span>
                <span className="text-[#14B8A6] font-semibold">{activeStep.opcode}</span>
                <span className="text-[#64748B]">at offset</span>
                <span className="text-amber-400">+0x{activeStep.instruction_offset.toString(16)}</span>
              </div>
              <span className="text-[#94A3B8] text-[10px] hidden md:inline">
                STEP TYPE: {activeStep.step_type}
              </span>
            </div>
          )}
        </div>

        {/* PANE 3: Evidence Inspector (Right, ~380px) */}
        <div className="w-96 bg-[#0E1116] flex flex-col shrink-0 overflow-y-auto">
          
          <div className="p-3 border-b border-[#262E3B] bg-[#12161E] flex items-center justify-between">
            <span className="text-[10px] font-mono tracking-wider text-[#64748B] uppercase">
              EVIDENCE INSPECTOR
            </span>
            {selectedFinding && (
              <EvidenceBadge level={selectedFinding.evidence_level} />
            )}
          </div>

          <div className="p-4 space-y-4 font-mono text-xs">
            
            {/* Section 1: Observed Dalvik Facts */}
            <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between border-b border-[#262E3B] pb-1.5">
                <span className="text-[10px] font-semibold text-[#14B8A6] tracking-wider uppercase">
                  1. OBSERVED DALVIK FACTS
                </span>
                <span className="text-[9px] text-[#64748B]">GROUND TRUTH</span>
              </div>

              {selectedFinding ? (
                <div className="space-y-1.5 text-[11px]">
                  <div>
                    <span className="text-[#64748B]">DEX Container:</span>
                    <span className="text-[#F1F5F9] ml-1.5">{selectedFinding.dex_file}</span>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Enclosing Class:</span>
                    <p className="text-[#F1F5F9] font-medium break-all mt-0.5">{selectedFinding.class_name}</p>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Call Site Method:</span>
                    <p className="text-teal-400 break-all mt-0.5">
                      {selectedFinding.method_name}
                      <span className="text-[#64748B] text-[10px]">{selectedFinding.descriptor}</span>
                    </p>
                  </div>

                  {selectedFinding.construction_site && (
                    <div className="pt-2 border-t border-[#262E3B]/60">
                      <span className="text-[10px] text-[#94A3B8] font-semibold">Service Constructor Site:</span>
                      <p className="text-[#64748B] text-[10px] mt-0.5">
                        Offset: +0x{selectedFinding.construction_site.instruction_offset.toString(16)} • 
                        Service Reg: v{selectedFinding.construction_site.service_register} • 
                        UUID Reg: v{selectedFinding.construction_site.uuid_register}
                      </p>
                    </div>
                  )}

                  {selectedFinding.registration_site && (
                    <div className="pt-1.5">
                      <span className="text-[10px] text-[#94A3B8] font-semibold">addService() Call Site:</span>
                      <p className="text-[#64748B] text-[10px] mt-0.5">
                        Offset: +0x{selectedFinding.registration_site.instruction_offset.toString(16)} • 
                        Server Reg: v{selectedFinding.registration_site.server_register} • 
                        Service Reg: v{selectedFinding.registration_site.service_register}
                      </p>
                    </div>
                  )}
                </div>
              ) : selectedCandidate ? (
                <div className="space-y-1.5 text-[11px]">
                  <div>
                    <span className="text-[#64748B]">String Literal:</span>
                    <p className="text-teal-400 break-all">{selectedCandidate.raw_string}</p>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Normalized 128-bit:</span>
                    <p className="text-[#F1F5F9] break-all">{selectedCandidate.normalized_uuid}</p>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Bytecode Locations:</span>
                    <p className="text-[#94A3B8]">{selectedCandidate.evidence?.length || 0} occurrence(s)</p>
                  </div>
                </div>
              ) : (
                <p className="text-[#64748B] text-[11px]">No finding selected</p>
              )}
            </div>

            {/* Section 2: Analytical Interpretation */}
            <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between border-b border-[#262E3B] pb-1.5">
                <span className="text-[10px] font-semibold text-amber-400 tracking-wider uppercase">
                  2. ANALYTICAL INTERPRETATION
                </span>
                <span className="text-[9px] text-[#64748B]">CONSERVATIVE</span>
              </div>

              {selectedFinding ? (
                <div className="space-y-2">
                  <p className="text-[#CBD5E1] text-[11px] leading-relaxed">
                    {selectedFinding.diagnosis}
                  </p>

                  {selectedFinding.unresolved_reason && (
                    <div className="p-2 rounded bg-amber-500/10 border border-amber-500/30 text-[10px] text-amber-300">
                      <span className="font-semibold uppercase tracking-wider block mb-0.5">
                        UNRESOLVED MECHANICS:
                      </span>
                      {selectedFinding.unresolved_reason}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-[#64748B] text-[11px]">
                  Candidate extracted from DEX string pool. No verified intra-method GATT registration trace detected.
                </p>
              )}
            </div>

            {/* Section 3: Bluetooth SIG Provenance */}
            <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between border-b border-[#262E3B] pb-1.5">
                <span className="text-[10px] font-semibold text-[#38BDF8] tracking-wider uppercase">
                  3. BLUETOOTH SIG PROVENANCE
                </span>
                <span className="text-[9px] text-[#64748B]">ASSIGNED NUMBERS</span>
              </div>

              {kbMatch?.knowledge_base_match ? (
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex items-center space-x-1.5 text-teal-400 font-semibold">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>{kbMatch.knowledge_base_match.name}</span>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Identifier Type:</span>
                    <span className="text-[#F1F5F9] ml-1.5">{kbMatch.knowledge_base_match.identifier_type}</span>
                  </div>
                  <div>
                    <span className="text-[#64748B]">Source:</span>
                    <span className="text-[#94A3B8] ml-1.5">{kbMatch.knowledge_base_match.source_name}</span>
                  </div>
                  {kbMatch.knowledge_base_match.description && (
                    <p className="text-[#94A3B8] text-[10px] leading-relaxed pt-1">
                      {kbMatch.knowledge_base_match.description}
                    </p>
                  )}
                </div>
              ) : (
                <div className="text-[11px] text-[#64748B]">
                  No standard match in Bluetooth SIG repository. Considered a vendor-specific or custom 128-bit UUID.
                </div>
              )}
            </div>

            {/* Action: Open in Relationship Explorer */}
            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab('explorer')}
                className="w-full py-2 px-3 rounded bg-[#1C222B] hover:bg-[#262E3B] text-teal-400 border border-[#3B4656] text-xs font-mono flex items-center justify-center space-x-2 transition-colors"
              >
                <Share2 className="w-3.5 h-3.5" />
                <span>Explore in Topology Graph</span>
              </button>
            )}

          </div>
        </div>

      </div>

    </div>
  );
};
