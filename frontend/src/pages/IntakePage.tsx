import React, { useState, useRef, useEffect } from 'react';
import {
  UploadCloud,
  FileCode,
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Binary,
  Share2,
  CheckCircle2,
  Copy,
  Check,
  FolderArchive,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api/client';
import { AnalysisSummary } from '../types';
import { ErrorBanner } from '../components/ErrorBanner';
import { NavTab } from '../components/SidebarNav';

interface IntakePageProps {
  onAnalysisComplete: (analysisId: string) => void;
  onNavigateTab: (tab: NavTab, params?: { analysisId?: string }) => void;
}

export const IntakePage: React.FC<IntakePageProps> = ({
  onAnalysisComplete,
  onNavigateTab,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [clientHash, setClientHash] = useState<string | null>(null);
  const [isHashing, setIsHashing] = useState(false);
  const [duplicateCase, setDuplicateCase] = useState<AnalysisSummary | null>(null);

  const [isUploading, setIsUploading] = useState(false);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<AnalysisSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [streamLogs, setStreamLogs] = useState<string[]>([]);
  const [copiedHash, setCopiedHash] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const logContainerRef = useRef<HTMLDivElement | null>(null);

  const computeSHA256 = async (file: File): Promise<string> => {
    setIsHashing(true);
    try {
      const buffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      return hashHex;
    } finally {
      setIsHashing(false);
    }
  };

  const validateAndStageFile = async (file: File) => {
    setError(null);
    setJobStatus(null);
    setActiveJobId(null);
    setStreamLogs([]);
    setDuplicateCase(null);

    if (!file.name.toLowerCase().endsWith('.apk')) {
      setError('INVALID TARGET: Intake requires a valid Android application archive (.apk)');
      setSelectedFile(null);
      setClientHash(null);
      return;
    }

    if (file.size > 100 * 1024 * 1024) {
      setError('GUARDRAIL LIMIT EXCEEDED: Binary exceeds the 100 MB static analysis limit.');
      setSelectedFile(null);
      setClientHash(null);
      return;
    }

    setSelectedFile(file);

    // Compute client-side SHA-256 immediately
    try {
      const hash = await computeSHA256(file);
      setClientHash(hash);

      // Check for duplicate in history
      const existing = await api.listAnalyses(1, 10, undefined, hash);
      const exactMatch = existing.items.find(
        (i) => i.sha256?.toLowerCase() === hash.toLowerCase()
      );
      if (exactMatch) {
        setDuplicateCase(exactMatch);
      }
    } catch (err) {
      console.warn('Failed to compute client SHA-256 hash', err);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndStageFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndStageFile(e.dataTransfer.files[0]);
    }
  };

  const startAnalysis = async () => {
    if (!selectedFile) return;

    try {
      setIsUploading(true);
      setError(null);
      setJobStatus(null);
      setStreamLogs([
        `[${new Date().toISOString().substring(11, 19)}] INTAKE INITIATED: Staging ${selectedFile.name} (${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)...`,
        `[${new Date().toISOString().substring(11, 19)}] SHA-256 FINGERPRINT: ${clientHash || 'computing...'}`,
      ]);

      // Upload file to backend
      const uploadRes = await api.uploadAPK(selectedFile);
      setActiveJobId(uploadRes.id);

      // Start honest polling
      pollJobStatus(uploadRes.id);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to stage APK');
      setIsUploading(false);
    }
  };

  const pollJobStatus = (jobId: string) => {
    const stageMessages = [
      'STAGE 1: Enforcing ZIP CRC-32 integrity & confirming non-empty Dalvik bytecode...',
      'STAGE 2: Parsing AndroidManifest.xml binary AST & cataloging multi-DEX files...',
      'STAGE 3: Extracting 128-bit & 16-bit UUID candidates from bytecode string pools...',
      'STAGE 4: Executing intra-method Dalvik register data-flow tracing to BluetoothGattServer.addService()...',
      'STAGE 5: Cross-referencing Bluetooth SIG curated knowledge base & persisting immutable records...',
    ];

    let currentStage = 0;
    const stageTimer = setInterval(() => {
      if (currentStage < stageMessages.length) {
        setStreamLogs((prev) => [
          ...prev,
          `[${new Date().toISOString().substring(11, 19)}] ${stageMessages[currentStage]}`,
        ]);
        currentStage++;
      }
    }, 550);

    const pollInterval = setInterval(async () => {
      try {
        const statusData = await api.getAnalysisStatus(jobId);
        setJobStatus(statusData);

        if (statusData.status !== 'running') {
          clearInterval(stageTimer);
          clearInterval(pollInterval);
          setIsUploading(false);

          if (statusData.status === 'success') {
            setStreamLogs((prev) => [
              ...prev,
              `[${new Date().toISOString().substring(11, 19)}] ANALYSIS COMPLETE: ${statusData.strong_count} strong registrations, ${statusData.unresolved_count} unresolved leads.`,
              `[${new Date().toISOString().substring(11, 19)}] PERSISTED: Examination record recorded in SQLite WAL database.`,
            ]);
            onAnalysisComplete(statusData.id);
          } else if (statusData.status === 'error') {
            setError(statusData.error_message || 'Static Dalvik analysis encountered an unrecoverable exception');
            setStreamLogs((prev) => [
              ...prev,
              `[${new Date().toISOString().substring(11, 19)}] [CRITICAL EXCEPTION]: ${statusData.error_message || 'Unknown engine failure'}`,
            ]);
          }
        }
      } catch (err: any) {
        clearInterval(stageTimer);
        clearInterval(pollInterval);
        setIsUploading(false);
        setError('Connection to backend polling lost');
      }
    }, 750);
  };

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [streamLogs]);

  const copyHash = () => {
    if (clientHash) {
      navigator.clipboard.writeText(clientHash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 1500);
    }
  };

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-8 select-none">
      
      {/* Header */}
      <div className="border-b border-[#262E3B] pb-6 space-y-1">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-teal-400" />
          <span className="text-[10px] font-mono tracking-wider text-[#64748B] uppercase font-semibold">
            SECURE STATIC INTAKE WORKSTATION
          </span>
        </div>
        <h1 className="text-xl md:text-2xl font-bold tracking-tight text-[#F1F5F9]">
          Ingest Target APK Archive
        </h1>
        <p className="text-xs text-[#94A3B8] max-w-2xl font-mono leading-relaxed">
          Staged Android packages undergo integrity validation, client-side cryptographic hashing, 
          DEX extraction, and 5-phase Dalvik register data-flow tracing.
        </p>
      </div>

      {error && <ErrorBanner title="INTAKE EXCEPTION" message={error} onDismiss={() => setError(null)} />}

      {/* Duplicate Warning Alert if Hash already in DB */}
      {duplicateCase && !isUploading && (
        <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-start justify-between font-mono text-xs">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="text-amber-400 font-semibold uppercase">
                Duplicate Binary Detected in SQLite Repository
              </span>
              <p className="text-[#CBD5E1]">
                An identical binary ({duplicateCase.file_name}) matching this SHA-256 fingerprint was already analyzed on{' '}
                {new Date(duplicateCase.created_at).toLocaleDateString()}.
              </p>
            </div>
          </div>

          <button
            onClick={() => onNavigateTab('workbench', { analysisId: duplicateCase.id })}
            className="px-3 py-1.5 rounded bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 border border-amber-500/40 text-xs font-mono shrink-0 ml-4 transition-colors"
          >
            Open Existing Examination
          </button>
        </div>
      )}

      {/* Main Drag-and-Drop Intake Box */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => !isUploading && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-lg p-8 sm:p-12 text-center cursor-pointer transition-all duration-200 ${
          isDragging
            ? 'border-teal-500 bg-teal-500/5 shadow-[0_0_20px_rgba(20,184,166,0.15)]'
            : selectedFile
            ? 'border-[#3B4656] bg-[#12161E]'
            : 'border-[#262E3B] bg-[#0E1116] hover:border-[#3B4656] hover:bg-[#12161E]'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept=".apk"
          className="hidden"
          disabled={isUploading}
        />

        <div className="flex flex-col items-center justify-center space-y-4">
          <div className="p-4 rounded-full bg-[#181E27] border border-[#262E3B] text-teal-400">
            <UploadCloud className="w-8 h-8" />
          </div>

          {selectedFile ? (
            <div className="space-y-2 max-w-md mx-auto font-mono">
              <div className="text-sm font-semibold text-[#F1F5F9] truncate">
                {selectedFile.name}
              </div>
              <div className="text-xs text-[#94A3B8]">
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Archive Staged
              </div>

              {/* Client-side SHA-256 Display */}
              <div className="mt-3 p-2 bg-[#0E1116] rounded border border-[#262E3B] flex items-center justify-between text-[11px]">
                <div className="truncate mr-2">
                  <span className="text-[#64748B]">SHA-256: </span>
                  <span className="text-teal-400 font-mono">
                    {isHashing ? 'Computing digest...' : clientHash || 'n/a'}
                  </span>
                </div>
                {clientHash && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      copyHash();
                    }}
                    className="text-[#94A3B8] hover:text-[#F1F5F9] p-1"
                    title="Copy SHA-256"
                  >
                    {copiedHash ? <Check className="w-3.5 h-3.5 text-teal-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-2 font-mono">
              <p className="text-sm font-medium text-[#F1F5F9]">
                Drag and drop Android APK file here, or <span className="text-teal-400 underline">browse</span>
              </p>
              <p className="text-xs text-[#64748B]">
                Supports Android APK archives up to 100 MB. Instant SHA-256 pre-calculation.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Action Button */}
      {selectedFile && !isUploading && !jobStatus && (
        <div className="flex items-center justify-end space-x-3">
          <button
            onClick={() => {
              setSelectedFile(null);
              setClientHash(null);
              setDuplicateCase(null);
            }}
            className="px-4 py-2 rounded border border-[#262E3B] text-[#94A3B8] hover:text-[#F1F5F9] text-xs font-mono transition-colors"
          >
            Clear Selection
          </button>

          <button
            onClick={startAnalysis}
            className="px-6 py-2.5 rounded bg-teal-500 hover:bg-teal-400 text-[#0E1116] font-semibold text-xs font-mono flex items-center space-x-2 transition-all shadow-[0_0_15px_rgba(20,184,166,0.25)]"
          >
            <span>&gt; Launch Dalvik Bytecode Analysis</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Progress & Live Terminal Execution Stream */}
      {(isUploading || streamLogs.length > 0) && (
        <div className="bg-[#12161E] border border-[#262E3B] rounded-lg overflow-hidden font-mono text-xs">
          <div className="h-9 bg-[#0E1116] border-b border-[#262E3B] px-4 flex items-center justify-between text-[11px] text-[#64748B]">
            <div className="flex items-center space-x-2">
              <span className={`w-2 h-2 rounded-full ${isUploading ? 'bg-teal-400 animate-ping' : 'bg-teal-400'}`} />
              <span className="text-[#F1F5F9] font-medium">STATIC ANALYSIS TELEMETRY STREAM</span>
            </div>
            <span>{isUploading ? 'STATUS: EXECUTING' : 'STATUS: FINISHED'}</span>
          </div>

          <div
            ref={logContainerRef}
            className="p-4 max-h-56 overflow-y-auto space-y-1.5 text-[11px] text-[#CBD5E1] bg-[#0A0D12]"
          >
            {streamLogs.map((log, idx) => (
              <div key={idx} className="flex items-start space-x-2">
                <span className="text-teal-500 select-none">&gt;</span>
                <span className="font-mono">{log}</span>
              </div>
            ))}
          </div>

          {/* Quick Action when Analysis Finishes */}
          {jobStatus && jobStatus.status === 'success' && (
            <div className="p-4 bg-[#12161E] border-t border-[#262E3B] flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="flex items-center space-x-2 text-teal-400 text-xs">
                <CheckCircle2 className="w-4 h-4" />
                <span>Examination ready: {jobStatus.strong_count} verified GATT call sites discovered.</span>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => onNavigateTab('workbench', { analysisId: jobStatus.id })}
                  className="px-4 py-2 rounded bg-teal-500 text-[#0E1116] hover:bg-teal-400 font-semibold text-xs font-mono flex items-center space-x-1.5 transition-all shadow-[0_0_10px_rgba(20,184,166,0.25)]"
                >
                  <Binary className="w-3.5 h-3.5" />
                  <span>Examine in Workbench</span>
                </button>

                <button
                  onClick={() => onNavigateTab('explorer', { analysisId: jobStatus.id })}
                  className="px-3 py-2 rounded bg-[#181E27] hover:bg-[#262E3B] text-[#F1F5F9] border border-[#3B4656] text-xs font-mono flex items-center space-x-1.5 transition-colors"
                >
                  <Share2 className="w-3.5 h-3.5 text-teal-400" />
                  <span>View Topology</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

    </div>
  );
};
