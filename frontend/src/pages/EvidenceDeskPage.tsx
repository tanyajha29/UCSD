import React, { useEffect, useState } from 'react';
import {
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Binary,
  Share2,
  FileText,
  UploadCloud,
  FolderArchive,
  Database,
  Search,
  ExternalLink,
  AlertTriangle,
  Clock,
  Layers,
} from 'lucide-react';
import { api } from '../api/client';
import { DashboardStats, AnalysisSummary } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';
import { NavTab } from '../components/SidebarNav';

interface EvidenceDeskPageProps {
  onNavigate: (tab: NavTab, params?: { analysisId?: string }) => void;
  onSelectCase: (caseId: string) => void;
}

export const EvidenceDeskPage: React.FC<EvidenceDeskPageProps> = ({
  onNavigate,
  onSelectCase,
}) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const fetchStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to UCSD backend engine');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="h-[60vh] flex items-center justify-center">
        <LoadingSpinner message="INITIALIZING FORENSIC EVIDENCE DESK..." size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-6xl mx-auto p-6 space-y-4">
        <ErrorBanner title="TELEMETRY CONNECTION EXCEPTION" message={error} onDismiss={() => setError(null)} />
        <button
          onClick={fetchStats}
          className="px-4 py-2 border border-teal-500/40 bg-teal-500/10 hover:bg-teal-500/20 text-teal-400 font-mono text-xs rounded transition-colors"
        >
          &gt; Reconnect Analysis Engine
        </button>
      </div>
    );
  }

  const isEmpty = !stats || stats.total_apks === 0;
  const recentCases = stats?.recent_analyses || [];

  // Filter cases by query
  const filteredCases = recentCases.filter((c) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.file_name.toLowerCase().includes(q) ||
      (c.package_name && c.package_name.toLowerCase().includes(q)) ||
      (c.sha256 && c.sha256.toLowerCase().includes(q))
    );
  });

  // Actionable leads: cases with strong registrations or unresolved patterns
  const actionableLeads = recentCases.filter((c) => c.strong_count > 0 || c.unresolved_count > 0);

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-8 select-none">
      
      {/* 1. Evidence Desk Header & Operational Readout */}
      <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-6 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-1.5">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-teal-400" />
            <span className="text-[10px] font-mono tracking-wider text-[#64748B] uppercase font-semibold">
              FORENSIC CASE MANAGEMENT & EVIDENCE DESK
            </span>
          </div>

          <h1 className="text-xl md:text-2xl font-bold tracking-tight text-[#F1F5F9]">
            Universal Candidate Service Detector
          </h1>

          <p className="text-xs text-[#94A3B8] max-w-2xl leading-relaxed font-mono">
            Ground-truth Dalvik bytecode static analysis isolating Bluetooth GATT service registrations, 
            intra-method register traces, and multi-APK collision conflicts.
          </p>
        </div>

        {/* Quick Actions */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0">
          <button
            onClick={() => onNavigate('intake')}
            className="px-4 py-2.5 rounded bg-teal-500 text-[#0E1116] hover:bg-teal-400 font-semibold text-xs font-mono flex items-center justify-center space-x-2 transition-all shadow-[0_0_12px_rgba(20,184,166,0.25)]"
          >
            <UploadCloud className="w-4 h-4" />
            <span>+ Intake APK Target</span>
          </button>

          {recentCases.length > 0 && (
            <button
              onClick={() => {
                onSelectCase(recentCases[0].id);
                onNavigate('workbench');
              }}
              className="px-4 py-2.5 rounded bg-[#181E27] hover:bg-[#262E3B] text-[#F1F5F9] border border-[#3B4656] text-xs font-mono flex items-center justify-center space-x-2 transition-colors"
            >
              <Binary className="w-4 h-4 text-teal-400" />
              <span>Open Workbench</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Key Forensic Counts Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-4 font-mono">
          <div className="text-[10px] text-[#64748B] uppercase tracking-wider">Total Targets Ingested</div>
          <div className="text-2xl font-bold text-[#F1F5F9] mt-1">{stats?.total_apks || 0}</div>
          <div className="text-[10px] text-[#94A3B8] mt-1">
            {stats?.successful_analyses || 0} analyzed • {stats?.failed_analyses || 0} errors
          </div>
        </div>

        <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-4 font-mono">
          <div className="text-[10px] text-teal-400 uppercase tracking-wider">Strong Registrations</div>
          <div className="text-2xl font-bold text-teal-400 mt-1">{stats?.strong_static_registrations || 0}</div>
          <div className="text-[10px] text-[#94A3B8] mt-1">
            Verified addService() linkage
          </div>
        </div>

        <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-4 font-mono">
          <div className="text-[10px] text-amber-400 uppercase tracking-wider">Unresolved Patterns</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">{stats?.unresolved_patterns || 0}</div>
          <div className="text-[10px] text-[#94A3B8] mt-1">
            Cross-method or field leads
          </div>
        </div>

        <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-4 font-mono">
          <div className="text-[10px] text-red-400 uppercase tracking-wider">Cross-APK Collisions</div>
          <div className="text-2xl font-bold text-red-400 mt-1">{stats?.cross_apk_conflicts || 0}</div>
          <div className="text-[10px] text-[#94A3B8] mt-1">
            {stats?.total_comparisons || 0} evaluated matrix jobs
          </div>
        </div>
      </div>

      {isEmpty ? (
        /* Empty Onboarding State */
        <div className="bg-[#12161E] border border-[#262E3B] rounded-lg p-10 text-center space-y-6 max-w-2xl mx-auto font-mono">
          <FolderArchive className="w-12 h-12 text-[#64748B] mx-auto opacity-70" />
          <div className="space-y-2">
            <h2 className="text-base font-semibold text-[#F1F5F9]">Evidence Repository is Empty</h2>
            <p className="text-xs text-[#94A3B8] leading-relaxed">
              No Android application packages have been ingested into the persistent SQLite database yet. 
              Intake your first APK to run automated Dalvik decompilation and inspect GATT service registrations.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-left pt-2">
            <div className="p-3 bg-[#0E1116] border border-[#262E3B] rounded">
              <span className="text-teal-400 font-bold text-xs">01. INGEST</span>
              <p className="text-[10px] text-[#94A3B8] mt-1">Upload target APK with client-side SHA-256 pre-calculation.</p>
            </div>
            <div className="p-3 bg-[#0E1116] border border-[#262E3B] rounded">
              <span className="text-teal-400 font-bold text-xs">02. TRACE</span>
              <p className="text-[10px] text-[#94A3B8] mt-1">Intra-method register tracing connects UUID literals to addService.</p>
            </div>
            <div className="p-3 bg-[#0E1116] border border-[#262E3B] rounded">
              <span className="text-teal-400 font-bold text-xs">03. DISASSEMBLE</span>
              <p className="text-[10px] text-[#94A3B8] mt-1">Inspect raw Dalvik opcodes and topology relationships.</p>
            </div>
          </div>

          <button
            onClick={() => onNavigate('intake')}
            className="px-5 py-2.5 rounded bg-teal-500 text-[#0E1116] hover:bg-teal-400 font-semibold text-xs font-mono inline-flex items-center space-x-2 transition-all shadow-[0_0_12px_rgba(20,184,166,0.3)]"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Intake First APK Target</span>
          </button>
        </div>
      ) : (
        <>
          {/* 3. Actionable Leads Queue (APKs needing reverse-engineering review) */}
          {actionableLeads.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono tracking-wider text-[#64748B] uppercase font-semibold">
                  ACTIONABLE FORENSIC LEADS ({actionableLeads.length})
                </span>
                <span className="text-[10px] font-mono text-[#94A3B8]">
                  Verified GATT service call sites requiring review
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {actionableLeads.map((c) => (
                  <div
                    key={`lead-${c.id}`}
                    className="bg-[#12161E] border border-[#262E3B] hover:border-[#3B4656] rounded-lg p-4 font-mono transition-all flex flex-col justify-between space-y-3"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-semibold text-[#F1F5F9] truncate mr-2" title={c.file_name}>
                          {c.file_name}
                        </span>
                        {c.strong_count > 0 ? (
                          <span className="px-1.5 py-0.2 rounded text-[9px] bg-teal-500/15 text-teal-400 border border-teal-500/30">
                            {c.strong_count} STRONG
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.2 rounded text-[9px] bg-amber-500/15 text-amber-400 border border-amber-500/30">
                            {c.unresolved_count} UNRESOLVED
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] text-[#94A3B8] truncate">
                        {c.package_name || 'Unresolved package'}
                      </div>

                      <div className="text-[10px] text-[#64748B] mt-1">
                        SHA-256: {c.sha256 ? `${c.sha256.substring(0, 14)}...` : 'n/a'}
                      </div>
                    </div>

                    <div className="pt-2 border-t border-[#262E3B] flex items-center space-x-2">
                      <button
                        onClick={() => {
                          onSelectCase(c.id);
                          onNavigate('workbench', { analysisId: c.id });
                        }}
                        className="flex-1 py-1.5 px-2 rounded bg-[#181E27] hover:bg-[#262E3B] text-teal-400 text-xs font-mono flex items-center justify-center space-x-1.5 border border-[#3B4656] transition-colors"
                      >
                        <Binary className="w-3.5 h-3.5" />
                        <span>Disassemble</span>
                      </button>

                      <button
                        onClick={() => {
                          onSelectCase(c.id);
                          onNavigate('explorer', { analysisId: c.id });
                        }}
                        className="py-1.5 px-2.5 rounded bg-[#181E27] hover:bg-[#262E3B] text-[#94A3B8] hover:text-[#F1F5F9] text-xs font-mono border border-[#3B4656] transition-colors"
                        title="View Topology Graph"
                      >
                        <Share2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 4. Complete Chronological Forensic Case Dossier Table */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <span className="text-[11px] font-mono tracking-wider text-[#64748B] uppercase font-semibold">
                PERSISTENT CASE DOSSIER ({filteredCases.length})
              </span>

              <div className="relative w-full sm:w-72">
                <Search className="w-3.5 h-3.5 text-[#64748B] absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search by binary, package, or hash..."
                  className="w-full pl-8 pr-3 py-1 bg-[#12161E] border border-[#262E3B] rounded text-xs font-mono text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-teal-500"
                />
              </div>
            </div>

            <div className="bg-[#12161E] border border-[#262E3B] rounded-lg overflow-hidden font-mono text-xs">
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead className="bg-[#0E1116] border-b border-[#262E3B] text-[#64748B] text-[10px] uppercase">
                    <tr>
                      <th className="py-2.5 px-4">Target Binary</th>
                      <th className="py-2.5 px-4">Package Identity</th>
                      <th className="py-2.5 px-4">SHA-256 Digest</th>
                      <th className="py-2.5 px-4">Discovered Evidence</th>
                      <th className="py-2.5 px-4">Timestamp</th>
                      <th className="py-2.5 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#262E3B]/60">
                    {filteredCases.map((c) => (
                      <tr
                        key={c.id}
                        className="hover:bg-[#181E27] transition-colors"
                      >
                        <td className="py-3 px-4">
                          <div className="font-semibold text-[#F1F5F9]">{c.file_name}</div>
                          <div className="text-[10px] text-[#64748B]">
                            {(c.file_size_bytes / (1024 * 1024)).toFixed(2)} MB
                          </div>
                        </td>

                        <td className="py-3 px-4">
                          <div className="text-[#94A3B8] truncate max-w-xs">{c.package_name || 'N/A'}</div>
                          <div className="text-[10px] text-[#64748B]">
                            {c.version_name ? `v${c.version_name}` : ''}
                          </div>
                        </td>

                        <td className="py-3 px-4 text-[#64748B] font-mono text-[11px]">
                          {c.sha256 ? `${c.sha256.substring(0, 16)}...` : 'n/a'}
                        </td>

                        <td className="py-3 px-4">
                          <div className="flex items-center space-x-1.5">
                            {c.strong_count > 0 && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] bg-teal-500/15 text-teal-400 border border-teal-500/30">
                                {c.strong_count} STRONG
                              </span>
                            )}
                            {c.unresolved_count > 0 && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] bg-amber-500/15 text-amber-400 border border-amber-500/30">
                                {c.unresolved_count} UNRESOLVED
                              </span>
                            )}
                            {c.candidate_count > 0 && c.strong_count === 0 && c.unresolved_count === 0 && (
                              <span className="text-[10px] text-[#64748B]">
                                {c.candidate_count} CANDIDATES
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-3 px-4 text-[#64748B] text-[10px]">
                          {new Date(c.created_at).toLocaleString()}
                        </td>

                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end space-x-2">
                            <button
                              onClick={() => {
                                onSelectCase(c.id);
                                onNavigate('workbench', { analysisId: c.id });
                              }}
                              className="px-2.5 py-1 rounded bg-[#181E27] hover:bg-[#262E3B] text-teal-400 text-xs font-mono border border-[#3B4656] transition-colors"
                            >
                              Examine
                            </button>
                            <button
                              onClick={() => {
                                onSelectCase(c.id);
                                onNavigate('explorer', { analysisId: c.id });
                              }}
                              className="p-1 rounded bg-[#181E27] hover:bg-[#262E3B] text-[#94A3B8] hover:text-[#F1F5F9] border border-[#3B4656] transition-colors"
                              title="View Relationship Graph"
                            >
                              <Share2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}

    </div>
  );
};
