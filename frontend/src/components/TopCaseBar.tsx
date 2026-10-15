import React, { useState, useEffect, useRef } from 'react';
import {
  FolderArchive,
  ChevronDown,
  Search,
  Command,
  PlusCircle,
  Binary,
  Share2,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Copy,
  Check,
} from 'lucide-react';
import { AnalysisSummary, SystemHealth } from '../types';
import { api } from '../api/client';
import { NavTab } from './SidebarNav';

interface TopCaseBarProps {
  activeCaseId: string | null;
  onSelectCase: (caseId: string | null) => void;
  onNavigateTab: (tab: NavTab) => void;
  onOpenCommandPalette: () => void;
  health: SystemHealth | null;
}

export const TopCaseBar: React.FC<TopCaseBarProps> = ({
  activeCaseId,
  onSelectCase,
  onNavigateTab,
  onOpenCommandPalette,
  health,
}) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [cases, setCases] = useState<AnalysisSummary[]>([]);
  const [searchFilter, setSearchFilter] = useState('');
  const [copiedHash, setCopiedHash] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Refresh cases on mount or dropdown open
    const loadCases = async () => {
      try {
        const res = await api.listAnalyses(1, 30);
        setCases(res.items);
      } catch (err) {
        console.warn('Failed to fetch case list for top bar', err);
      }
    };
    loadCases();
  }, [dropdownOpen, activeCaseId]);

  // Click outside listener for dropdown
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    };
    if (dropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [dropdownOpen]);

  const activeCase = cases.find((c) => c.id === activeCaseId);

  const filteredCases = cases.filter(
    (c) =>
      c.file_name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      (c.package_name && c.package_name.toLowerCase().includes(searchFilter.toLowerCase())) ||
      (c.sha256 && c.sha256.toLowerCase().includes(searchFilter.toLowerCase()))
  );

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 1500);
  };

  const isHealthy = health?.status === 'healthy';

  return (
    <header className="h-14 bg-[#0E1116] border-b border-[#262E3B] px-4 flex items-center justify-between select-none z-20">
      
      {/* Left: Active Investigation / Case Selector Dropdown */}
      <div className="relative flex items-center space-x-3" ref={dropdownRef}>
        <div className="flex items-center space-x-2">
          <span className="text-[10px] font-mono tracking-wider text-[#64748B] uppercase hidden sm:inline">
            INVESTIGATION:
          </span>

          <button
            onClick={() => setDropdownOpen((prev) => !prev)}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded border text-xs font-mono transition-all ${
              activeCase
                ? 'bg-[#151921] border-[#3B4656] text-[#F1F5F9] hover:border-[#14B8A6]'
                : 'bg-[#151921] border-[#262E3B] text-[#94A3B8] hover:border-[#3B4656]'
            }`}
          >
            <FolderArchive className="w-3.5 h-3.5 text-[#14B8A6] shrink-0" />
            
            {activeCase ? (
              <div className="flex items-center space-x-2 truncate max-w-[260px] md:max-w-[340px]">
                <span className="truncate font-medium text-[#F1F5F9]">{activeCase.file_name}</span>
                {activeCase.sha256 && (
                  <span className="text-[10px] text-[#64748B] font-mono hidden md:inline">
                    [{activeCase.sha256.substring(0, 8)}]
                  </span>
                )}
                {activeCase.strong_count > 0 && (
                  <span className="px-1.5 py-0.2 rounded text-[9px] bg-teal-500/15 text-teal-400 border border-teal-500/30">
                    {activeCase.strong_count} STRONG
                  </span>
                )}
              </div>
            ) : (
              <span className="text-[#94A3B8]">Select Investigation Case...</span>
            )}

            <ChevronDown className={`w-3.5 h-3.5 text-[#64748B] transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
          </button>
        </div>

        {/* Quick Hash Copy button */}
        {activeCase?.sha256 && (
          <button
            onClick={() => copyHash(activeCase.sha256!)}
            title="Copy full SHA-256 fingerprint"
            className="p-1.5 rounded hover:bg-[#151921] text-[#64748B] hover:text-[#94A3B8] border border-transparent hover:border-[#262E3B] transition-colors hidden lg:flex items-center"
          >
            {copiedHash ? <Check className="w-3 h-3 text-[#14B8A6]" /> : <Copy className="w-3 h-3" />}
          </button>
        )}

        {/* Case Switcher Dropdown Menu */}
        {dropdownOpen && (
          <div className="absolute top-full left-0 mt-1.5 w-96 bg-[#151921] border border-[#262E3B] rounded-lg shadow-2xl p-2 z-50">
            {/* Search Input */}
            <div className="relative mb-2">
              <Search className="w-3.5 h-3.5 text-[#64748B] absolute left-2.5 top-2.5" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Filter cases by filename or hash..."
                className="w-full pl-8 pr-3 py-1.5 bg-[#0E1116] border border-[#262E3B] rounded text-xs font-mono text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#14B8A6]"
                autoFocus
              />
            </div>

            {/* Case List */}
            <div className="max-h-64 overflow-y-auto space-y-1">
              {filteredCases.length === 0 ? (
                <div className="p-3 text-center text-xs font-mono text-[#64748B]">
                  No matching analysis cases found
                </div>
              ) : (
                filteredCases.map((c) => {
                  const isCurrent = c.id === activeCaseId;
                  return (
                    <div
                      key={c.id}
                      onClick={() => {
                        onSelectCase(c.id);
                        setDropdownOpen(false);
                      }}
                      className={`p-2 rounded cursor-pointer transition-colors text-xs font-mono flex items-center justify-between ${
                        isCurrent
                          ? 'bg-[#1C222B] border-l-2 border-[#14B8A6] text-[#F1F5F9]'
                          : 'text-[#94A3B8] hover:bg-[#1C222B]/60 hover:text-[#F1F5F9]'
                      }`}
                    >
                      <div className="truncate mr-2">
                        <div className="font-medium text-[#F1F5F9] truncate">{c.file_name}</div>
                        <div className="text-[10px] text-[#64748B] truncate">
                          {c.package_name || 'No package'} • {c.sha256 ? c.sha256.substring(0, 10) : 'n/a'}
                        </div>
                      </div>

                      <div className="shrink-0 flex items-center space-x-1">
                        {c.strong_count > 0 ? (
                          <span className="px-1.5 py-0.2 rounded text-[9px] bg-teal-500/15 text-teal-400 border border-teal-500/30">
                            {c.strong_count} STRONG
                          </span>
                        ) : c.unresolved_count > 0 ? (
                          <span className="px-1.5 py-0.2 rounded text-[9px] bg-amber-500/15 text-amber-400 border border-amber-500/30">
                            {c.unresolved_count} UNRESOLVED
                          </span>
                        ) : (
                          <span className="text-[10px] text-[#64748B]">
                            {c.candidate_count} CANDIDATES
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Quick Intake Button */}
            <div className="pt-2 mt-2 border-t border-[#262E3B] flex items-center justify-between">
              <button
                onClick={() => {
                  setDropdownOpen(false);
                  onNavigateTab('intake');
                }}
                className="w-full flex items-center justify-center space-x-1.5 py-1.5 rounded bg-[#1C222B] hover:bg-[#262E3B] text-xs font-mono text-[#14B8A6] transition-colors"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>+ Intake New APK Case</span>
              </button>
            </div>
          </div>
        )}

        {/* Quick Context Action Pills (When case is active) */}
        {activeCase && (
          <div className="hidden xl:flex items-center space-x-1 border-l border-[#262E3B] pl-3">
            <button
              onClick={() => onNavigateTab('workbench')}
              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-[#151921] hover:bg-[#1C222B] text-[#94A3B8] hover:text-[#14B8A6] text-[11px] font-mono border border-[#262E3B] transition-colors"
              title="Open active case in Dalvik Workbench"
            >
              <Binary className="w-3 h-3 text-[#14B8A6]" />
              <span>Disassembly</span>
            </button>
            <button
              onClick={() => onNavigateTab('explorer')}
              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-[#151921] hover:bg-[#1C222B] text-[#94A3B8] hover:text-[#14B8A6] text-[11px] font-mono border border-[#262E3B] transition-colors"
              title="Explore relationship graph topology"
            >
              <Share2 className="w-3 h-3 text-[#14B8A6]" />
              <span>Topology</span>
            </button>
          </div>
        )}
      </div>

      {/* Right: Engine Status Pill & Command Palette Launcher */}
      <div className="flex items-center space-x-3">
        {/* Engine Status Pill */}
        <div className="flex items-center space-x-2 px-2.5 py-1 rounded bg-[#151921] border border-[#262E3B]">
          <span className="relative flex h-2 w-2">
            {isHealthy ? (
              <>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-teal-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-teal-500" />
              </>
            ) : (
              <>
                <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
              </>
            )}
          </span>
          <span
            className={`text-[10px] font-mono tracking-wider font-medium ${
              isHealthy ? 'text-teal-400' : 'text-red-400'
            }`}
          >
            {isHealthy ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}
          </span>
          <span className="text-[10px] font-mono text-[#64748B] hidden md:inline">
            • WAL
          </span>
        </div>

        {/* Command Palette Trigger */}
        <button
          onClick={onOpenCommandPalette}
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded border border-[#262E3B] bg-[#151921] hover:border-[#3B4656] text-[#94A3B8] hover:text-[#F1F5F9] transition-colors"
          title="Open Forensic Command Palette (Ctrl+K / ⌘K)"
        >
          <Command className="w-3 h-3 text-[#64748B]" />
          <span className="text-[10px] font-mono">⌘K</span>
        </button>
      </div>

    </header>
  );
};
