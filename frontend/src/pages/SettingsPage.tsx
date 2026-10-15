import React, { useEffect, useState } from 'react';
import {
  Settings,
  Shield,
  BookOpen,
  Database,
  ExternalLink,
  Server,
  Lock,
  Copy,
  Check,
  Search,
  Keyboard,
} from 'lucide-react';
import { api } from '../api/client';
import { KnowledgeBaseEntry, SystemHealth } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';

export const SettingsPage: React.FC = () => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [kbEntries, setKbEntries] = useState<KnowledgeBaseEntry[]>([]);
  const [kbMeta, setKbMeta] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [copiedUuid, setCopiedUuid] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState('');

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        setLoading(true);
        const [hData, kbData] = await Promise.all([
          api.getHealth(),
          api.getKnowledgeBase(),
        ]);
        setHealth(hData);
        setKbEntries(kbData.entries);
        setKbMeta(kbData.metadata);
      } catch (err) {
        console.error('Failed to load settings data', err);
      } finally {
        setLoading(false);
      }
    };

    fetchSettings();
  }, []);

  const handleCopy = (uuid: string) => {
    navigator.clipboard.writeText(uuid);
    setCopiedUuid(uuid);
    setTimeout(() => setCopiedUuid(null), 1800);
  };

  if (loading) {
    return <LoadingSpinner message="INDEXING SYSTEM PROVENANCE & BLUETOOTH SIG DATASET..." size="lg" />;
  }

  const filteredEntries = kbEntries.filter((e) =>
    e.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
    e.normalized_uuid.toLowerCase().includes(searchFilter.toLowerCase()) ||
    e.source_name.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* 1. Header */}
      <div className="border-b border-[#1A2332] pb-6">
        <div className="flex items-center space-x-2 mb-1">
          <span className="w-2 h-2 rounded-full bg-[#00E5A0]" />
          <span className="text-[11px] font-mono tracking-tracked text-[#7A8794] uppercase font-semibold">
            SYSTEM PROVENANCE & RIGOR SPECIFICATIONS
          </span>
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-[#E8EDF2]">
          Engine Architecture & Bluetooth SIG Registry
        </h1>
        <p className="text-xs text-[#7A8794] mt-1 font-mono">
          Authoritative standards lookup, Dalvik register tracker configuration, and evidence-chain ethical boundaries.
        </p>
      </div>

      {/* 2. Three Terminal Readout Modules */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Module 1: Core Analyzer */}
        <div className="bg-[#0B0F14] border border-[#1A2332] hover:border-[#2A3A4F] rounded-lg p-5 space-y-2 font-mono transition-colors">
          <div className="flex items-center justify-between text-[#7A8794] text-[10px] uppercase tracking-wider">
            <span>CORE ANALYZER ENGINE</span>
            <Server className="w-3.5 h-3.5 text-[#00E5A0]" />
          </div>
          <div className="text-xl font-bold text-[#00E5A0] tracking-tight">
            v{health?.analyzer_version || '0.1.0'}
          </div>
          <p className="text-[11px] text-[#7A8794] leading-relaxed">
            Intra-method Dalvik register data-flow tracer with AXML manifest decoder & ZIP integrity verifier.
          </p>
        </div>

        {/* Module 2: Persistence Layer */}
        <div className="bg-[#0B0F14] border border-[#1A2332] hover:border-[#2A3A4F] rounded-lg p-5 space-y-2 font-mono transition-colors">
          <div className="flex items-center justify-between text-[#7A8794] text-[10px] uppercase tracking-wider">
            <span>PERSISTENCE LAYER</span>
            <Database className="w-3.5 h-3.5 text-[#4DA6FF]" />
          </div>
          <div className="text-xl font-bold text-[#E8EDF2] tracking-tight">
            SQLite (WAL MODE)
          </div>
          <p className="text-[11px] text-[#7A8794] leading-relaxed">
            Thread-safe write-ahead logging with volume-mounted storage at <code className="text-[#C5D0DA]">/app/data/db</code>.
          </p>
        </div>

        {/* Module 3: Security & Sandboxing */}
        <div className="bg-[#0B0F14] border border-[#1A2332] hover:border-[#2A3A4F] rounded-lg p-5 space-y-2 font-mono transition-colors">
          <div className="flex items-center justify-between text-[#7A8794] text-[10px] uppercase tracking-wider">
            <span>SECURITY & SANDBOXING</span>
            <Shield className="w-3.5 h-3.5 text-[#FFB020]" />
          </div>
          <div className="text-xl font-bold text-[#E8EDF2] tracking-tight">
            NON-EXECUTING INTAKE
          </div>
          <p className="text-[11px] text-[#7A8794] leading-relaxed">
            Pure static analysis. Zero dynamic execution or hooking. 100MB staging guardrail with path sanitization.
          </p>
        </div>

      </div>

      {/* 3. Keyboard Shortcuts Specification */}
      <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg p-5 space-y-3 font-mono">
        <div className="flex items-center space-x-2">
          <Keyboard className="w-4 h-4 text-[#00E5A0]" />
          <span className="text-xs font-semibold text-[#E8EDF2] tracking-tight uppercase">
            FORENSIC WORKSTATION KEYBOARD SHORTCUTS
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 pt-2">
          {[
            { key: 'G', label: 'Dashboard' },
            { key: 'N', label: 'New Analysis' },
            { key: 'C', label: 'Collision Matrix' },
            { key: 'H', label: 'Evidence Ledger' },
            { key: 'R', label: 'Reports Archive' },
            { key: 'S', label: 'Settings & KB' },
            { key: '⌘K', label: 'Command Palette' },
          ].map((item) => (
            <div
              key={item.key}
              className="p-2.5 rounded bg-[#05070A] border border-[#1A2332] flex items-center justify-between"
            >
              <kbd className="px-1.5 py-0.5 rounded bg-[#11171F] border border-[#2A3A4F] text-[#00E5A0] text-xs font-bold shadow-sm">
                {item.key}
              </kbd>
              <span className="text-[10px] text-[#7A8794] truncate ml-2">
                {item.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* 4. Curated Bluetooth SIG Knowledge Base Browser */}
      <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg overflow-hidden space-y-0">
        
        <div className="p-5 border-b border-[#1A2332] flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0B0F14]">
          <div>
            <div className="flex items-center space-x-2">
              <BookOpen className="w-4 h-4 text-[#00E5A0]" />
              <h2 className="text-xs font-mono tracking-tracked text-[#E8EDF2] uppercase font-semibold">
                CURATED BLUETOOTH SIG & VENDOR REGISTRY SPECIFICATION
              </h2>
            </div>
            <p className="text-xs text-[#7A8794] mt-0.5 font-mono">
              Version {kbMeta?.knowledge_base_version || '1.0.0'} ({kbEntries.length} verified identifiers with authoritative provenance).
            </p>
          </div>

          {/* Search Filter */}
          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 text-[#7A8794] absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter specifications..."
              className="w-full pl-9 pr-3 py-1.5 bg-[#05070A] border border-[#1A2332] rounded text-xs font-mono text-[#E8EDF2] placeholder-[#7A8794] focus:outline-none focus:border-[#00E5A0]"
            />
          </div>
        </div>

        {/* Specification Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#05070A] text-[#7A8794] uppercase text-[10px] tracking-wider border-b border-[#1A2332]">
              <tr>
                <th className="py-3 px-4">Standard Specification Name</th>
                <th className="py-3 px-4">Canonical 128-bit UUID</th>
                <th className="py-3 px-4">Provenance Authority</th>
                <th className="py-3 px-4 text-right">Official Document</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1A2332] text-[#C5D0DA]">
              {filteredEntries.map((e) => {
                const isCopied = copiedUuid === e.normalized_uuid;
                return (
                  <tr key={e.normalized_uuid} className="hover:bg-[#11171F] transition-colors group">
                    <td className="py-3 px-4 font-semibold text-[#E8EDF2]">
                      <div className="flex items-center space-x-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#00E5A0]" />
                        <span>{e.name}</span>
                      </div>
                    </td>

                    {/* UUID with Copy on Hover */}
                    <td className="py-3 px-4 text-[#00E5A0] font-mono">
                      <div className="flex items-center space-x-2">
                        <span>{e.normalized_uuid}</span>
                        <button
                          onClick={() => handleCopy(e.normalized_uuid)}
                          className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-[#1A2332] text-[#7A8794] hover:text-[#00E5A0] transition-all"
                          title="Copy UUID to clipboard"
                        >
                          {isCopied ? (
                            <Check className="w-3.5 h-3.5 text-[#00E5A0]" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        {isCopied && (
                          <span className="text-[9px] text-[#00E5A0] font-mono animate-fade-in">
                            COPIED
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-[#7A8794]">
                      {e.source_name}
                    </td>

                    <td className="py-3 px-4 text-right">
                      {e.source_url ? (
                        <a
                          href={e.source_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#4DA6FF] hover:text-[#00E5A0] inline-flex items-center space-x-1"
                        >
                          <span>DOC</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      ) : (
                        <span className="text-[#7A8794]/60">PROPRIETARY</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

      </div>

      {/* 5. Ethical Boundaries & Limitations */}
      <div className="bg-[#0B0F14] border border-[#1A2332] rounded-lg p-6 space-y-4 font-mono text-xs">
        <div className="flex items-center space-x-2 text-[#E8EDF2]">
          <Lock className="w-4 h-4 text-[#00E5A0]" />
          <span className="font-semibold uppercase tracking-tight">
            ETHICAL BOUNDARIES & STATIC ANALYSIS LIMITATIONS
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-[#7A8794] leading-relaxed pt-2">
          <div className="space-y-1.5 border-l-2 border-[#1A2332] pl-3">
            <span className="text-[10px] font-bold text-[#E8EDF2] uppercase block">
              Defensive Research Scope
            </span>
            <p>
              UCSD is engineered exclusively for defensive static auditing, application verification, and pre-release vetting. 
              A static registration collision does not prove runtime exploitation or malicious intent.
            </p>
          </div>

          <div className="space-y-1.5 border-l-2 border-[#1A2332] pl-3">
            <span className="text-[10px] font-bold text-[#E8EDF2] uppercase block">
              Static Dalvik Bytecode Integrity
            </span>
            <p>
              Intra-method register tracing models Dalvik forward register simulation within individual method bodies. 
              It deliberately classifies cross-method, field-stored, and dynamic reflection instances as unresolved.
            </p>
          </div>
        </div>
      </div>

    </div>
  );
};
