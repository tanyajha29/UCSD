import React, { useState, useEffect, useRef } from 'react';
import { 
  Search, 
  Terminal, 
  FileCode, 
  Layers, 
  History as HistoryIcon, 
  FileText, 
  Settings, 
  Upload, 
  ShieldCheck, 
  BookOpen, 
  ArrowRight,
  Database,
  Binary,
  Share2,
} from 'lucide-react';
import { NavTab } from './SidebarNav';
import { api } from '../api/client';
import { AnalysisSummary } from '../types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (tab: NavTab, params?: { analysisId?: string }) => void;
}

interface CommandItem {
  id: string;
  category: 'NAVIGATION' | 'ACTIONS' | 'ANALYSES';
  title: string;
  subtitle?: string;
  icon: React.ComponentType<{ className?: string }>;
  action: () => void;
  badge?: string;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({ isOpen, onClose, onNavigate }) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [recentAnalyses, setRecentAnalyses] = useState<AnalysisSummary[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);

      // Fetch recent analyses for quick jumping
      api.listAnalyses(1, 10).then((res) => {
        setRecentAnalyses(res.items);
      }).catch(() => setRecentAnalyses([]));
    }
  }, [isOpen]);

  const defaultCommands: CommandItem[] = [
    {
      id: 'nav-desk',
      category: 'NAVIGATION',
      title: 'Evidence Desk',
      subtitle: 'Overview of static Dalvik findings, case dossiers, and triage queue',
      icon: Terminal,
      action: () => { onNavigate('desk'); onClose(); },
      badge: '1',
    },
    {
      id: 'nav-intake',
      category: 'NAVIGATION',
      title: 'APK Intake Workstation',
      subtitle: 'Stage binary for 5-phase Dalvik decompilation and SHA-256 validation',
      icon: Upload,
      action: () => { onNavigate('intake'); onClose(); },
      badge: '2',
    },
    {
      id: 'nav-workbench',
      category: 'NAVIGATION',
      title: 'Dalvik Workbench (Disassembly IDE)',
      subtitle: 'Monospace bytecode disassembly, hex offsets, and register data-flow traces',
      icon: Binary,
      action: () => { onNavigate('workbench'); onClose(); },
      badge: '3',
    },
    {
      id: 'nav-explorer',
      category: 'NAVIGATION',
      title: 'Relationship Explorer (Topology)',
      subtitle: 'Interactive SVG node-link graph connecting APK, class, registration, and UUID',
      icon: Share2,
      action: () => { onNavigate('explorer'); onClose(); },
      badge: '4',
    },
    {
      id: 'nav-comparison',
      category: 'NAVIGATION',
      title: 'Cross-APK Conflict Matrix',
      subtitle: 'Evaluate static duplicate registrations across multiple APK binaries',
      icon: Layers,
      action: () => { onNavigate('compare'); onClose(); },
      badge: '5',
    },
    {
      id: 'nav-history',
      category: 'NAVIGATION',
      title: 'Forensic Ledger / History',
      subtitle: 'Browse persistent SQLite records of analyzed binaries',
      icon: Database,
      action: () => { onNavigate('history'); onClose(); },
      badge: '6',
    },
    {
      id: 'nav-reports',
      category: 'NAVIGATION',
      title: 'Forensic Reports Archive',
      subtitle: 'Download standalone offline HTML and structured JSON artifacts',
      icon: FileText,
      action: () => { onNavigate('reports'); onClose(); },
      badge: '7',
    },
    {
      id: 'nav-settings',
      category: 'NAVIGATION',
      title: 'Engine & Bluetooth SIG Registry',
      subtitle: '24 curated standard and vendor assigned UUID records & system stats',
      icon: Settings,
      action: () => { onNavigate('settings'); onClose(); },
      badge: '8',
    },
    {
      id: 'act-upload',
      category: 'ACTIONS',
      title: 'Quick Intake: Upload New Binary',
      subtitle: 'Open drag-and-drop intake workstation',
      icon: FileCode,
      action: () => { onNavigate('intake'); onClose(); },
    },
  ];

  const analysisCommands: CommandItem[] = recentAnalyses.map((item) => ({
    id: `analysis-${item.id}`,
    category: 'ANALYSES',
    title: item.file_name,
    subtitle: `${item.package_name || 'Processing...'} • SHA: ${item.sha256 ? item.sha256.substring(0, 12) : 'calc...'}`,
    icon: Database,
    action: () => {
      onNavigate('workbench', { analysisId: item.id });
      onClose();
    },
    badge: item.status.toUpperCase(),
  }));

  const allItems = [...defaultCommands, ...analysisCommands];

  const filteredItems = query.trim() === ''
    ? allItems
    : allItems.filter((cmd) => {
        const q = query.toLowerCase();
        return (
          cmd.title.toLowerCase().includes(q) ||
          (cmd.subtitle && cmd.subtitle.toLowerCase().includes(q)) ||
          cmd.category.toLowerCase().includes(q)
        );
      });

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, filteredItems.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredItems.length) % Math.max(1, filteredItems.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredItems[selectedIndex]) {
        filteredItems[selectedIndex].action();
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-[#0A0D12]/80 backdrop-blur-md transition-opacity"
      onClick={onClose}
    >
      <div 
        className="w-full max-w-2xl bg-[#12161E] border border-[#3B4656] rounded-lg shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3.5 border-b border-[#262E3B] bg-[#181E27]">
          <Search className="w-4 h-4 text-[#64748B] mr-3 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command, tool, APK name, package, or SHA-256..."
            className="w-full bg-transparent text-sm text-[#F1F5F9] font-mono placeholder-[#64748B] focus:outline-none"
          />
          <span className="text-[10px] font-mono text-[#64748B] px-1.5 py-0.5 border border-[#262E3B] rounded bg-[#12161E] ml-2 shrink-0">
            ESC
          </span>
        </div>

        {/* Command List */}
        <div 
          ref={listRef}
          className="max-h-96 overflow-y-auto p-2 space-y-1 divide-y divide-[#262E3B]/40"
        >
          {filteredItems.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-[#64748B]">
              NO MATCHING COMMANDS OR ANALYSES FOUND
            </div>
          ) : (
            filteredItems.map((item, index) => {
              const isSelected = index === selectedIndex;
              const Icon = item.icon;
              return (
                <div
                  key={item.id}
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`flex items-center justify-between px-3 py-2.5 rounded cursor-pointer transition-colors duration-100 ${
                    isSelected 
                      ? 'bg-[#181E27] border-l-2 border-teal-500 pl-2.5 text-[#F1F5F9]' 
                      : 'text-[#CBD5E1] hover:bg-[#181E27]/50'
                  }`}
                >
                  <div className="flex items-center space-x-3 min-w-0">
                    <div className={`p-1.5 rounded ${isSelected ? 'text-teal-400 bg-teal-500/10' : 'text-[#64748B] bg-[#0E1116]'}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-medium tracking-tight truncate flex items-center space-x-2">
                        <span>{item.title}</span>
                        {item.badge && (
                          <span className={`text-[9px] font-mono px-1 rounded ${
                            item.badge === 'SUCCESS' ? 'text-teal-400 bg-teal-500/10' :
                            item.badge === 'FAILED' ? 'text-red-400 bg-red-500/10' :
                            'text-[#64748B] border border-[#262E3B]'
                          }`}>
                            {item.badge}
                          </span>
                        )}
                      </div>
                      {item.subtitle && (
                        <div className="text-[11px] font-mono text-[#64748B] truncate">
                          {item.subtitle}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center pl-2 shrink-0">
                    {isSelected ? (
                      <ArrowRight className="w-3.5 h-3.5 text-teal-400 animate-pulse" />
                    ) : (
                      <span className="text-[10px] font-mono text-[#64748B]/60 uppercase">
                        {item.category}
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Navigation Hints */}
        <div className="flex items-center justify-between px-3 py-2 border-t border-[#262E3B] bg-[#0E1116] text-[10px] font-mono text-[#64748B]">
          <div className="flex items-center space-x-3">
            <span><kbd className="text-[#CBD5E1]">↑↓</kbd> Navigate</span>
            <span><kbd className="text-[#CBD5E1]">↵</kbd> Select</span>
            <span><kbd className="text-[#CBD5E1]">ESC</kbd> Close</span>
          </div>
          <div className="text-teal-400/80">
            UCSD FORENSIC COMMAND
          </div>
        </div>
      </div>
    </div>
  );
};
