import React from 'react';
import { Database, Cpu, HardDrive, Keyboard } from 'lucide-react';
import { SystemHealth } from '../types';

interface BottomStatusBarProps {
  health: SystemHealth | null;
  activeCaseName: string | null;
  activeCaseHash: string | null;
  totalAnalysesCount?: number;
}

export const BottomStatusBar: React.FC<BottomStatusBarProps> = ({
  health,
  activeCaseName,
  activeCaseHash,
  totalAnalysesCount = 0,
}) => {
  return (
    <footer className="h-7 bg-[#0E1116] border-t border-[#262E3B] px-4 flex items-center justify-between text-[10px] font-mono text-[#64748B] select-none shrink-0 z-20">
      {/* Left: DB & Engine details */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-1.5" title="SQLite WAL persistence storage">
          <Database className="w-3 h-3 text-[#14B8A6]" />
          <span>DB: <span className="text-[#94A3B8]">SQLite WAL</span></span>
        </div>

        <div className="hidden sm:flex items-center space-x-1.5" title="Analysis engine version">
          <Cpu className="w-3 h-3 text-[#14B8A6]" />
          <span>ENGINE: <span className="text-[#94A3B8]">UCSD v{health?.analyzer_version || '0.1.0'}</span></span>
        </div>

        <div className="hidden md:flex items-center space-x-1.5" title="Bluetooth SIG Curated Database">
          <span>SIG KB: <span className="text-teal-400">{health?.knowledge_base?.total_entries || 24} Entries</span></span>
        </div>
      </div>

      {/* Center: Active Target */}
      <div className="hidden lg:flex items-center space-x-2 truncate max-w-sm">
        {activeCaseName ? (
          <>
            <span className="text-[#64748B]">TARGET:</span>
            <span className="text-[#F1F5F9] font-medium truncate">{activeCaseName}</span>
            {activeCaseHash && (
              <span className="text-[#64748B] text-[9px]">
                ({activeCaseHash.substring(0, 10)})
              </span>
            )}
          </>
        ) : (
          <span className="text-[#64748B]">NO ACTIVE CASE SELECTED</span>
        )}
      </div>

      {/* Right: Keyboard shortcuts hint */}
      <div className="flex items-center space-x-3">
        <div className="hidden sm:flex items-center space-x-2">
          <Keyboard className="w-3 h-3 text-[#64748B]" />
          <span>
            <kbd className="px-1 py-0.2 rounded border border-[#262E3B] bg-[#151921] text-[#94A3B8]">⌘K</kbd> COMMANDS
          </span>
          <span>
            <kbd className="px-1 py-0.2 rounded border border-[#262E3B] bg-[#151921] text-[#94A3B8]">1-8</kbd> TOOLS
          </span>
        </div>
      </div>
    </footer>
  );
};
