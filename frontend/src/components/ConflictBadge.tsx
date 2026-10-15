import React from 'react';
import { ConflictCondition } from '../types';

interface Props {
  condition: ConflictCondition | string;
  isProven?: boolean;
}

export const ConflictBadge: React.FC<Props> = ({ condition, isProven = false }) => {
  switch (condition) {
    case 'STRONG_DUPLICATE_STATIC_REGISTRATION':
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-red-500/15 text-red-400 border border-red-500/40 shadow-[0_0_8px_rgba(239,68,68,0.2)]">
          <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
          <span>STRONG DUPLICATE STATIC REGISTRATION</span>
          {isProven && (
            <span className="bg-red-500/20 text-red-300 text-[9px] px-1 py-0.2 rounded border border-red-500/50">
              PROVEN
            </span>
          )}
        </span>
      );

    case 'KNOWN_ASSIGNED_STANDARD_MATCH':
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-teal-500/10 text-teal-400 border border-teal-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
          <span>BLUETOOTH SIG STANDARD</span>
        </span>
      );

    case 'KNOWN_SYSTEM_OR_VENDOR_MATCH':
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-[#181E27] text-[#CBD5E1] border border-[#3B4656]">
          <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
          <span>SOURCED SYSTEM / VENDOR</span>
        </span>
      );

    case 'UNRESOLVED_REGISTRATION_OVERLAP':
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
          <span>UNRESOLVED OVERLAP</span>
        </span>
      );

    case 'DUPLICATE_CANDIDATE_NO_REGISTRATION':
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-[#181E27] text-[#94A3B8] border border-[#262E3B]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#64748B]" />
          <span>SHARED STRING ONLY</span>
        </span>
      );

    case 'UNKNOWN_UNCONFLICTED':
    default:
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-[#12161E] text-[#64748B] border border-[#262E3B]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#64748B]/50" />
          <span>UNCONFLICTED</span>
        </span>
      );
  }
};
