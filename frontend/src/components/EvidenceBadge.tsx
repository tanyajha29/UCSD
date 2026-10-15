import React from 'react';
import { EvidenceLevel } from '../types';

interface Props {
  level: EvidenceLevel | string;
  showExplanation?: boolean;
}

export const EvidenceBadge: React.FC<Props> = ({ level, showExplanation = false }) => {
  switch (level) {
    case 'STRONG_STATIC_ASSOCIATION':
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-teal-500/10 text-teal-400 border border-teal-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shadow-[0_0_6px_rgba(20,184,166,0.6)]" />
          <span>STRONG STATIC ASSOCIATION</span>
          {showExplanation && (
            <span className="text-[10px] text-teal-400/80 ml-1 font-normal">
              (Verified intra-method constructor &amp; addService linkage)
            </span>
          )}
        </span>
      );

    case 'REGISTRATION_PATTERN_UUID_UNRESOLVED':
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shadow-[0_0_6px_rgba(245,158,11,0.6)]" />
          <span>PATTERN UNRESOLVED</span>
          {showExplanation && (
            <span className="text-[10px] text-amber-400/80 ml-1 font-normal">
              (Cross-method, field, or dynamic UUID reference)
            </span>
          )}
        </span>
      );

    case 'UUID_CANDIDATE_ONLY':
    default:
      return (
        <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-[#181E27] text-[#94A3B8] border border-[#262E3B]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#64748B]" />
          <span>UUID CANDIDATE ONLY</span>
          {showExplanation && (
            <span className="text-[10px] text-[#64748B] ml-1 font-normal">
              (String literal only; no local GATT server registration)
            </span>
          )}
        </span>
      );
  }
};
