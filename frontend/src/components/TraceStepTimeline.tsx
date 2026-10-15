import React, { useState } from 'react';
import { TraceStep } from '../types';

interface Props {
  steps: TraceStep[];
}

export const TraceStepTimeline: React.FC<Props> = ({ steps }) => {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  if (!steps || steps.length === 0) {
    return <p className="text-xs font-mono text-[#7A8794] italic">No intra-method trace steps recorded.</p>;
  }

  return (
    <div className="space-y-2 font-mono">
      <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1A2332]">
        {steps.map((step, idx) => {
          const isExpanded = expandedIndex === idx;
          const opcodeColor = step.opcode.startsWith('const')
            ? 'text-[#00E5A0] bg-[#00E5A0]/10 border-[#00E5A0]/30'
            : step.opcode.startsWith('invoke-direct')
            ? 'text-[#4DA6FF] bg-[#4DA6FF]/10 border-[#4DA6FF]/30'
            : step.opcode.startsWith('invoke-virtual')
            ? 'text-[#FF3B5C] bg-[#FF3B5C]/10 border-[#FF3B5C]/30'
            : 'text-[#FFB020] bg-[#FFB020]/10 border-[#FFB020]/30';

          return (
            <div key={idx} className="relative group">
              {/* Timeline marker */}
              <div className="absolute -left-6 top-2 w-3 h-3 rounded-full border-2 border-[#05070A] bg-[#00E5A0]" />

              <div
                onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                className="bg-[#0B0F14] border border-[#1A2332] hover:border-[#2A3A4F] rounded p-3 cursor-pointer transition-colors"
              >
                <div className="flex items-center justify-between flex-wrap gap-2 text-xs">
                  <div className="flex items-center space-x-2">
                    <span className="text-[#7A8794]">#{step.step_index}</span>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-medium border ${opcodeColor}`}>
                      {step.opcode}
                    </span>
                    <span className="text-[#E8EDF2] font-medium">
                      {step.step_type.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <span className="text-[11px] text-[#7A8794] bg-[#05070A] px-2 py-0.5 rounded border border-[#1A2332]">
                    offset: +0x{step.instruction_offset.toString(16).padStart(4, '0')}
                  </span>
                </div>

                {/* Details drilldown */}
                {step.details && Object.keys(step.details).length > 0 && (
                  <div className="mt-2.5 pt-2.5 border-t border-[#1A2332] text-[11px] text-[#7A8794]">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {Object.entries(step.details).map(([k, v]) => (
                        <div key={k} className="flex space-x-2">
                          <span className="text-[#7A8794]">{k}:</span>
                          <span className="text-[#00E5A0] truncate font-medium">
                            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
