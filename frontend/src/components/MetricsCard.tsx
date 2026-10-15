import React, { useEffect, useState } from 'react';

export type MiniVizType = 
  | 'total_apks' 
  | 'strong_registrations' 
  | 'candidate_only' 
  | 'cross_apk_overlaps' 
  | 'unresolved_patterns' 
  | 'comparisons';

interface MetricsCardProps {
  title: string;
  value: number;
  subtitle?: string;
  vizType?: MiniVizType;
  meta?: {
    successCount?: number;
    failedCount?: number;
    totalPossible?: number;
  };
  variant?: 'default' | 'phosphor' | 'critical' | 'warning' | 'info';
  isCriticalGlow?: boolean;
}

export const MetricsCard: React.FC<MetricsCardProps> = ({
  title,
  value,
  subtitle,
  vizType,
  meta,
  variant = 'default',
  isCriticalGlow = false,
}) => {
  const [displayValue, setDisplayValue] = useState(0);

  // Animated Count-Up from 0 over 800ms
  useEffect(() => {
    let startTimestamp: number | null = null;
    const duration = 800;
    const target = typeof value === 'number' ? value : 0;

    const step = (timestamp: number) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      // Ease-out cubic
      const easedProgress = 1 - Math.pow(1 - progress, 3);
      setDisplayValue(Math.floor(easedProgress * target));

      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        setDisplayValue(target);
      }
    };

    window.requestAnimationFrame(step);
  }, [value]);

  // Mini Data Visualization Renderer
  const renderMiniViz = () => {
    switch (vizType) {
      case 'total_apks': {
        const success = meta?.successCount ?? value;
        const failed = meta?.failedCount ?? 0;
        const total = Math.max(1, success + failed);
        const successPct = Math.round((success / total) * 100);
        return (
          <div className="w-14 flex flex-col gap-1 items-end" title={`Success: ${success}, Failed: ${failed}`}>
            <div className="text-[9px] font-mono text-[#7A8794]">{successPct}% OK</div>
            <div className="w-full h-1.5 bg-[#1A2332] rounded-full overflow-hidden flex">
              <div 
                className="bg-[#00E5A0] h-full transition-all duration-500" 
                style={{ width: `${successPct}%` }}
              />
              <div 
                className="bg-[#FF3B5C] h-full transition-all duration-500" 
                style={{ width: `${100 - successPct}%` }}
              />
            </div>
          </div>
        );
      }

      case 'strong_registrations': {
        // Vertical tally / LED bar meter
        const bars = [1, 2, 3, 4, 5];
        return (
          <div className="flex items-end gap-1 h-6" title="Verified Dalvik Registration Sites">
            {bars.map((bar) => {
              const active = value >= bar;
              return (
                <div
                  key={bar}
                  className={`w-1.5 rounded-sm transition-all duration-300 ${
                    active 
                      ? 'bg-[#00E5A0] shadow-[0_0_6px_rgba(0,229,160,0.6)]' 
                      : 'bg-[#1A2332]'
                  }`}
                  style={{ height: `${bar * 20}%` }}
                />
              );
            })}
          </div>
        );
      }

      case 'candidate_only': {
        // Dotted grid filled proportionally
        const dots = Array.from({ length: 9 });
        return (
          <div className="grid grid-cols-3 gap-1 p-1 bg-[#05070A] rounded border border-[#1A2332]" title="Candidate UUID String Density">
            {dots.map((_, i) => {
              const isFilled = value > i;
              return (
                <div
                  key={i}
                  className={`w-1.5 h-1.5 rounded-full ${
                    isFilled ? 'bg-[#4DA6FF]' : 'bg-[#1A2332]'
                  }`}
                />
              );
            })}
          </div>
        );
      }

      case 'cross_apk_overlaps': {
        // Two overlapping circles (Venn-style) with glowing red intersection
        const hasCollision = value > 0;
        return (
          <svg width="36" height="22" viewBox="0 0 36 22" fill="none" className="shrink-0">
            <circle cx="12" cy="11" r="8" stroke="#7A8794" strokeWidth="1.2" fill="none" opacity="0.6" />
            <circle cx="24" cy="11" r="8" stroke="#7A8794" strokeWidth="1.2" fill="none" opacity="0.6" />
            {hasCollision && (
              <circle
                cx="18"
                cy="11"
                r="4.5"
                fill="#FF3B5C"
                className="animate-pulse"
                style={{ filter: 'drop-shadow(0 0 6px #FF3B5C)' }}
              />
            )}
          </svg>
        );
      }

      case 'unresolved_patterns': {
        // Warning triangle with animated pulse if count > 0
        const hasUnresolved = value > 0;
        return (
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="shrink-0">
            <path
              d="M12 4L21 20H3L12 4Z"
              stroke={hasUnresolved ? '#FFB020' : '#1A2332'}
              strokeWidth="1.5"
              fill={hasUnresolved ? 'rgba(255, 176, 32, 0.1)' : 'none'}
              strokeLinejoin="round"
              className={hasUnresolved ? 'animate-pulse' : ''}
            />
            {hasUnresolved && (
              <circle cx="12" cy="16" r="1.2" fill="#FFB020" />
            )}
            {hasUnresolved && (
              <line x1="12" y1="9" x2="12" y2="13" stroke="#FFB020" strokeWidth="1.5" strokeLinecap="round" />
            )}
          </svg>
        );
      }

      case 'comparisons': {
        // Small node-link graph
        return (
          <svg width="32" height="24" viewBox="0 0 32 24" fill="none" className="shrink-0">
            <line x1="6" y1="12" x2="26" y2="6" stroke="#2A3A4F" strokeWidth="1.2" />
            <line x1="6" y1="12" x2="26" y2="18" stroke="#2A3A4F" strokeWidth="1.2" />
            <circle cx="6" cy="12" r="3" fill="#11171F" stroke="#00E5A0" strokeWidth="1.2" />
            <circle cx="26" cy="6" r="2.5" fill="#11171F" stroke="#7A8794" strokeWidth="1.2" />
            <circle cx="26" cy="18" r="2.5" fill="#11171F" stroke="#7A8794" strokeWidth="1.2" />
          </svg>
        );
      }

      default:
        return null;
    }
  };

  const isCriticalAlert = isCriticalGlow || (vizType === 'cross_apk_overlaps' && value > 0);

  return (
    <div 
      className={`group relative bg-[#0B0F14] border border-[#1A2332] rounded-lg p-4 transition-all duration-200 hover:-translate-y-0.5 hover:border-[#2A3A4F] hover:bg-[#11171F] overflow-hidden ${
        isCriticalAlert 
          ? 'shadow-[0_0_24px_rgba(255,59,92,0.12)] border-[#FF3B5C]/40' 
          : ''
      }`}
    >
      {/* Top Header Row */}
      <div className="flex items-center justify-between mb-3">
        <span className="text-[11px] font-mono tracking-tracked text-[#7A8794] uppercase truncate">
          {title}
        </span>
        {renderMiniViz()}
      </div>

      {/* Big Number Readout with tabular-nums */}
      <div className="flex items-baseline space-x-2">
        <span className={`text-2xl font-semibold font-mono tracking-tight tabular-nums ${
          isCriticalAlert 
            ? 'text-[#FF3B5C]' 
            : variant === 'phosphor' 
            ? 'text-[#00E5A0]' 
            : variant === 'warning' 
            ? 'text-[#FFB020]' 
            : 'text-[#E8EDF2]'
        }`}>
          {displayValue}
        </span>
      </div>

      {/* Subtitle */}
      {subtitle && (
        <p className="text-[11px] font-mono text-[#7A8794] mt-1.5 truncate">
          {subtitle}
        </p>
      )}

      {/* Phosphor-green underline on hover (scaleX 0 -> 1) */}
      <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#00E5A0] scale-x-0 group-hover:scale-x-100 transition-transform duration-200 origin-left" />
    </div>
  );
};
