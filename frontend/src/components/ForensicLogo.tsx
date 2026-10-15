import React from 'react';

interface ForensicLogoProps {
  className?: string;
  size?: number;
}

export const ForensicLogo: React.FC<ForensicLogoProps> = ({ className = '', size = 28 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 ${className}`}
      aria-label="UCSD Logo"
    >
      <defs>
        {/* Glow filter for candidate service node */}
        <filter id="nodeGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2.5" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
        <radialGradient id="hexRadial" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#00E5A0" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#00E5A0" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Hexagonal Outer Frame in subtle border */}
      <polygon
        points="16,3 28,10 28,22 16,29 4,22 4,10"
        stroke="#1A2332"
        strokeWidth="1.5"
        fill="#0B0F14"
        strokeLinejoin="round"
      />

      {/* Interconnecting data-flow lines */}
      <line
        x1="10"
        y1="12"
        x2="22"
        y2="12"
        stroke="#2A3A4F"
        strokeWidth="1.2"
        strokeDasharray="2 2"
        className="animate-pulse"
      />
      <line
        x1="10"
        y1="12"
        x2="16"
        y2="22"
        stroke="#2A3A4F"
        strokeWidth="1.2"
      />
      <line
        x1="22"
        y1="12"
        x2="16"
        y2="22"
        stroke="#00E5A0"
        strokeWidth="1.5"
        strokeOpacity="0.8"
      />

      {/* Node 1: Left Service / Client (Slate) */}
      <circle
        cx="10"
        cy="12"
        r="2.5"
        fill="#11171F"
        stroke="#7A8794"
        strokeWidth="1.5"
        style={{
          animation: 'fadeInNode 400ms ease-out 0ms forwards',
          opacity: 0,
        }}
      />

      {/* Node 2: Right Target / Duplicate (Slate/Blue) */}
      <circle
        cx="22"
        cy="12"
        r="2.5"
        fill="#11171F"
        stroke="#4DA6FF"
        strokeWidth="1.5"
        style={{
          animation: 'fadeInNode 400ms ease-out 120ms forwards',
          opacity: 0,
        }}
      />

      {/* Node 3: Bottom Candidate Service (Glowing Phosphor Green) */}
      <circle
        cx="16"
        cy="22"
        r="5"
        fill="url(#hexRadial)"
      />
      <circle
        cx="16"
        cy="22"
        r="3"
        fill="#00E5A0"
        filter="url(#nodeGlow)"
        style={{
          animation: 'fadeInNode 400ms ease-out 240ms forwards',
          opacity: 0,
        }}
      />
      <circle
        cx="16"
        cy="22"
        r="1.2"
        fill="#05070A"
      />

      <style>{`
        @keyframes fadeInNode {
          from {
            opacity: 0;
            transform: scale(0.6);
            transform-origin: center;
          }
          to {
            opacity: 1;
            transform: scale(1);
            transform-origin: center;
          }
        }
      `}</style>
    </svg>
  );
};
