/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Evidence Lab obsidian graphite foundation
        lab: {
          void: '#0A0D12',
          base: '#0E1116',
          panel: '#151921',
          elevated: '#1C222B',
          card: '#181E27',
          border: '#262E3B',
          'border-active': '#3B4656',
          parchment: '#1E232B',
        },
        // Semantic accents
        teal: {
          400: '#2DD4BF',
          500: '#14B8A6',
          600: '#0D9488',
          glow: 'rgba(13, 148, 136, 0.15)',
        },
        amber: {
          400: '#FBBF24',
          500: '#F59E0B',
          600: '#D97706',
          glow: 'rgba(217, 119, 6, 0.15)',
        },
        // Primary and secondary text
        txt: {
          primary: '#F1F5F9',
          secondary: '#94A3B8',
          mono: '#CBD5E1',
          dim: '#64748B',
        },
        // Backwards compatibility tokens
        void: '#0A0D12',
        panel: '#151921',
        elevated: '#1C222B',
        subtle: '#262E3B',
        'subtle-border': '#262E3B',
        'active-border': '#3B4656',
        phosphor: {
          DEFAULT: '#14B8A6',
          glow: 'rgba(20, 184, 166, 0.15)',
          hover: 'rgba(20, 184, 166, 0.22)',
          border: '#14B8A6',
        },
        alert: {
          critical: '#DC2626',
          warning: '#F59E0B',
        },
        signal: {
          info: '#38BDF8',
        },
        cyber: {
          bg: '#0A0D12',
          card: '#151921',
          'card-sub': '#1C222B',
          border: '#262E3B',
          'border-focus': '#3B4656',
          accent: '#14B8A6',
          'accent-light': '#2DD4BF',
          success: '#14B8A6',
          warning: '#F59E0B',
          danger: '#DC2626',
          purple: '#818CF8',
        }
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      letterSpacing: {
        tracked: '0.10em',
        tightest: '-0.02em',
      },
      animation: {
        'pulse-subtle': 'pulseSubtle 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 2s linear infinite',
      },
      keyframes: {
        pulseSubtle: {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.5', transform: 'scale(0.97)' },
        },
        scanline: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        }
      }
    },
  },
  plugins: [],
};
