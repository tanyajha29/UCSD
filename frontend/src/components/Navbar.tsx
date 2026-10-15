import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  History,
  GitCompare,
  FileText,
  Settings,
  Command,
} from 'lucide-react';
import { SystemHealth } from '../types';
import { ForensicLogo } from './ForensicLogo';

export type ActiveTab = 'dashboard' | 'analyze' | 'history' | 'compare' | 'reports' | 'settings';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  health: SystemHealth | null;
  onOpenCommandPalette: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  health,
  onOpenCommandPalette,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyze', label: 'New Analysis', icon: UploadCloud },
    { id: 'history', label: 'History', icon: History },
    { id: 'compare', label: 'Cross-APK Conflict', icon: GitCompare },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings & About', icon: Settings },
  ] as const;

  const isHealthy = health?.status === 'healthy';

  return (
    <header className="border-b border-[#1A2332] bg-[#05070A]/95 backdrop-blur-md sticky top-0 z-40 h-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-full flex items-center justify-between">
        
        {/* Left: Forensic Mark & Title */}
        <div 
          className="flex items-center space-x-3 cursor-pointer group"
          onClick={() => setActiveTab('dashboard')}
        >
          <ForensicLogo size={32} />
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-sm tracking-tight text-[#E8EDF2] group-hover:text-white transition-colors">
                UCSD
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border border-[#1A2332] bg-[#0B0F14] text-[#C5D0DA]">
                v{health?.analyzer_version || '0.1.0'}
              </span>
            </div>
            <p className="text-[10px] font-mono tracking-tracked text-[#7A8794] uppercase hidden md:block">
              Universal Candidate Service Detector
            </p>
          </div>
        </div>

        {/* Center: Horizontal Navigation */}
        <nav className="hidden lg:flex items-center space-x-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded text-xs font-medium tracking-tight transition-all duration-150 relative ${
                  isActive
                    ? 'text-[#00E5A0] bg-[#11171F] border border-[#1A2332]'
                    : 'text-[#7A8794] hover:text-[#E8EDF2] hover:bg-[#0B0F14]'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-[#00E5A0]' : 'text-[#7A8794]'}`} />
                <span>{item.label}</span>
                {isActive && (
                  <span className="absolute bottom-0 left-2 right-2 h-[2px] bg-[#00E5A0] shadow-[0_0_8px_#00E5A0]" />
                )}
              </button>
            );
          })}
        </nav>

        {/* Right: Engine Status + Command Palette Trigger */}
        <div className="flex items-center space-x-3">
          {/* Status Indicator */}
          <div className="flex items-center space-x-2 px-2.5 py-1 rounded bg-[#0B0F14] border border-[#1A2332]">
            <span className="relative flex h-2 w-2">
              {isHealthy ? (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00E5A0] opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00E5A0]" />
                </>
              ) : (
                <>
                  <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-[#FF3B5C] opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-[#FF3B5C]" />
                </>
              )}
            </span>
            <span className={`text-[10px] font-mono tracking-wider font-medium ${
              isHealthy ? 'text-[#00E5A0]' : 'text-[#FF3B5C]'
            }`}>
              {isHealthy ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}
            </span>
          </div>

          {/* Command Palette Trigger Chip */}
          <button
            onClick={onOpenCommandPalette}
            className="flex items-center space-x-1.5 px-2 py-1 rounded border border-[#1A2332] bg-[#0B0F14] hover:border-[#2A3A4F] hover:bg-[#11171F] text-[#7A8794] hover:text-[#E8EDF2] transition-colors"
            title="Open Command Palette (Ctrl+K / ⌘K)"
          >
            <Command className="w-3 h-3" />
            <span className="text-[10px] font-mono">⌘K</span>
          </button>
        </div>

      </div>

      {/* Mobile Nav Drawer Bar */}
      <div className="lg:hidden flex items-center justify-around border-t border-[#1A2332] bg-[#05070A] py-1.5 px-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex flex-col items-center p-1 rounded text-[10px] ${
                isActive ? 'text-[#00E5A0]' : 'text-[#7A8794]'
              }`}
            >
              <Icon className="w-4 h-4 mb-0.5" />
              <span>{item.label.split(' ')[0]}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
