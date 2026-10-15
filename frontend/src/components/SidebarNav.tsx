import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  Binary,
  Share2,
  GitCompare,
  Database,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';
import { ForensicLogo } from './ForensicLogo';

export type NavTab =
  | 'desk'
  | 'intake'
  | 'workbench'
  | 'explorer'
  | 'compare'
  | 'history'
  | 'reports'
  | 'settings';

interface SidebarNavProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  hasActiveCase: boolean;
}

interface NavItem {
  id: NavTab;
  label: string;
  shortLabel: string;
  icon: React.ComponentType<{ className?: string }>;
  hotkey: string;
  description: string;
  requiresCase?: boolean;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({
  activeTab,
  onSelectTab,
  collapsed,
  onToggleCollapse,
  hasActiveCase,
}) => {
  const navItems: NavItem[] = [
    {
      id: 'desk',
      label: 'Evidence Desk',
      shortLabel: 'Desk',
      icon: LayoutDashboard,
      hotkey: '1',
      description: 'Case overview & triage queue',
    },
    {
      id: 'intake',
      label: 'APK Intake',
      shortLabel: 'Intake',
      icon: UploadCloud,
      hotkey: '2',
      description: 'Secure static APK ingestion',
    },
    {
      id: 'workbench',
      label: 'Dalvik Workbench',
      shortLabel: 'IDE',
      icon: Binary,
      hotkey: '3',
      description: 'Reverse-engineering & disassembly',
    },
    {
      id: 'explorer',
      label: 'Relationship Explorer',
      shortLabel: 'Graph',
      icon: Share2,
      hotkey: '4',
      description: 'Interactive SVG node-link topology',
    },
    {
      id: 'compare',
      label: 'Cross-APK Conflicts',
      shortLabel: 'Conflicts',
      icon: GitCompare,
      hotkey: '5',
      description: 'Multi-APK duplicate collision matrix',
    },
    {
      id: 'history',
      label: 'Forensic Ledger',
      shortLabel: 'Ledger',
      icon: Database,
      hotkey: '6',
      description: 'SQLite persistence history archive',
    },
    {
      id: 'reports',
      label: 'Reports & Exports',
      shortLabel: 'Reports',
      icon: FileText,
      hotkey: '7',
      description: 'Standalone HTML & JSON artifacts',
    },
    {
      id: 'settings',
      label: 'Engine & KB',
      shortLabel: 'Settings',
      icon: Settings,
      hotkey: '8',
      description: 'Bluetooth SIG directory & system stats',
    },
  ];

  return (
    <aside
      className={`bg-[#0E1116] border-r border-[#262E3B] flex flex-col justify-between transition-all duration-200 z-30 select-none ${
        collapsed ? 'w-16' : 'w-60'
      }`}
    >
      {/* Top: Logo & Branding */}
      <div>
        <div
          onClick={() => onSelectTab('desk')}
          className="h-14 border-b border-[#262E3B] flex items-center px-4 cursor-pointer hover:bg-[#151921] transition-colors"
          title="Return to Evidence Desk"
        >
          <div className="flex items-center space-x-3 overflow-hidden">
            <ForensicLogo size={28} />
            {!collapsed && (
              <div className="truncate">
                <div className="flex items-center space-x-1.5">
                  <span className="font-semibold text-sm tracking-tight text-[#F1F5F9]">
                    UCSD
                  </span>
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded border border-[#262E3B] bg-[#151921] text-[#14B8A6]">
                    FORENSIC
                  </span>
                </div>
                <div className="text-[9px] font-mono tracking-wider text-[#94A3B8] truncate uppercase">
                  Evidence Lab
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Navigation Rail Items */}
        <nav className="p-2 space-y-1 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                title={`${item.label} [${item.hotkey}] — ${item.description}`}
                className={`w-full flex items-center rounded text-xs font-mono transition-all duration-150 relative group ${
                  collapsed ? 'justify-center p-2.5' : 'px-3 py-2 space-x-3'
                } ${
                  isActive
                    ? 'bg-[#151921] text-[#14B8A6] border border-[#262E3B] shadow-[0_0_10px_rgba(20,184,166,0.12)]'
                    : 'text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#151921]/60'
                }`}
              >
                {/* Active indicator bar */}
                {isActive && (
                  <span className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-[#14B8A6] rounded-r" />
                )}

                <Icon
                  className={`w-4 h-4 shrink-0 transition-colors ${
                    isActive ? 'text-[#14B8A6]' : 'text-[#64748B] group-hover:text-[#CBD5E1]'
                  }`}
                />

                {!collapsed && (
                  <div className="flex-1 flex items-center justify-between text-left truncate">
                    <span className="truncate">{item.label}</span>
                    <span className="text-[10px] text-[#64748B] font-mono group-hover:text-[#94A3B8] ml-1">
                      {item.hotkey}
                    </span>
                  </div>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom: Collapse Button */}
      <div className="p-2 border-t border-[#262E3B] bg-[#0E1116]">
        <button
          onClick={onToggleCollapse}
          className={`w-full flex items-center justify-center p-2 rounded text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#151921] text-xs font-mono transition-colors border border-transparent hover:border-[#262E3B]`}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <div className="flex items-center space-x-2 w-full px-2">
              <ChevronLeft className="w-4 h-4 shrink-0" />
              <span className="text-[11px] truncate">Collapse Navigation</span>
            </div>
          )}
        </button>
      </div>
    </aside>
  );
};
