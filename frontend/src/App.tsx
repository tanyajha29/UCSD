import React, { useEffect, useState } from 'react';
import { SidebarNav, NavTab } from './components/SidebarNav';
import { TopCaseBar } from './components/TopCaseBar';
import { BottomStatusBar } from './components/BottomStatusBar';
import { CommandPalette } from './components/CommandPalette';
import { EvidenceDeskPage } from './pages/EvidenceDeskPage';
import { IntakePage } from './pages/IntakePage';
import { WorkbenchPage } from './pages/WorkbenchPage';
import { RelationshipExplorerPage } from './pages/RelationshipExplorerPage';
import { ComparisonPage } from './pages/ComparisonPage';
import { HistoryPage } from './pages/HistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { SystemHealth, AnalysisSummary } from './types';
import { api } from './api/client';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('desk');
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const [activeCaseSummary, setActiveCaseSummary] = useState<AnalysisSummary | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);

  // Poll engine health
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const data = await api.getHealth();
        setHealth(data);
      } catch (err) {
        console.warn('Backend currently unreachable', err);
        setHealth(null);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  // Update active case summary when activeCaseId changes
  useEffect(() => {
    if (!activeCaseId) {
      // Try to load the most recent case as default
      api.listAnalyses(1, 1).then((res) => {
        if (res.items.length > 0) {
          setActiveCaseId(res.items[0].id);
          setActiveCaseSummary(res.items[0]);
        }
      }).catch(() => {});
      return;
    }

    api.getAnalysisStatus(activeCaseId)
      .then((data) => setActiveCaseSummary(data))
      .catch((err) => console.warn('Failed to load active case status', err));
  }, [activeCaseId]);

  // Global Keyboard Shortcuts (Ctrl+K, and 1-8 for instant tool navigation)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Toggle Command Palette on Ctrl+K / Cmd+K
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen((prev) => !prev);
        return;
      }

      // Ignore single-key shortcuts when typing in inputs/textareas
      const target = e.target as HTMLElement;
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable ||
        isCommandPaletteOpen
      ) {
        return;
      }

      const key = e.key;
      if (key === '1') {
        e.preventDefault();
        setActiveTab('desk');
      } else if (key === '2') {
        e.preventDefault();
        setActiveTab('intake');
      } else if (key === '3') {
        e.preventDefault();
        setActiveTab('workbench');
      } else if (key === '4') {
        e.preventDefault();
        setActiveTab('explorer');
      } else if (key === '5') {
        e.preventDefault();
        setActiveTab('compare');
      } else if (key === '6') {
        e.preventDefault();
        setActiveTab('history');
      } else if (key === '7') {
        e.preventDefault();
        setActiveTab('reports');
      } else if (key === '8') {
        e.preventDefault();
        setActiveTab('settings');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isCommandPaletteOpen]);

  const handleNavigate = (tab: NavTab, params?: { analysisId?: string }) => {
    if (params?.analysisId) {
      setActiveCaseId(params.analysisId);
    }
    setActiveTab(tab);
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case 'desk':
        return (
          <EvidenceDeskPage
            onNavigate={handleNavigate}
            onSelectCase={(id) => setActiveCaseId(id)}
          />
        );
      case 'intake':
        return (
          <IntakePage
            onAnalysisComplete={(id) => {
              setActiveCaseId(id);
              setActiveTab('workbench');
            }}
            onNavigateTab={handleNavigate}
          />
        );
      case 'workbench':
        return (
          <WorkbenchPage
            analysisId={activeCaseId}
            onSelectCase={(id) => setActiveCaseId(id)}
            onNavigateTab={handleNavigate}
          />
        );
      case 'explorer':
        return (
          <RelationshipExplorerPage
            analysisId={activeCaseId}
            onSelectCase={(id) => setActiveCaseId(id)}
            onNavigateTab={handleNavigate}
          />
        );
      case 'compare':
        return <ComparisonPage />;
      case 'history':
        return (
          <HistoryPage
            onSelectAnalysis={(id) => {
              setActiveCaseId(id);
              setActiveTab('workbench');
            }}
          />
        );
      case 'reports':
        return <ReportsPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return (
          <EvidenceDeskPage
            onNavigate={handleNavigate}
            onSelectCase={(id) => setActiveCaseId(id)}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0D12] text-[#F1F5F9] flex font-sans selection:bg-teal-500/20 selection:text-teal-400">
      
      {/* 1. Persistent Left Navigation Rail */}
      <SidebarNav
        activeTab={activeTab}
        onSelectTab={(tab) => setActiveTab(tab)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed((prev) => !prev)}
        hasActiveCase={!!activeCaseId}
      />

      {/* 2. Main Workbench Shell (Top Case Bar + Tool Area + Bottom Status Strip) */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        
        {/* Top Contextual Bar / Active Investigation Selector */}
        <TopCaseBar
          activeCaseId={activeCaseId}
          onSelectCase={(id) => setActiveCaseId(id)}
          onNavigateTab={handleNavigate}
          onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
          health={health}
        />

        {/* Central Tool Work Area */}
        <main className="flex-1 overflow-y-auto bg-[#0A0D12]">
          {renderActiveView()}
        </main>

        {/* Persistent Bottom Status Strip */}
        <BottomStatusBar
          health={health}
          activeCaseName={activeCaseSummary?.file_name || null}
          activeCaseHash={activeCaseSummary?.sha256 || null}
        />
      </div>

      {/* Global Forensic Command Palette */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onNavigate={handleNavigate}
      />

    </div>
  );
};

export default App;
