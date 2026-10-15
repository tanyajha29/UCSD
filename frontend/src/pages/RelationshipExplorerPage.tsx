import React, { useState, useEffect, useRef } from 'react';
import {
  Share2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Filter,
  CheckCircle2,
  AlertTriangle,
  FolderArchive,
  Info,
  Layers,
  Binary,
  ArrowRight,
  ShieldCheck,
  Code,
  Database,
} from 'lucide-react';
import { api } from '../api/client';
import { AnalysisReport, RegistrationFinding, UUIDCandidate } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';
import { NavTab } from '../components/SidebarNav';

interface Node {
  id: string;
  type: 'apk' | 'package' | 'method' | 'registration' | 'uuid' | 'sig';
  label: string;
  sublabel?: string;
  column: number;
  x: number;
  y: number;
  data: any;
}

interface Edge {
  id: string;
  source: string;
  target: string;
  type: 'declared' | 'invokes' | 'registers' | 'references' | 'matches';
  status?: 'strong' | 'unresolved' | 'candidate';
}

interface RelationshipExplorerPageProps {
  analysisId: string | null;
  onSelectCase?: (caseId: string) => void;
  onNavigateTab?: (tab: NavTab) => void;
}

export const RelationshipExplorerPage: React.FC<RelationshipExplorerPageProps> = ({
  analysisId,
  onSelectCase,
  onNavigateTab,
}) => {
  const [currentId, setCurrentId] = useState<string | null>(analysisId);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // SVG Pan & Zoom state
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 50, y: 50 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  // Graph interactive state
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Filter state
  const [showCandidates, setShowCandidates] = useState(false);
  const [showStandardMatches, setShowStandardMatches] = useState(true);
  const [showUnresolved, setShowUnresolved] = useState(true);

  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!analysisId) {
      api.listAnalyses(1, 1).then((res) => {
        if (res.items.length > 0) {
          setCurrentId(res.items[0].id);
          if (onSelectCase) onSelectCase(res.items[0].id);
        }
      }).catch(() => {});
    } else {
      setCurrentId(analysisId);
    }
  }, [analysisId]);

  useEffect(() => {
    if (!currentId) return;

    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getAnalysisResults(currentId);
        setReport(data.report);
        setFileName(data.file_name || data.report?.metadata?.file_name || 'APK Target');
        setSelectedNodeId(null);
      } catch (err: any) {
        setError(err.message || 'Failed to load graph data');
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [currentId]);

  // Construct DAG nodes and edges from real backend AnalysisReport
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  if (report?.metadata) {
    const meta = report.metadata;
    const manifest = meta.manifest;
    const findings: RegistrationFinding[] = meta.registration_analysis?.findings || [];
    const kbAssessments = meta.knowledge_base_assessment?.findings || [];
    const candidates: UUIDCandidate[] = meta.ble_analysis?.uuid_candidates || [];

    // Col 0: APK Node
    const apkNodeId = 'node-apk';
    nodes.push({
      id: apkNodeId,
      type: 'apk',
      label: fileName,
      sublabel: `SHA: ${meta.sha256?.substring(0, 10)}`,
      column: 0,
      x: 80,
      y: 200,
      data: meta,
    });

    // Col 1: Package Node
    const pkgNodeId = 'node-pkg';
    const pkgName = manifest?.package_name || 'unresolved.package';
    nodes.push({
      id: pkgNodeId,
      type: 'package',
      label: pkgName,
      sublabel: `Target SDK: ${manifest?.target_sdk_version || 'N/A'}`,
      column: 1,
      x: 340,
      y: 200,
      data: manifest,
    });
    edges.push({
      id: 'edge-apk-pkg',
      source: apkNodeId,
      target: pkgNodeId,
      type: 'declared',
    });

    // Col 2 & 3: Methods & Registrations from Findings
    let currentFindingY = 60;
    const spacingY = 110;

    findings.forEach((finding, idx) => {
      const isStrong = finding.evidence_level === 'STRONG_STATIC_ASSOCIATION';
      if (!isStrong && !showUnresolved) return;

      const methodId = `node-mth-${idx}`;
      const regId = `node-reg-${idx}`;
      const uuidId = `node-uuid-${idx}`;

      // Method Node
      nodes.push({
        id: methodId,
        type: 'method',
        label: `${finding.method_name}()`,
        sublabel: finding.class_name.split('.').pop(),
        column: 2,
        x: 600,
        y: currentFindingY,
        data: finding,
      });
      edges.push({
        id: `edge-pkg-mth-${idx}`,
        source: pkgNodeId,
        target: methodId,
        type: 'declared',
      });

      // Registration Call Node
      nodes.push({
        id: regId,
        type: 'registration',
        label: isStrong ? 'addService(vService)' : 'GATT Registration Call',
        sublabel: isStrong ? 'VERIFIED LINKAGE' : 'UNRESOLVED PATTERN',
        column: 3,
        x: 880,
        y: currentFindingY,
        data: finding,
      });
      edges.push({
        id: `edge-mth-reg-${idx}`,
        source: methodId,
        target: regId,
        type: 'registers',
        status: isStrong ? 'strong' : 'unresolved',
      });

      // UUID Node
      if (finding.normalized_uuid) {
        nodes.push({
          id: uuidId,
          type: 'uuid',
          label: `${finding.normalized_uuid.substring(0, 18)}...`,
          sublabel: finding.normalized_uuid,
          column: 4,
          x: 1160,
          y: currentFindingY,
          data: finding,
        });
        edges.push({
          id: `edge-reg-uuid-${idx}`,
          source: regId,
          target: uuidId,
          type: 'references',
          status: isStrong ? 'strong' : 'unresolved',
        });

        // Col 5: Bluetooth SIG Standard Node if matched
        const kbMatch = kbAssessments.find(
          (k) => k.normalized_uuid.toLowerCase() === finding.normalized_uuid?.toLowerCase()
        );

        if (kbMatch?.knowledge_base_match && showStandardMatches) {
          const sigId = `node-sig-${idx}`;
          nodes.push({
            id: sigId,
            type: 'sig',
            label: kbMatch.knowledge_base_match.name,
            sublabel: kbMatch.knowledge_base_match.identifier_type,
            column: 5,
            x: 1440,
            y: currentFindingY,
            data: kbMatch.knowledge_base_match,
          });
          edges.push({
            id: `edge-uuid-sig-${idx}`,
            source: uuidId,
            target: sigId,
            type: 'matches',
            status: 'strong',
          });
        }
      }

      currentFindingY += spacingY;
    });

    // Optional Candidate-only UUIDs
    if (showCandidates) {
      candidates.slice(0, 8).forEach((cand, cIdx) => {
        // Skip if already in findings
        if (findings.some((f) => f.normalized_uuid === cand.normalized_uuid)) return;

        const candUuidId = `node-cand-${cIdx}`;
        nodes.push({
          id: candUuidId,
          type: 'uuid',
          label: `${cand.normalized_uuid.substring(0, 18)}...`,
          sublabel: 'String Pool Candidate',
          column: 4,
          x: 1160,
          y: currentFindingY,
          data: cand,
        });
        edges.push({
          id: `edge-pkg-cand-${cIdx}`,
          source: pkgNodeId,
          target: candUuidId,
          type: 'references',
          status: 'candidate',
        });
        currentFindingY += spacingY;
      });
    }
  }

  // Node position map for rendering curves
  const nodeMap = new Map<string, Node>();
  nodes.forEach((n) => nodeMap.set(n.id, n));

  // Determine highlighted elements when node is hovered or selected
  const activeFocusId = hoveredNodeId || selectedNodeId;
  const connectedNodeIds = new Set<string>();
  const connectedEdgeIds = new Set<string>();

  if (activeFocusId) {
    connectedNodeIds.add(activeFocusId);
    edges.forEach((edge) => {
      if (edge.source === activeFocusId || edge.target === activeFocusId) {
        connectedEdgeIds.add(edge.id);
        connectedNodeIds.add(edge.source);
        connectedNodeIds.add(edge.target);
      }
    });
  }

  // Pan interaction handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
    setZoom((prev) => Math.min(Math.max(0.4, prev * zoomFactor), 2.5));
  };

  const selectedNode = nodes.find((n) => n.id === selectedNodeId);

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center p-12">
        <LoadingSpinner message="SYNTHESIZING EVIDENCE TOPOLOGY GRAPH..." size="lg" />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-4xl mx-auto p-8 space-y-4">
        <ErrorBanner title="TOPOLOGY EXPLORER ERROR" message={error || 'No analysis case selected'} />
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem-1.75rem)] flex flex-col bg-[#0A0D12] overflow-hidden select-none">
      
      {/* Top Topology Context & Filter Bar */}
      <div className="h-11 bg-[#0E1116] border-b border-[#262E3B] px-4 flex items-center justify-between text-xs font-mono shrink-0">
        
        {/* Left: Info */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 text-[#14B8A6] font-semibold">
            <Share2 className="w-4 h-4" />
            <span>RELATIONSHIP EXPLORER:</span>
          </div>
          <span className="text-[#F1F5F9] font-medium truncate max-w-xs">{fileName}</span>
          <span className="text-[10px] text-[#64748B]">
            ({nodes.length} nodes • {edges.length} connections)
          </span>
        </div>

        {/* Center: Filter Toggles */}
        <div className="hidden lg:flex items-center space-x-3">
          <label className="flex items-center space-x-1.5 text-[11px] text-[#94A3B8] cursor-pointer hover:text-[#F1F5F9]">
            <input
              type="checkbox"
              checked={showUnresolved}
              onChange={(e) => setShowUnresolved(e.target.checked)}
              className="accent-[#F59E0B] rounded"
            />
            <span>Unresolved Patterns</span>
          </label>

          <label className="flex items-center space-x-1.5 text-[11px] text-[#94A3B8] cursor-pointer hover:text-[#F1F5F9]">
            <input
              type="checkbox"
              checked={showStandardMatches}
              onChange={(e) => setShowStandardMatches(e.target.checked)}
              className="accent-[#14B8A6] rounded"
            />
            <span>Bluetooth SIG Matches</span>
          </label>

          <label className="flex items-center space-x-1.5 text-[11px] text-[#94A3B8] cursor-pointer hover:text-[#F1F5F9]">
            <input
              type="checkbox"
              checked={showCandidates}
              onChange={(e) => setShowCandidates(e.target.checked)}
              className="accent-[#64748B] rounded"
            />
            <span>Candidate Pool</span>
          </label>
        </div>

        {/* Right: Zoom Controls */}
        <div className="flex items-center space-x-1">
          <button
            onClick={() => setZoom((z) => Math.min(2.5, z * 1.2))}
            className="p-1.5 rounded bg-[#151921] hover:bg-[#1C222B] text-[#94A3B8] hover:text-[#F1F5F9] border border-[#262E3B] transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(0.4, z / 1.2))}
            className="p-1.5 rounded bg-[#151921] hover:bg-[#1C222B] text-[#94A3B8] hover:text-[#F1F5F9] border border-[#262E3B] transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => {
              setZoom(1);
              setPan({ x: 50, y: 50 });
            }}
            className="p-1.5 rounded bg-[#151921] hover:bg-[#1C222B] text-[#94A3B8] hover:text-[#F1F5F9] border border-[#262E3B] transition-colors"
            title="Reset View"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>

      </div>

      {/* Main Graph Area */}
      <div className="flex-1 flex overflow-hidden relative">
        
        {/* Interactive SVG Canvas */}
        <div
          ref={containerRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onWheel={handleWheel}
          className={`flex-1 h-full overflow-hidden relative bg-[#0A0D12] forensic-grid cursor-grab ${
            isDragging ? 'cursor-grabbing' : ''
          }`}
        >
          <svg className="w-full h-full">
            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              
              {/* Layer 1: Edges */}
              {edges.map((edge) => {
                const sourceNode = nodeMap.get(edge.source);
                const targetNode = nodeMap.get(edge.target);
                if (!sourceNode || !targetNode) return null;

                const isConnected = connectedEdgeIds.has(edge.id);
                const isDimmed = activeFocusId && !isConnected;

                // Compute smooth Bezier curve
                const x1 = sourceNode.x + 190;
                const y1 = sourceNode.y + 24;
                const x2 = targetNode.x;
                const y2 = targetNode.y + 24;
                const midX = (x1 + x2) / 2;

                const pathD = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;

                const strokeColor =
                  edge.status === 'strong'
                    ? '#14B8A6'
                    : edge.status === 'unresolved'
                    ? '#F59E0B'
                    : edge.status === 'candidate'
                    ? '#64748B'
                    : '#3B4656';

                return (
                  <path
                    key={edge.id}
                    d={pathD}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={isConnected ? 2.5 : 1.5}
                    strokeOpacity={isDimmed ? 0.15 : isConnected ? 1 : 0.6}
                    strokeDasharray={edge.status === 'unresolved' ? '4 3' : undefined}
                    className="transition-all duration-150"
                  />
                );
              })}

              {/* Layer 2: Nodes */}
              {nodes.map((node) => {
                const isSelected = selectedNodeId === node.id;
                const isHovered = hoveredNodeId === node.id;
                const isConnected = connectedNodeIds.has(node.id);
                const isDimmed = activeFocusId && !isConnected;

                let badgeColor = 'bg-[#151921] text-[#94A3B8] border-[#262E3B]';
                let iconColor = 'text-[#94A3B8]';

                if (node.type === 'apk') {
                  badgeColor = 'bg-[#151921] text-teal-400 border-teal-500/40';
                  iconColor = 'text-teal-400';
                } else if (node.type === 'registration') {
                  badgeColor =
                    node.data?.evidence_level === 'STRONG_STATIC_ASSOCIATION'
                      ? 'bg-teal-500/10 text-teal-400 border-teal-500/50'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/50';
                } else if (node.type === 'sig') {
                  badgeColor = 'bg-teal-500/15 text-teal-400 border-teal-500/40';
                  iconColor = 'text-teal-400';
                }

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNodeId(node.id);
                    }}
                    onMouseEnter={() => setHoveredNodeId(node.id)}
                    onMouseLeave={() => setHoveredNodeId(null)}
                    className="cursor-pointer"
                    opacity={isDimmed ? 0.25 : 1}
                  >
                    {/* Node background card */}
                    <rect
                      width="190"
                      height="48"
                      rx="6"
                      fill="#12161E"
                      stroke={
                        isSelected
                          ? '#14B8A6'
                          : isHovered
                          ? '#3B4656'
                          : '#262E3B'
                      }
                      strokeWidth={isSelected ? 2 : 1}
                      filter={isSelected ? 'drop-shadow(0 0 8px rgba(20,184,166,0.3))' : undefined}
                    />

                    {/* Node Category Pill */}
                    <text
                      x="10"
                      y="18"
                      fill="#64748B"
                      fontSize="9"
                      fontFamily="JetBrains Mono, monospace"
                      fontWeight="bold"
                    >
                      {node.type.toUpperCase()}
                    </text>

                    {/* Node Main Label */}
                    <text
                      x="10"
                      y="32"
                      fill="#F1F5F9"
                      fontSize="11"
                      fontFamily="JetBrains Mono, monospace"
                      fontWeight="600"
                    >
                      {node.label.length > 22 ? `${node.label.substring(0, 20)}...` : node.label}
                    </text>

                    {/* Node Sublabel */}
                    {node.sublabel && (
                      <text
                        x="10"
                        y="43"
                        fill="#94A3B8"
                        fontSize="8.5"
                        fontFamily="JetBrains Mono, monospace"
                      >
                        {node.sublabel.length > 26 ? `${node.sublabel.substring(0, 24)}...` : node.sublabel}
                      </text>
                    )}
                  </g>
                );
              })}

            </g>
          </svg>

          {/* Floating Instructions Legend */}
          <div className="absolute bottom-4 left-4 bg-[#0E1116]/90 border border-[#262E3B] backdrop-blur-md rounded-lg p-2.5 text-[10px] font-mono text-[#64748B] space-y-1 shadow-lg pointer-events-none">
            <div className="text-[#94A3B8] font-semibold">TOPOLOGY FLOW</div>
            <div>APK ➔ Package ➔ Method ➔ Registration ➔ UUID ➔ Standard</div>
            <div className="pt-1 text-[#64748B]">Click any node to inspect Dalvik evidence details</div>
          </div>
        </div>

        {/* Right Node Inspector Drawer */}
        {selectedNode && (
          <div className="w-80 bg-[#0E1116] border-l border-[#262E3B] flex flex-col p-4 space-y-4 font-mono text-xs overflow-y-auto shrink-0 animate-in slide-in-from-right-4 duration-150">
            <div className="flex items-center justify-between border-b border-[#262E3B] pb-2">
              <span className="text-[10px] text-[#14B8A6] font-semibold uppercase tracking-wider">
                NODE METADATA
              </span>
              <button
                onClick={() => setSelectedNodeId(null)}
                className="text-[#64748B] hover:text-[#F1F5F9] text-xs"
              >
                ✕
              </button>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-[#64748B] uppercase">Type</span>
              <p className="text-[#F1F5F9] font-semibold">{selectedNode.type.toUpperCase()}</p>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-[#64748B] uppercase">Identifier / Label</span>
              <p className="text-teal-400 break-all">{selectedNode.label}</p>
            </div>

            {selectedNode.sublabel && (
              <div className="space-y-1">
                <span className="text-[10px] text-[#64748B] uppercase">Specification</span>
                <p className="text-[#CBD5E1] break-all">{selectedNode.sublabel}</p>
              </div>
            )}

            {/* If Method / Registration Node */}
            {selectedNode.data?.diagnosis && (
              <div className="space-y-1 border-t border-[#262E3B] pt-2">
                <span className="text-[10px] text-amber-400 uppercase">Dalvik Diagnosis</span>
                <p className="text-[#94A3B8] text-[11px] leading-relaxed">
                  {selectedNode.data.diagnosis}
                </p>
              </div>
            )}

            {/* If UUID / Standard Match */}
            {selectedNode.data?.description && (
              <div className="space-y-1 border-t border-[#262E3B] pt-2">
                <span className="text-[10px] text-[#38BDF8] uppercase">Standard Profile Notes</span>
                <p className="text-[#94A3B8] text-[11px] leading-relaxed">
                  {selectedNode.data.description}
                </p>
              </div>
            )}

            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab('workbench')}
                className="mt-4 w-full py-2 px-3 rounded bg-[#1C222B] hover:bg-[#262E3B] text-teal-400 border border-[#3B4656] text-xs font-mono flex items-center justify-center space-x-2 transition-colors"
              >
                <Binary className="w-3.5 h-3.5" />
                <span>Examine in Workbench</span>
              </button>
            )}
          </div>
        )}

      </div>

    </div>
  );
};
