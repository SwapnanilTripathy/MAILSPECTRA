import React, { useState, useMemo } from 'react';
import { Network, ZoomIn, ZoomOut, Filter, Info, ShieldAlert, Globe, Server, Mail, Link as LinkIcon, Layers } from 'lucide-react';
import DefangedIndicator from '../common/DefangedIndicator';

export default function ThreatGraphView({ threatGraph }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterType, setFilterType] = useState('ALL');
  const [zoomLevel, setZoomLevel] = useState(1.0);

  const nodes = threatGraph?.nodes || [];
  const edges = threatGraph?.edges || [];
  const metrics = threatGraph?.metrics || {
    node_count: nodes.length,
    edge_count: edges.length,
    density: 0.0,
    connected_components: 1,
  };

  const nodeTypes = ['ALL', ...Array.from(new Set(nodes.map((n) => n.type || 'UNKNOWN')))];

  // Color & Icon mapping for node types
  const nodeConfig = {
    EMAIL: { color: '#38bdf8', bg: '#0369a1', icon: Mail, label: 'Email Artifact' },
    SENDER: { color: '#a855f7', bg: '#7e22ce', icon: Mail, label: 'Sender Identity' },
    DOMAIN: { color: '#3b82f6', bg: '#1d4ed8', icon: Globe, label: 'Domain' },
    IP: { color: '#f59e0b', bg: '#b45309', icon: Server, label: 'IP Address' },
    ASN: { color: '#10b981', bg: '#047857', icon: Layers, label: 'ASN' },
    URL: { color: '#ef4444', bg: '#b91c1c', icon: LinkIcon, label: 'Extracted URL' },
    LOCATION: { color: '#ec4899', bg: '#be185d', icon: Globe, label: 'Location' },
    MAIL_SERVER: { color: '#6366f1', bg: '#4338ca', icon: Server, label: 'Mail Server' },
  };

  // Simple layout calculation (radial circular layout for clean aesthetic rendering)
  const renderedNodes = useMemo(() => {
    const total = nodes.length;
    if (total === 0) return [];

    const centerX = 400;
    const centerY = 280;
    const radius = Math.min(220, Math.max(140, total * 22));

    // Place email/case node at center if present, others arranged radially
    return nodes.map((node, index) => {
      const isCenter = node.type === 'EMAIL' || node.type === 'SENDER';
      let x = centerX;
      let y = centerY;

      if (!isCenter || total > 1) {
        const angle = (index / total) * 2 * Math.PI - Math.PI / 2;
        const dist = node.type === 'EMAIL' ? 0 : node.type === 'SENDER' || node.type === 'DOMAIN' ? radius * 0.55 : radius;
        x = centerX + dist * Math.cos(angle);
        y = centerY + dist * Math.sin(angle);
      }

      return {
        ...node,
        x,
        y,
      };
    });
  }, [nodes]);

  const nodeMap = useMemo(() => {
    const map = new Map();
    renderedNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [renderedNodes]);

  const filteredNodes = filterType === 'ALL'
    ? renderedNodes
    : renderedNodes.filter((n) => n.type === filterType);

  if (nodes.length === 0) {
    return (
      <div className="p-8 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-400 font-mono text-sm">
        No graph relationship nodes generated for this email artifact.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Graph Metrics Summary Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <span className="text-[10px] font-mono uppercase text-slate-400">GRAPH NODES</span>
          <p className="text-xl font-bold font-mono text-cyan-400 mt-1">{metrics.node_count || nodes.length}</p>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <span className="text-[10px] font-mono uppercase text-slate-400">RELATIONSHIP EDGES</span>
          <p className="text-xl font-bold font-mono text-blue-400 mt-1">{metrics.edge_count || edges.length}</p>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <span className="text-[10px] font-mono uppercase text-slate-400">GRAPH DENSITY</span>
          <p className="text-xl font-bold font-mono text-purple-400 mt-1">
            {metrics.density !== undefined ? Number(metrics.density).toFixed(3) : '0.000'}
          </p>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <span className="text-[10px] font-mono uppercase text-slate-400">CONNECTED CLUSTERS</span>
          <p className="text-xl font-bold font-mono text-emerald-400 mt-1">{metrics.connected_components || 1}</p>
        </div>
      </div>

      {/* Main Interactive Graph Viewport */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph Canvas */}
        <div className="lg:col-span-2 rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-xl relative flex flex-col">
          {/* Canvas Toolbar */}
          <div className="p-4 border-b border-slate-800 bg-slate-900/40 flex flex-wrap items-center justify-between gap-3 z-10">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono uppercase tracking-wider text-slate-300">
                NetworkX Infrastructure Graph
              </span>
            </div>

            {/* Filter Pills */}
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                {nodeTypes.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>

              {/* Zoom Controls */}
              <div className="flex items-center ml-2 border-l border-slate-700 pl-2 gap-1">
                <button
                  onClick={() => setZoomLevel((prev) => Math.max(0.7, prev - 0.1))}
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                  title="Zoom Out"
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <span className="text-[10px] font-mono text-slate-400 px-1">{Math.round(zoomLevel * 100)}%</span>
                <button
                  onClick={() => setZoomLevel((prev) => Math.min(1.5, prev + 0.1))}
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                  title="Zoom In"
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* SVG Graph Viewport */}
          <div className="w-full h-[520px] bg-[#090D16] relative overflow-hidden flex items-center justify-center">
            {/* Grid Pattern Background */}
            <div
              className="absolute inset-0 opacity-15"
              style={{
                backgroundImage: 'radial-gradient(#38bdf8 1px, transparent 1px)',
                backgroundSize: '24px 24px',
              }}
            />

            <svg
              viewBox="0 0 800 560"
              className="w-full h-full cursor-grab active:cursor-grabbing transition-transform duration-200"
              style={{ transform: `scale(${zoomLevel})` }}
            >
              <defs>
                <marker
                  id="arrow"
                  viewBox="0 0 10 10"
                  refX="22"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
                </marker>
                <marker
                  id="arrow-active"
                  viewBox="0 0 10 10"
                  refX="22"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
                </marker>
              </defs>

              {/* Render Edges */}
              {edges.map((edge, idx) => {
                const src = nodeMap.get(edge.source);
                const tgt = nodeMap.get(edge.target);
                if (!src || !tgt) return null;

                const isConnectedToSelected =
                  selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target);

                const midX = (src.x + tgt.x) / 2;
                const midY = (src.y + tgt.y) / 2;

                return (
                  <g key={idx}>
                    <line
                      x1={src.x}
                      y1={src.y}
                      x2={tgt.x}
                      y2={tgt.y}
                      stroke={isConnectedToSelected ? '#06b6d4' : '#334155'}
                      strokeWidth={isConnectedToSelected ? 2.5 : 1.2}
                      strokeDasharray={edge.relationship === 'CONTAINS_URL' ? '4,4' : undefined}
                      markerEnd={isConnectedToSelected ? 'url(#arrow-active)' : 'url(#arrow)'}
                      className="transition-all"
                    />
                    {/* Edge Label */}
                    <text
                      x={midX}
                      y={midY - 4}
                      fill={isConnectedToSelected ? '#38bdf8' : '#64748b'}
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="select-none"
                    >
                      {edge.relationship || edge.label || ''}
                    </text>
                  </g>
                );
              })}

              {/* Render Nodes */}
              {filteredNodes.map((node) => {
                const cfg = nodeConfig[node.type] || { color: '#94a3b8', bg: '#475569', label: node.type };
                const isSelected = selectedNode?.id === node.id;

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer group"
                  >
                    {/* Selected Halo Pulse */}
                    {isSelected && (
                      <circle
                        r="24"
                        fill="none"
                        stroke={cfg.color}
                        strokeWidth="2"
                        strokeDasharray="4,4"
                        className="animate-spin"
                        style={{ animationDuration: '6s' }}
                      />
                    )}

                    {/* Node Body Circle */}
                    <circle
                      r="16"
                      fill={isSelected ? cfg.color : '#111827'}
                      stroke={cfg.color}
                      strokeWidth={isSelected ? 3 : 2}
                      className="transition-all shadow-lg"
                    />

                    {/* Node Type Indicator */}
                    <text
                      y="4"
                      textAnchor="middle"
                      fill={isSelected ? '#0B0F19' : cfg.color}
                      fontSize="10"
                      fontWeight="bold"
                      fontFamily="monospace"
                      className="select-none pointer-events-none"
                    >
                      {(node.type || 'N').substring(0, 2)}
                    </text>

                    {/* Node Label Text Below */}
                    <text
                      y="28"
                      textAnchor="middle"
                      fill="#cbd5e1"
                      fontSize="10"
                      fontFamily="monospace"
                      className="select-none"
                    >
                      {(node.label || node.id || '').length > 18
                        ? `${(node.label || node.id).substring(0, 16)}…`
                        : node.label || node.id}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Node Inspector Sidebar */}
        <div className="rounded-xl bg-[#111827] border border-slate-800 p-5 shadow-xl flex flex-col">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 text-xs font-mono uppercase tracking-wider text-slate-300">
            <Info className="w-4 h-4 text-cyan-400" />
            <span>Graph Entity Inspector</span>
          </div>

          {selectedNode ? (
            <div className="mt-4 space-y-4 font-mono text-xs flex-1">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block">ENTITY TYPE</span>
                <span className="inline-block mt-1 px-2.5 py-1 rounded text-xs font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                  {selectedNode.type}
                </span>
              </div>

              <div>
                <span className="text-[10px] uppercase text-slate-500 block">IDENTIFIER / VALUE</span>
                <div className="mt-1">
                  <DefangedIndicator value={selectedNode.id} className="text-white break-all" />
                </div>
              </div>

              {selectedNode.label && selectedNode.label !== selectedNode.id && (
                <div>
                  <span className="text-[10px] uppercase text-slate-500 block">DISPLAY LABEL</span>
                  <p className="text-slate-200 mt-1 font-sans">{selectedNode.label}</p>
                </div>
              )}

              {/* Connected Relationships */}
              <div className="pt-3 border-t border-slate-800">
                <span className="text-[10px] uppercase text-slate-500 block mb-2">ASSOCIATED RELATIONSHIPS</span>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {edges
                    .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map((edge, i) => {
                      const isSource = edge.source === selectedNode.id;
                      const targetId = isSource ? edge.target : edge.source;
                      return (
                        <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 text-[11px]">
                          <span className="text-cyan-400 font-bold">{isSource ? '→ ' : '← '}</span>
                          <span className="text-slate-400">{edge.relationship}: </span>
                          <span className="text-slate-200">{targetId}</span>
                        </div>
                      );
                    })}
                </div>
              </div>
            </div>
          ) : (
            <div className="mt-8 flex flex-col items-center justify-center text-center text-slate-500 font-mono text-xs space-y-2 flex-1">
              <Network className="w-8 h-8 text-slate-600 animate-pulse" />
              <p>Click any graph node to inspect its technical attributes, associated infrastructure, and relationships.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
