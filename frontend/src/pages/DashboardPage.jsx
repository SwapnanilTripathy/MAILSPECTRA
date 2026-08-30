import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  FolderGit2,
  Network,
  UploadCloud,
  FileText,
  AlertTriangle,
  Radio,
  ArrowRight,
  TrendingUp,
  Clock,
  Sparkles,
  Zap,
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import api from '../api/client';
import MetricCard from '../components/common/MetricCard';
import SeverityBadge from '../components/common/SeverityBadge';

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [recentCases, setRecentCases] = useState([]);
  const [distribution, setDistribution] = useState(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [statsRes, recentRes, distRes] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getDashboardRecent().catch(() => ({ items: [] })),
        api.getDashboardDistribution().catch(() => null),
      ]);
      setStats(statsRes);
      setRecentCases(recentRes?.items || []);
      setDistribution(distRes);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const res = await api.analyzeEmailFile(file);
      navigate('/investigate', { state: { initialAnalysis: res } });
    } catch (err) {
      alert(`Analysis error: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#10b981', '#a855f7', '#06b6d4'];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner / SIH Hackathon Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#111827] via-slate-900 to-[#111827] border border-slate-800 p-6 shadow-2xl">
        <div className="absolute right-0 top-0 w-96 h-full bg-cyan-500/10 blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                SMART INDIA HACKATHON 2026 • SIH26106
              </span>
              <span className="text-xs font-mono text-slate-400">Team DEEP thinkers</span>
            </div>
            <h1 className="text-2xl lg:text-3xl font-extrabold tracking-tight text-white mt-2">
              DEEP<span className="text-cyan-400">TRACE</span> SOC Command Center
            </h1>
            <p className="text-sm text-slate-300 mt-1 max-w-2xl">
              AI-driven email forensics, multi-class threat classification, NetworkX threat graph attribution, and SHA-256 evidence chain of custody.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <label className="cursor-pointer flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/30 transition">
              <UploadCloud className="w-4 h-4" />
              <span>{uploading ? 'Processing EML...' : 'Quick EML Triage'}</span>
              <input type="file" accept=".eml,.msg,.txt" onChange={handleQuickUpload} disabled={uploading} className="hidden" />
            </label>
            <button
              onClick={() => navigate('/investigate')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition"
            >
              <Search className="w-4 h-4 text-cyan-400" />
              <span>Deep Workspace</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Emails Analyzed"
          value={stats?.total_analyzed ?? 0}
          subtitle="Processed RFC822 artifacts"
          icon={FolderGit2}
          color="cyan"
          trend="+100% real-time"
        />
        <MetricCard
          title="Threats Identified"
          value={stats?.threats_detected ?? 0}
          subtitle={`${stats?.critical_threats ?? 0} Critical / High Severity`}
          icon={ShieldAlert}
          color="red"
          trend="Multi-layer filter"
        />
        <MetricCard
          title="Active Threat Clusters"
          value={stats?.active_campaigns ?? 0}
          subtitle="Cross-case correlated campaigns"
          icon={Network}
          color="purple"
          trend="Graph correlation"
        />
        <MetricCard
          title="Average Risk Score"
          value={`${stats?.average_risk_score ?? 0}/100`}
          subtitle={`${stats?.open_cases ?? 0} Active Triage Cases`}
          icon={Zap}
          color="amber"
          trend="Hybrid 0-100 scale"
        />
      </div>

      {/* Charts Section: Threat Categories & Severity Bands */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Categories Donut */}
        <div className="rounded-xl bg-[#111827] border border-slate-800 p-5 shadow-xl flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              AI Threat Classification Distribution
            </h3>
            <span className="text-xs font-mono text-slate-400">7 Multi-Class Models</span>
          </div>

          <div className="h-64 w-full mt-4 flex items-center justify-center">
            {distribution?.category_distribution?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={distribution.category_distribution}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={4}
                  >
                    {distribution.category_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const item = payload[0];
                        return (
                          <div className="p-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white shadow-xl">
                            <span className="font-bold">{item.name}:</span> {item.value} cases
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    formatter={(value) => <span className="text-xs font-mono text-slate-300">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs font-mono text-slate-500">No email classification data recorded yet.</div>
            )}
          </div>
        </div>

        {/* Severity Risk Bands */}
        <div className="rounded-xl bg-[#111827] border border-slate-800 p-5 shadow-xl flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Forensic Risk Severity Bands
            </h3>
            <span className="text-xs font-mono text-slate-400">0 - 100 Risk Score Engine</span>
          </div>

          <div className="h-64 w-full mt-4">
            {distribution?.risk_distribution?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={distribution.risk_distribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const d = payload[0].payload;
                        return (
                          <div className="p-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white">
                            <p className="font-bold">{d.name}</p>
                            <p className="text-cyan-400">{d.value} Cases</p>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Bar dataKey="value" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
                No risk distribution records available.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Live Investigation Queue (Recent Triage)
            </h3>
          </div>
          <button
            onClick={() => navigate('/cases')}
            className="flex items-center gap-1 text-xs font-mono text-cyan-400 hover:text-cyan-300 transition"
          >
            <span>View All Cases</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {recentCases.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-mono text-xs">
            No recent cases found. Run your first email analysis from the Investigate workspace!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Case ID</th>
                  <th className="px-5 py-3">Subject / Artifact</th>
                  <th className="px-5 py-3">Sender</th>
                  <th className="px-5 py-3">Verdict</th>
                  <th className="px-5 py-3">Risk Score</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentCases.map((c, i) => (
                  <tr key={i} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-3 font-bold text-cyan-400">{c.case_id}</td>
                    <td className="px-5 py-3 text-slate-200 truncate max-w-xs font-sans" title={c.subject}>
                      {c.subject || c.filename}
                    </td>
                    <td className="px-5 py-3 text-slate-400 truncate max-w-[180px]">{c.from_address || 'N/A'}</td>
                    <td className="px-5 py-3">
                      <SeverityBadge severity={c.classification} size="sm" />
                    </td>
                    <td className="px-5 py-3">
                      <span className={`font-bold ${c.risk_score >= 60 ? 'text-red-400' : c.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {c.risk_score}/100
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                        {c.status || 'OPEN'}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        onClick={() => navigate(`/cases/${c.case_id}`)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[11px] transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
