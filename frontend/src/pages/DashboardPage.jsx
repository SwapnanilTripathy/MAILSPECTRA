import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  FolderGit2,
  Network,
  UploadCloud,
  ArrowRight,
  Clock,
  Zap,
  PieChart as PieIcon,
  BarChart3,
  Inbox,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from 'recharts';
import api from '../api/client';
import MetricCard from '../components/common/MetricCard';
import SeverityBadge from '../components/common/SeverityBadge';

const COLORS = [
  '#ef4444',
  '#f97316',
  '#eab308',
  '#10b981',
  '#a855f7',
  '#06b6d4',
];

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [recentCases, setRecentCases] = useState(null);
  const [distribution, setDistribution] = useState(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    const fetchDashboardData = async () => {
      const [statsRes, recentRes, distRes] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getDashboardRecent().catch(() => null),
        api.getDashboardDistribution().catch(() => null),
      ]);
      setStats(statsRes);
      setRecentCases(recentRes?.items || (recentRes ? [] : null));
      setDistribution(distRes);
      setLoading(false);
    };
    fetchDashboardData();
  }, []);

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
      e.target.value = '';
    }
  };
  const metricValue = (value) => (loading ? '…' : stats ? value : '—');
  const emptyText = (message) =>
    loading
      ? 'Loading data…'
      : !distribution
        ? 'Data is currently unavailable.'
        : message;

  return (
    <div className="dashboard space-y-6 max-w-7xl mx-auto">
      <section className="overview-hero">
        <div className="overview-copy">
          <div className="eyebrow">
            <span className="eyebrow-line" /> EMAIL SECURITY WORKSPACE
          </div>
          <h1>
            Security overview<span className="heading-period">.</span>
          </h1>
          <p>
            Everything you need to investigate suspicious emails and understand
            the threats behind them.
          </p>
          <div className="hero-actions">
            <label
              className={`primary-action ${uploading ? 'opacity-60' : ''}`}
            >
              <UploadCloud size={17} aria-hidden="true" />
              <span>
                {uploading ? 'Processing email…' : 'Quick email triage'}
              </span>
              <input
                type="file"
                accept=".eml,.msg,.txt"
                onChange={handleQuickUpload}
                disabled={uploading}
                className="sr-only"
              />
            </label>
            <button
              onClick={() => navigate('/investigate')}
              className="secondary-action"
            >
              Open workspace <ArrowRight size={16} aria-hidden="true" />
            </button>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="hero-orbit hero-orbit-outer" />
          <div className="hero-orbit hero-orbit-inner" />
          <div className="hero-shield">
            <ShieldAlert size={42} strokeWidth={1.3} />
          </div>
          <span className="hero-orbit-dot dot-one" />
          <span className="hero-orbit-dot dot-two" />
          <span className="hero-cross cross-one">+</span>
          <span className="hero-cross cross-two">+</span>
        </div>
      </section>

      <section aria-labelledby="overview-heading">
        <div className="section-heading">
          <div>
            <p className="section-kicker">AT A GLANCE</p>
            <h2 id="overview-heading">Your security landscape</h2>
          </div>
          <span className="section-aside">Overview</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <MetricCard
            title="Emails analyzed"
            value={metricValue(stats?.total_analyzed ?? 0)}
            subtitle="Processed artifacts"
            icon={FolderGit2}
            color="cyan"
          />
          <MetricCard
            title="Threats identified"
            value={metricValue(stats?.threats_detected ?? 0)}
            subtitle={
              stats
                ? `${stats.critical_threats ?? 0} critical / high severity`
                : 'Critical / high severity'
            }
            icon={ShieldAlert}
            color="red"
          />
          <MetricCard
            title="Active campaigns"
            value={metricValue(stats?.active_campaigns ?? 0)}
            subtitle="Correlated threat clusters"
            icon={Network}
            color="purple"
          />
          <MetricCard
            title="Average risk score"
            value={metricValue(`${stats?.average_risk_score ?? 0}/100`)}
            subtitle={
              stats
                ? `${stats.open_cases ?? 0} active triage cases`
                : 'Across analyzed emails'
            }
            icon={Zap}
            color="amber"
          />
        </div>
        {!loading && !stats && (
          <p className="data-note" role="status">
            Dashboard statistics are unavailable. Check the backend connection.
          </p>
        )}
      </section>

      <section aria-labelledby="insights-heading">
        <div className="section-heading">
          <div>
            <p className="section-kicker">THREAT INTELLIGENCE</p>
            <h2 id="insights-heading">Analysis insights</h2>
          </div>
          <span className="section-aside">Based on analyzed emails</span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="insight-card">
            <div className="card-heading">
              <div>
                <h3>Threat classification</h3>
                <p>Distribution by classification</p>
              </div>
              <span className="card-heading-icon">
                <PieIcon size={18} aria-hidden="true" />
              </span>
            </div>
            <div className="chart-area">
              {distribution?.category_distribution?.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={distribution.category_distribution}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="48%"
                      innerRadius={55}
                      outerRadius={80}
                      paddingAngle={4}
                    >
                      {distribution.category_distribution.map(
                        (entry, index) => (
                          <Cell
                            key={`${entry.name}-${index}`}
                            fill={COLORS[index % COLORS.length]}
                          />
                        ),
                      )}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: '#111c2d',
                        border: '1px solid #334155',
                        borderRadius: 8,
                      }}
                    />
                    <Legend
                      verticalAlign="bottom"
                      height={36}
                      formatter={(value) => (
                        <span className="text-xs text-slate-300">{value}</span>
                      )}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty-chart">
                  <div className="empty-icon">
                    <PieIcon size={22} aria-hidden="true" />
                  </div>
                  <strong>
                    {loading
                      ? 'Loading classification'
                      : !distribution
                        ? 'Classification unavailable'
                        : 'No classification data'}
                  </strong>
                  <span>
                    {emptyText(
                      'Analyze an email to see your threat breakdown.',
                    )}
                  </span>
                </div>
              )}
            </div>
          </div>
          <div className="insight-card">
            <div className="card-heading">
              <div>
                <h3>Risk distribution</h3>
                <p>Cases grouped by severity</p>
              </div>
              <span className="card-heading-icon">
                <BarChart3 size={18} aria-hidden="true" />
              </span>
            </div>
            <div className="chart-area">
              {distribution?.risk_distribution?.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={distribution.risk_distribution}
                    margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                  >
                    <XAxis
                      dataKey="name"
                      stroke="#64748b"
                      tick={{ fontSize: 11, fill: '#94a3b8' }}
                    />
                    <YAxis
                      stroke="#64748b"
                      tick={{ fontSize: 11, fill: '#94a3b8' }}
                    />
                    <Tooltip
                      contentStyle={{
                        background: '#111c2d',
                        border: '1px solid #334155',
                        borderRadius: 8,
                      }}
                    />
                    <Bar dataKey="value" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty-chart">
                  <div className="empty-icon">
                    <BarChart3 size={22} aria-hidden="true" />
                  </div>
                  <strong>
                    {loading
                      ? 'Loading risk data'
                      : !distribution
                        ? 'Risk data unavailable'
                        : 'No risk data yet'}
                  </strong>
                  <span>
                    {emptyText(
                      'Risk scores will appear as cases are analyzed.',
                    )}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="recent-card" aria-labelledby="recent-heading">
        <div className="recent-heading">
          <div className="flex items-center gap-3">
            <span className="card-heading-icon">
              <Clock size={18} aria-hidden="true" />
            </span>
            <div>
              <h2 id="recent-heading">Recent investigations</h2>
              <p>Your latest triage activity</p>
            </div>
          </div>
          <button onClick={() => navigate('/cases')} className="text-link">
            View all cases <ArrowRight size={15} aria-hidden="true" />
          </button>
        </div>
        {!recentCases?.length ? (
          <div className="recent-empty">
            <Inbox size={22} aria-hidden="true" />
            <span>
              {loading
                ? 'Loading investigations…'
                : !recentCases
                  ? 'Recent investigations are currently unavailable.'
                  : 'No investigations yet. Start by analyzing an email.'}
            </span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/40 text-slate-400 border-b border-slate-800">
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
                  <tr
                    key={c.case_id || i}
                    className="hover:bg-slate-800/30 transition"
                  >
                    <td className="px-5 py-3 font-bold text-cyan-400">
                      {c.case_id}
                    </td>
                    <td
                      className="px-5 py-3 text-slate-200 truncate max-w-xs font-sans"
                      title={c.subject}
                    >
                      {c.subject || c.filename}
                    </td>
                    <td className="px-5 py-3 text-slate-400 truncate max-w-[180px]">
                      {c.from_address || 'N/A'}
                    </td>
                    <td className="px-5 py-3">
                      <SeverityBadge severity={c.classification} size="sm" />
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`font-bold ${c.risk_score >= 60 ? 'text-red-400' : c.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}
                      >
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
      </section>
    </div>
  );
}
